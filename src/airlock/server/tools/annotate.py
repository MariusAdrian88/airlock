"""annotate set: rename, retype, comment, annotate (note + optional rename), struct_define.

Each tool changes the Ghidra project through a worker write op (one transaction, saved before the
answer), then updates the index and bumps ``function.version`` of everything whose decompile text
can change (DESIGN.md section 5 "Invalidation"); cached decompiles, asm and outlines of an older
version are recomputed on the next request. Ghidra is the source of truth: the index is updated
after a successful worker answer only. Notes are agent data in the ``note`` table (they are not
written to Ghidra except as the optional plate-comment mirror).

Tools exist only when allow_writes is on (the loader hides them otherwise); a clean session never
reaches them (role gate). ``patch_bytes`` is not implemented.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from airlock import logs
from airlock.index.store import Function, Store
from airlock.server import dotnet as dn
from airlock.server import notes as nt
from airlock.server import roles
from airlock.server import targets as tg
from airlock.server.context import ServerContext
from airlock.server.indexer import worker_error
from airlock.server.registry import tool
from airlock.server.selectors import fmt_addr, parse_address, split_binary_target
from airlock.server.tools.common import Bound, bind_binary, bind_scope
from airlock.server.tools.core import _get_decompiled
from airlock.worker.protocol import WorkerError

log = logging.getLogger("airlock")

KINDS = ("function", "global", "label", "local")
COMMENT_KINDS = ("plate", "pre", "eol")
MAX_COMMENT = 4000
EXCERPT_LINES = 12
MAX_FIELDS = 512
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")
_NAME_BAD = re.compile(r"[\s\x00-\x1f]")

_HINTS = {
    "bad_name": "Use a name without spaces or special characters",
    "bad_type": "Use a C type such as int, char *, or a struct defined with struct_define",
    "exists": "Choose another name",
    "no_variable": "Use a name from the list, as the decompile shows it",
    "no_function": "Check the address",
    "wrong_kind": "Use the matching kind",
    "ambiguous": "Pass the address instead",
    "not_found": "Check the name or pass an address",
    "decompile_failed": "Try again, or raise defaults.decompile_timeout_s",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- shared steps ----------------------------------------------------------------------------------

def _gate(ctx: ServerContext) -> str | None:
    if ctx.session.role == roles.CLEAN:
        return "error wrong_role: write tools are not available in a clean-room session."
    if not ctx.config.allow_writes:
        return "error writes_disabled: allow_writes is off. Set allow_writes in config.jsonc and restart."
    return None


def _bad_name(name: str, what: str = "name") -> str | None:
    if not name or _NAME_BAD.search(name):
        return f"error bad_args: {what} must be non-empty with no spaces. Fix and retry."
    return None


def _worker(ctx: ServerContext, bd: Bound, op: str, args: dict[str, Any]) -> tuple[dict | None, str | None]:
    """(reply, error line) for a worker write op on the binary's program."""
    ix = ctx.indexer
    try:
        ix.ensure_open(bd.project)
        r = ctx.worker.request(op, {"program": ix.program_of(bd.store, bd.binary), **args}, timeout=600)
    except WorkerError as e:
        return None, worker_error(e, _HINTS.get(e.code, "Check logs\\worker.log or call index_status"))
    return r, None


def _managed_fn(bd: Bound, fn: Function) -> bool:
    return dn.is_managed_site(bd.binary, fn.space, fn.entry)


def _managed_refusal(fn: Function, what: str) -> str:
    """One line for a write that has no target: a .NET method has no Ghidra function."""
    return (f"error managed: {fn.qualified_name} is a .NET method; {what} "
            "Use annotate with a note only.")


_NAME_FACT = "its name comes from metadata."
_VAR_FACT = "its variables and types come from metadata, not from Ghidra."
_CMT_FACT = "it has no Ghidra function to hold a comment."


def _managed_only_refusal(bd: Bound, what: str) -> str:
    return (f"error managed: {bd.binary.name} is a managed-only .NET assembly with no Ghidra program; "
            f"{what} Use annotate with a note on a method.")


def _function_target(ctx: ServerContext, binary: str, text: str, external_ok: bool = False,
                     managed_what: str = "") -> tuple[Bound, Function, str | None] | str:
    """Resolve a function. ``managed_what`` set: a .NET method (or external callee) is refused with
    ``error managed``; empty: the caller handles managed targets itself."""
    ft = tg.resolve_target(ctx, binary, text, (tg.FUNCTION, tg.IMPORT_FN))
    if isinstance(ft, str):
        return ft
    assert isinstance(ft, tg.FunctionTarget)
    if managed_what and _managed_fn(ft.bound, ft.fn):
        return _managed_refusal(ft.fn, managed_what)
    if ft.fn.is_external and not external_ok:
        return tg.err("external", f"{ft.fn.qualified_name} is an imported function with no code",
                      "Rename or annotate a function that calls it, or use annotate for a note")
    return ft.bound, ft.fn, ft.any_note


def _callers(st: Store, fn: Function) -> set[int]:
    """Direct callers, including callers through a function pointer."""
    return {f.id for f in st.callers(fn, 100000)} | {f.id for f in st.ptr_callers(fn, 100000)}


def _site(ctx: ServerContext, binary: str, text: str) -> tuple[Bound, str, int, Function | None] | str:
    """An exact address: (bound, space, offset, function containing it). A name is a function entry."""
    tr = tg.resolve_target(ctx, binary, text, (tg.FUNCTION, tg.ADDRESS))
    if isinstance(tr, str):
        return tr
    if isinstance(tr, tg.AddressTarget):
        bd = tr.bound
        return bd, tr.space, tr.value, bd.store.function_containing(bd.binary.id, tr.value, tr.space)
    assert isinstance(tr, tg.FunctionTarget)
    bd, fn = tr.bound, tr.fn
    _pre, bare = split_binary_target(bd.store, text)
    p = parse_address(bare.strip())
    if p is not None:
        return bd, p[0], p[1], bd.store.function_containing(bd.binary.id, p[1], p[0]) or fn
    return bd, fn.space, fn.entry, fn


def _refresh_map(ctx: ServerContext, bd: Bound) -> None:
    try:
        ctx._on_ready(bd.project, bd.binary.id)   # coalesced background rewrite of the project map
    except Exception as e:  # noqa: BLE001  the map is an extra
        logs.project_log(ctx.indexer.paths(bd.project).logs).warning("map refresh after annotate failed: %s", e)


def _sig_line(bd: Bound, fn: Function) -> str:
    flags = ", ".join(x for x in (fn.calling_conv, fn.name_state) if x)
    return f"{bd.addr(fn.entry, fn.space)} {fn.signature or fn.qualified_name} [{flags}]"


def _invalidated(n: int) -> str:
    return f"invalidated {n} cached decompile{'s' if n != 1 else ''}"


# -- rename ----------------------------------------------------------------------------------------

@tool("rename", "Rename a function, global, label or local variable in Ghidra; cached decompiles "
                "that show the name are refreshed on their next request.")
def rename(ctx: ServerContext, target: str, new_name: str, kind: str = "function",
           function: str = "", binary: str = "") -> str:
    refused = _gate(ctx)
    if refused:
        return refused
    new_name = new_name.strip()
    if kind not in KINDS:
        return f"error bad_args: unknown kind '{kind}'. Use function, global, label or local."
    bad = _bad_name(new_name, "new_name")
    if bad:
        return bad
    if not target.strip():
        return "error bad_target: target is empty. Pass a name or an address."
    if kind == "function":
        return _rename_function(ctx, target, new_name, binary)
    if kind == "local":
        return _rename_local(ctx, target, new_name, function, binary)
    return _rename_label(ctx, target, new_name, kind, binary)


def _rename_function(ctx: ServerContext, target: str, new_name: str, binary: str) -> str:
    r = _function_target(ctx, binary, target, managed_what=_NAME_FACT)
    if isinstance(r, str):
        return r
    bd, fn, note = r
    st = bd.store
    if new_name == fn.qualified_name or new_name == fn.name and not fn.namespace:
        return f"unchanged: {fn.qualified_name} already has this name."
    res, err = _worker(ctx, bd, "rename_function", {"space": fn.space, "entry": fn.entry,
                                                    "new_name": new_name})
    if err:
        return err
    ids = {fn.id} | _callers(st, fn)
    st.apply_rename(fn.id, res["name"], res["namespace"], res.get("signature"),
                    res.get("calling_conv"), ids)
    _refresh_map(ctx, bd)
    fresh = st.get_function(fn.id) or fn
    return "\n".join(([note] if note else []) + [
        f"renamed {res['old']} -> {fresh.qualified_name} at {bd.addr(fn.entry, fn.space)}; "
        f"{_invalidated(len(ids))} (the function and {len(ids) - 1} callers)",
        _sig_line(bd, fresh)])


def _rename_local(ctx: ServerContext, variable: str, new_name: str, function: str, binary: str) -> str:
    if not function.strip():
        return ("error bad_args: kind=local needs function=<name or address>; target is the "
                "variable's current name. Fix and retry.")
    r = _function_target(ctx, binary, function, managed_what=_VAR_FACT)
    if isinstance(r, str):
        return r
    bd, fn, _note = r
    res, err = _worker(ctx, bd, "rename_variable", {
        "space": fn.space, "entry": fn.entry, "variable": variable.strip(), "new_name": new_name})
    if err:
        return err
    st = bd.store
    st.set_signature(fn.id, res.get("signature"), res.get("calling_conv"))
    st.bump_versions([fn.id])
    kind = "parameter" if res.get("is_param") else "variable"
    return (f"renamed {kind} {variable.strip()} -> {new_name} in {fn.qualified_name}; "
            f"{_invalidated(1)}")


def _rename_label(ctx: ServerContext, target: str, new_name: str, kind: str, binary: str) -> str:
    sc = bind_scope(ctx, binary, target)
    if isinstance(sc, str):
        return sc
    if len(sc.bounds) != 1:
        return ("error ambiguous_binary: the project has several binaries. "
                "Pass binary=<name> or binary!0xaddress.")
    bd = sc.bounds[0]
    st = bd.store
    if dn.is_managed_only(bd.binary):
        return _managed_only_refusal(bd, "labels and names come from metadata.")
    parsed = parse_address(sc.bare)
    if parsed is not None:
        space, value = parsed
        if dn.is_managed_site(bd.binary, space, value):
            return (f"error managed: {fmt_addr(value, bd.psize, space)} is a .NET metadata token, not "
                    "Ghidra code; its name comes from metadata. Use annotate with a note only.")
        if kind == "label" and st.function_containing(bd.binary.id, value, space) is None:
            return tg.err("bad_target", f"{fmt_addr(value, bd.psize, space)} is not inside a function",
                          "Use kind=global for a data label")
        args: dict[str, Any] = {"space": space, "address": value}
    else:
        args = {"name": sc.bare}
    res, err = _worker(ctx, bd, "rename_label", {**args, "new_name": new_name})
    if err:
        return err
    addr, space = int(res["address"]), str(res.get("space") or "ram")
    ids = set(st.functions_referencing(bd.binary.id, addr))
    inside = st.function_containing(bd.binary.id, addr, space)
    if inside is not None:
        ids.add(inside.id)
    st.bump_versions(ids)
    what = (f"renamed {kind} {res['old']} -> {new_name}" if res.get("old")
            else f"named {kind} {new_name}")
    return f"{what} at {bd.addr(addr, space)}; {_invalidated(len(ids))}"


# -- retype ----------------------------------------------------------------------------------------

@tool("retype", "Set the data type of a local variable or parameter of a function; returns the "
                "refreshed decompile lines that use it.")
def retype(ctx: ServerContext, function: str, variable: str, type: str, binary: str = "") -> str:
    refused = _gate(ctx)
    if refused:
        return refused
    variable, type_ = variable.strip(), type.strip()
    if not variable or not type_:
        return "error bad_args: variable and type are required. Fix and retry."
    r = _function_target(ctx, binary, function, managed_what=_VAR_FACT)
    if isinstance(r, str):
        return r
    bd, fn, _note = r
    st = bd.store
    res, err = _worker(ctx, bd, "retype_variable", {
        "space": fn.space, "entry": fn.entry, "variable": variable, "type": type_})
    if err:
        return err
    st.set_signature(fn.id, res.get("signature"), res.get("calling_conv"))
    ids = {fn.id}
    if res.get("is_param"):          # the signature changed: callers show different casts
        ids |= _callers(st, fn)
    st.bump_versions(ids)
    fresh = st.get_function(fn.id) or fn
    head = (f"retyped {'parameter' if res.get('is_param') else 'variable'} {variable} in "
            f"{fn.qualified_name} to {res.get('type') or type_}; {_invalidated(len(ids))}")
    c_text, derr = _get_decompiled(ctx, bd, fresh)
    if derr or c_text is None:
        return head + "\n" + (derr or "no decompile available")
    return head + "\n" + _excerpt(c_text, variable)


def _excerpt(c_text: str, variable: str) -> str:
    """Decompile lines that mention the variable, numbered, at most EXCERPT_LINES."""
    rx = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(variable) + r"(?![A-Za-z0-9_])")
    lines = [(i, ln.rstrip()) for i, ln in enumerate(c_text.splitlines(), 1) if ln.strip()]
    hits = [(i, ln) for i, ln in lines if rx.search(ln)]
    if not hits:
        return (f"no decompile line names '{variable}' now (the decompiler renames automatic "
                "variables by type). Call function to read it.")
    shown = hits[:EXCERPT_LINES]
    out = [f"{i:>5}  {ln}" for i, ln in shown]
    if len(hits) > len(shown):
        out.append(f"… {len(hits) - len(shown)} more lines use {variable}. Call function lines=a-b.")
    return "\n".join(out)


# -- comment ---------------------------------------------------------------------------------------

@tool("comment", "Set a plate, pre or end-of-line comment at an address in Ghidra (empty text clears it).")
def comment(ctx: ServerContext, address: str, text: str, kind: str = "plate", binary: str = "") -> str:
    refused = _gate(ctx)
    if refused:
        return refused
    if kind not in COMMENT_KINDS:
        return f"error bad_args: unknown kind '{kind}'. Use plate, pre or eol."
    if len(text) > MAX_COMMENT:
        return f"error bad_args: text is {len(text)} characters, the limit is {MAX_COMMENT}. Shorten it."
    if not address.strip():
        return "error bad_target: address is empty. Pass an address like 0x00401000 or a function name."
    site = _site(ctx, binary, address)
    if isinstance(site, str):
        if site.startswith("error bad_target"):      # a P/Invoke thunk or external callee by name
            ft = tg.resolve_target(ctx, binary, address, (tg.FUNCTION, tg.IMPORT_FN))
            if isinstance(ft, tg.FunctionTarget) and _managed_fn(ft.bound, ft.fn):
                return _managed_refusal(ft.fn, _CMT_FACT)
        return site
    bd, space, value, fn = site
    if dn.is_managed_only(bd.binary):
        return _managed_only_refusal(bd, "Ghidra comments do not apply.")
    if dn.is_managed_site(bd.binary, space, value) or (fn is not None and _managed_fn(bd, fn)):
        what = fn.qualified_name if fn is not None else fmt_addr(value, bd.psize, space)
        return (f"error managed: {what} is a .NET method; {_CMT_FACT} "
                "Use annotate with a note only.")
    res, err = _worker(ctx, bd, "set_comment", {"space": space, "address": value, "text": text,
                                                "kind": kind})
    if err:
        return err
    if fn is not None:
        bd.store.bump_versions([fn.id])
    where = f" in {fn.qualified_name}" if fn is not None else ""
    verb = "cleared" if res.get("cleared") else "set"
    return f"{kind} comment {verb} at {bd.addr(value, space)}{where}" + (
        f"; {_invalidated(1)}" if fn is not None else "")


# -- annotate (note + optional rename) -----------------------------------------------------------

@tool("annotate", "Add a note to a function, with an optional rename, in one step; notes appear in "
                  "function output and in search kind=note.")
def annotate(ctx: ServerContext, target: str, summary: str, tags: str = "", confidence: str = "",
             new_name: str = "", binary: str = "") -> str:
    refused = _gate(ctx)
    if refused:
        return refused
    summary = summary.strip()
    if not summary:
        return "error bad_args: summary is empty. Say what the function does."
    if len(summary) > nt.MAX_SUMMARY:
        return (f"error bad_args: summary is {len(summary)} characters, the limit is "
                f"{nt.MAX_SUMMARY}. Shorten it.")
    confidence = confidence.strip().lower()
    if confidence and confidence not in nt.CONFIDENCE:
        return "error bad_args: confidence must be low, medium or high. Fix and retry."
    new_name = new_name.strip()
    if new_name:
        bad = _bad_name(new_name, "new_name")
        if bad:
            return bad
    r = _function_target(ctx, binary, target, external_ok=True)
    if isinstance(r, str):
        return r
    bd, fn, note = r
    st = bd.store
    managed = _managed_fn(bd, fn)
    rename_to = new_name if new_name and new_name not in (fn.qualified_name, fn.name) else ""
    refused_rename = ""
    if rename_to and managed:              # the note is agent data and is kept; the name is a fact
        refused_rename = _managed_refusal(fn, _NAME_FACT).replace(
            "Use annotate with a note only.", "The rename was not applied; the note was saved.")
        rename_to = ""
    elif rename_to and fn.is_external:
        return tg.err("external", f"{fn.qualified_name} is an imported function with no code",
                      "Rename or annotate a function that calls it, or use annotate for a note")
    tag_text = nt.normalise_tags(tags)
    mirror = (bool(ctx.config.defaults.get("mirror_notes_to_ghidra"))
              and fn.space == "ram" and not fn.is_external and not managed)
    rename_info: dict[str, Any] | None = None
    ids: set[int] = set()
    if rename_to or mirror:
        wargs: dict[str, Any] = {"space": fn.space, "entry": fn.entry}
        if rename_to:
            wargs["new_name"] = rename_to
        if mirror:
            wargs["notes"] = nt.mirror_lines(st, fn, nt.format_note(summary, tag_text, confidence or None, 300))
        res, err = _worker(ctx, bd, "annotate_function", wargs)
        if err:
            return err
        ids.add(fn.id)                       # the plate comment is part of the decompile text
        if rename_to:
            ids |= _callers(st, fn)
            rename_info = {"fn_id": fn.id, "name": res["name"], "namespace": res["namespace"],
                           "signature": res.get("signature"), "calling_conv": res.get("calling_conv")}
    nid = st.add_note(fn.binary_id, fn.space, fn.entry, summary, tag_text, confidence or None,
                      "agent", _now(), rename_info, ids)
    _refresh_map(ctx, bd)
    fresh = st.get_function(fn.id) or fn
    out = ([note] if note else []) + [f"note #{nid} saved on {fresh.qualified_name} "
                                      f"{bd.addr(fn.entry, fn.space)}"]
    if rename_info:
        out[-1] += f"; renamed {fn.qualified_name} -> {fresh.qualified_name}"
    if ids:
        out[-1] += f"; {_invalidated(len(ids))}"
    if mirror:
        out[-1] += "; mirrored to the plate comment"
    if refused_rename:
        out.append(refused_rename)
    return "\n".join(out)


# -- struct_define ---------------------------------------------------------------------------------

@tool("struct_define", "Create or replace a structure (fields: offset, type, name) in the Ghidra "
                       "project; cached decompiles that show it are refreshed.")
def struct_define(ctx: ServerContext, name: str, fields: list[dict[str, Any]], size: int = 0,
                  binary: str = "") -> str:
    refused = _gate(ctx)
    if refused:
        return refused
    name = name.strip()
    if not _IDENT.match(name):
        return f"error bad_args: '{name}' is not a C identifier. Use letters, digits and underscore."
    if not fields or len(fields) > MAX_FIELDS:
        return f"error bad_args: fields needs 1 to {MAX_FIELDS} entries of {{offset, type, name}}."
    bd = bind_binary(ctx, binary)
    if isinstance(bd, str):
        return bd
    if dn.is_managed_only(bd.binary):
        return _managed_only_refusal(bd, "structures do not apply.")
    args: dict[str, Any] = {"name": name, "fields": fields}
    if size:
        args["size"] = size
    res, err = _worker(ctx, bd, "define_struct", args)
    if err:
        return err
    ids = bd.store.function_ids_mentioning(bd.binary.id, name) if res.get("replaced") else []
    bd.store.bump_versions(ids)
    verb = "replaced" if res.get("replaced") else "created"
    tail = f"; {_invalidated(len(ids))}" if ids else ""
    return f"struct {name} {verb}: {res['size']} bytes, {res['fields']} fields{tail}"
