"""annotate set: rename, retype, comment, annotate (note + optional rename), struct_define.

Each tool changes the Ghidra project through a worker write op (one transaction, saved before the
answer), then updates the index and bumps ``function.version`` of everything whose decompile text
can change (DESIGN.md section 5 "Invalidation"); cached decompiles, asm and outlines of an older
version are recomputed on the next request. Ghidra is the source of truth: the index is updated
after a successful worker answer only. Notes are agent data in the ``note`` table (they are not
written to Ghidra except as the optional plate-comment mirror).

Tools exist only when allow_writes is on (the loader hides them otherwise); a clean session never
reaches them (role gate). ``patch_bytes`` is off by default (``disabled_tools``).
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
from airlock.server.indexer import WORKER_LOG_FACT, worker_error
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

# The next step after a worker error, only where it is data the agent needs (the force flag is
# the agent's decision to cut instructions or overwrite) or a fix only the user can make.
_HINTS = {
    "uninitialized": "uninitialised memory has no file bytes",
    "boundary": "force=true cuts or re-decodes them",
    "changed": "the bytes changed since the patch; force=true restores anyway",
    "decompile_failed": "the limit is defaults.decompile_timeout_s in config.jsonc",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- shared steps ----------------------------------------------------------------------------------

def _gate(ctx: ServerContext) -> str | None:
    if ctx.session.role == roles.CLEAN:
        return "error wrong_role: write tools are not available in a clean-room session."
    if not ctx.config.allow_writes:
        return "error writes_disabled: allow_writes is off in config.jsonc."
    return None


def _bad_name(name: str, what: str = "name") -> str | None:
    if not name or _NAME_BAD.search(name):
        return f"error bad_args: {what} must be non-empty with no spaces."
    return None


def _worker(ctx: ServerContext, bd: Bound, op: str, args: dict[str, Any]) -> tuple[dict | None, str | None]:
    """(reply, error line) for a worker write op on the binary's program."""
    ix = ctx.indexer
    for attempt in (1, 2):      # a decompile the write needs may fail once on a busy worker
        try:
            ix.ensure_open(bd.project)
            r = ctx.worker.request(op, {"program": ix.program_of(bd.store, bd.binary), **args}, timeout=600)
        except WorkerError as e:
            if e.code == "decompile_failed" and attempt == 1:
                continue
            hint = _HINTS.get(e.code, "" if e.code in _SELF_EXPLAINED else WORKER_LOG_FACT)
            return None, worker_error(e, hint)
        return r, None
    return None, None   # not reached


# worker error codes whose message says all there is (names, kinds, candidates)
_SELF_EXPLAINED = frozenset({"bad_name", "bad_type", "exists", "no_variable", "no_function",
                             "wrong_kind", "ambiguous", "not_found"})


def _managed_fn(bd: Bound, fn: Function) -> bool:
    return dn.is_managed_site(bd.binary, fn.space, fn.entry)


def _managed_refusal(fn: Function, what: str) -> str:
    """One line for a write that has no target: a .NET method has no Ghidra function."""
    return f"error managed: {fn.qualified_name} is a .NET method; {what} {_NOTE_ONLY}"


_NOTE_ONLY = "A note is the only annotation it takes."
_NAME_FACT = "its name comes from metadata."
_VAR_FACT = "its variables and types come from metadata, not from Ghidra."
_CMT_FACT = "it has no Ghidra function to hold a comment."


def _managed_only_refusal(bd: Bound, what: str) -> str:
    return (f"error managed: {bd.binary.name} is a managed-only .NET assembly with no Ghidra program; "
            f"{what} A note on a method is the only annotation it takes.")


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
        return tg.err("external", f"{ft.fn.qualified_name} is an imported function with no code")
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
        return f"error bad_args: unknown kind '{kind}' (kinds: function, global, label, local)."
    bad = _bad_name(new_name, "new_name")
    if bad:
        return bad
    if not target.strip():
        return "error bad_target: target is empty."
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
                "variable's current name.")
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
        return ("error ambiguous_binary: the project has several binaries: "
                f"{', '.join(b.binary.name for b in sc.bounds)}.")
    bd = sc.bounds[0]
    st = bd.store
    if dn.is_managed_only(bd.binary):
        return _managed_only_refusal(bd, "labels and names come from metadata.")
    used = ""
    parsed = parse_address(sc.bare)
    if parsed is not None:
        space, value = parsed
        if dn.is_managed_site(bd.binary, space, value):
            return (f"error managed: {fmt_addr(value, bd.psize, space)} is a .NET metadata token, not "
                    f"Ghidra code; its name comes from metadata. {_NOTE_ONLY}")
        if kind == "label" and st.function_containing(bd.binary.id, value, space) is None:
            kind = "global"     # a label outside every function is a global data label
            used = f"(kind=global used: {fmt_addr(value, bd.psize, space)} is not inside a function)\n"
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
    return f"{used}{what} at {bd.addr(addr, space)}; {_invalidated(len(ids))}"


# -- retype ----------------------------------------------------------------------------------------

@tool("retype", "Set the data type of a local variable or parameter of a function; returns the "
                "refreshed decompile lines that use it.")
def retype(ctx: ServerContext, function: str, variable: str, type: str, binary: str = "") -> str:
    refused = _gate(ctx)
    if refused:
        return refused
    variable, type_ = variable.strip(), type.strip()
    if not variable or not type_:
        return "error bad_args: variable and type are required."
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
    return head + "\n" + _excerpt(c_text, variable, res.get("type") or type_)


def _word(name: str) -> re.Pattern[str]:
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])")


def _excerpt(c_text: str, variable: str, type_: str = "") -> str:
    """Decompile lines that mention the variable, numbered, at most EXCERPT_LINES. When the
    decompiler renamed it (automatic variables are named by type), the lines with the new type."""
    lines = [(i, ln.rstrip()) for i, ln in enumerate(c_text.splitlines(), 1) if ln.strip()]
    hits = [(i, ln) for i, ln in lines if _word(variable).search(ln)]
    what = variable
    if not hits:
        base = re.sub(r"[\s*&\[\]0-9]+$", "", type_.strip()).split()[-1:] if type_.strip() else []
        if base:
            hits = [(i, ln) for i, ln in lines if _word(base[0]).search(ln)]
            what = base[0]
        if not hits:
            return (f"no decompile line names '{variable}' now (the decompiler renames automatic "
                    "variables by type)")
        hits = [(0, f"no line names '{variable}' now (renamed by type); lines with {what}:")] + hits
    shown = hits[:EXCERPT_LINES]
    out = [f"{i:>5}  {ln}" if i else ln for i, ln in shown]
    if len(hits) > len(shown):
        rest = [str(i) for i, _ln in hits[len(shown):]]
        out.append(f"… {len(rest)} more lines use {what}: " + " ".join(rest[:20])
                   + (" …" if len(rest) > 20 else ""))
    return "\n".join(out)


# -- comment ---------------------------------------------------------------------------------------

@tool("comment", "Set a plate, pre or end-of-line comment at an address in Ghidra (empty text clears it).")
def comment(ctx: ServerContext, address: str, text: str, kind: str = "plate", binary: str = "") -> str:
    refused = _gate(ctx)
    if refused:
        return refused
    if kind not in COMMENT_KINDS:
        return f"error bad_args: unknown kind '{kind}' (kinds: plate, pre, eol)."
    if len(text) > MAX_COMMENT:
        return f"error bad_args: text is {len(text)} characters, the limit is {MAX_COMMENT}."
    if not address.strip():
        return "error bad_target: address is empty."
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
        return f"error managed: {what} is a .NET method; {_CMT_FACT} {_NOTE_ONLY}"
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
                f"{nt.MAX_SUMMARY}.")
    confidence = confidence.strip().lower()
    if confidence and confidence not in nt.CONFIDENCE:
        return "error bad_args: confidence must be low, medium or high."
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
            _NOTE_ONLY, "The rename was not applied; the note was saved.")
        rename_to = ""
    elif rename_to and fn.is_external:
        return tg.err("external", f"{fn.qualified_name} is an imported function with no code")
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
                      ctx.author, _now(), rename_info, ids)
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
        return f"error bad_args: '{name}' is not a C identifier (letters, digits, underscore)."
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


# -- patch_bytes -----------------------------------------------------------------------------------

_PATCH_NOTE = re.compile(r"patch (\S+) (\d+) bytes: old=([0-9a-f]+) new=([0-9a-f]+)")
MAX_PATCH = 512


def _hex_bytes(text: str) -> bytes | None:
    s = re.sub(r"0x|[\s,]", "", text or "", flags=re.I)
    if not s or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    return bytes.fromhex(s)


@tool("patch_bytes", "Write bytes into the Ghidra program (never the file) with an automatic note; "
                     "restore=<note id> undoes a patch.")
def patch_bytes(ctx: ServerContext, address: str = "", hex: str = "", why: str = "", force: bool = False,
                restore: int = 0, binary: str = "") -> str:
    refused = _gate(ctx)
    if refused:
        return refused
    if restore:
        return _restore_patch(ctx, restore, why, force, binary)
    if not address.strip():
        return "error bad_target: address is empty."
    data = _hex_bytes(hex)
    if data is None or len(data) > MAX_PATCH:
        return (f"error bad_args: hex must be 1 to {MAX_PATCH} bytes of hex digits, e.g. '90 90' or "
                "8BFF55.")
    site = _site(ctx, binary, address)
    if isinstance(site, str):
        return site
    bd, space, offset, fn = site
    return _do_patch(ctx, bd, space, offset, fn, data, why, force, None, 0)


def _do_patch(ctx: ServerContext, bd: Bound, space: str, offset: int, fn: Function | None,
              data: bytes, why: str, force: bool, expect: bytes | None, restores: int) -> str:
    if dn.is_managed_only(bd.binary) or (fn is not None and _managed_fn(bd, fn)):
        return _managed_only_refusal(bd, "it has no machine code to patch.")
    wargs: dict[str, Any] = {"space": space, "address": offset, "hex": data.hex(), "force": force}
    if expect is not None:
        wargs["expect"] = expect.hex()
    res, err = _worker(ctx, bd, "patch_bytes", wargs)
    if err:
        return err
    st = bd.store
    ids: set[int] = {fn.id} if fn is not None else set()
    for entry in res.get("functions") or []:
        f = st.function_at(bd.binary.id, entry, "ram")
        if f is not None:
            ids.add(f.id)
    key = fn if fn is not None else (st.get_function(min(ids)) if ids else None)
    where = bd.addr(res["address"], space)
    summary = (f"patch {where} {res['length']} bytes: old={res['old']} new={res['new']}"
               + (f" (restore of note #{restores})" if restores else "")
               + (f" why: {why.strip()}" if why.strip() else ""))
    nid = st.add_note(bd.binary.id, key.space if key else space, key.entry if key else res["address"],
                      summary, "patch", None, ctx.author, _now(), None, ids)
    _refresh_map(ctx, bd)
    name = f" in {key.qualified_name}" if key else ""
    out = (f"patched {res['length']} bytes at {where}{name}: old {res['old']}, new {res['new']}; "
           f"note #{nid}; {_invalidated(len(ids))}")
    if res.get("cleared"):
        out += f"; re-disassembled {res.get('instructions', 0)} instructions"
    return out + "."


def _restore_patch(ctx: ServerContext, note_id: int, why: str, force: bool, binary: str) -> str:
    bd = bind_binary(ctx, binary)
    if isinstance(bd, str):
        return bd
    row = bd.store.get_note(note_id)
    m = _PATCH_NOTE.search(row["summary"]) if row is not None else None
    if row is None or m is None or "patch" not in (row["tags"] or "").split(","):
        return f"error not_found: note #{note_id} is not a patch note of this binary. List them with search kind=note."
    other = row["binary_id"]
    if other != bd.binary.id:
        bd = Bound(bd.project, bd.store, bd.store.get_binary_by_id(other))   # type: ignore[arg-type]
    p = parse_address(m.group(1))
    if p is None:
        return f"error bad_args: note #{note_id} has no readable address."
    space, offset = p
    fn = bd.store.function_containing(bd.binary.id, offset, space)
    return _do_patch(ctx, bd, space, offset, fn, bytes.fromhex(m.group(3)), why or "", force,
                     bytes.fromhex(m.group(4)), note_id)
