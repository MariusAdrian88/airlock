"""Functions Ghidra did not create where static C++ tables prove code (DESIGN.md section 5).

MFC message map handlers and vtable slot targets (``server/cpp.py`` tables, derived from the PE)
are code entry points. Where the index has no function entry for them, the worker op
``create_functions`` disassembles and creates the function; the caller then re-reads the binary's
functions and edges. Vtable slots exist only for the vtables of RTTI classes (data pointers are
not candidates); the code check of ``cpp`` already ran on every target.

Versioned per binary by meta ``fnfix_version:<id>`` (``FIX_VERSION``): old projects do it once on
open, a failed address is not retried until the version is bumped.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from airlock.index.store import Store
from airlock.worker.protocol import WorkerError

FIX_VERSION = 6          # 6: direct call targets in no function; 5: route table handlers; 4: MFC dispatch map handlers; 3: Delphi property accessors; 2: Delphi method and event addresses
BATCH = 500           # addresses per worker call: one transaction and one save each (the op accepts 20000)
RESTARTED = ("worker_exited", "timeout")     # errors after which the worker process is gone


def meta_key(binary_id: int) -> str:
    return f"fnfix_version:{binary_id}"


def info_key(binary_id: int) -> str:
    return f"fnfix_info:{binary_id}"


def stale(store: Store, binary_id: int) -> bool:
    return store.get_meta(meta_key(binary_id)) != str(FIX_VERSION)


def candidates(store: Store, binary_id: int) -> list[int]:
    """Sorted addresses of message map handlers, vtable slot targets, Delphi methods (published and
    virtual), DFM event handlers and direct call targets that are no function entry of the binary."""
    sql = ("SELECT DISTINCT {col} FROM {tab} WHERE binary_id=?1 AND {col} IS NOT NULL AND {col} NOT IN "
           "(SELECT entry FROM function WHERE binary_id=?1 AND space='ram')")
    out: set[int] = set()
    code_methods = "(SELECT binary_id, addr FROM dl_method WHERE kind NOT IN ('interface-tab', 'interface-table', 'header'))"
    for tab, col in (("msgmap_entry", "handler"), ("vtable_slot", "target"), (code_methods, "addr"),
                     ("dl_event", "addr"), ("mfc_map_entry", "pfn"), ("mfc_map_entry", "pfn_set")):
        out.update(r[0] for r in store.db.execute(sql.format(tab=tab, col=col), (binary_id,)))
    out.update(_call_targets(store, binary_id))
    return sorted(out)


def _call_targets(store: Store, binary_id: int) -> list[int]:
    """Direct call targets (edges of kind ``call`` with no function) that lie in no function body."""
    import bisect

    fns = store.db.execute("SELECT entry, COALESCE(size, 0) FROM function WHERE binary_id=? AND space='ram' "
                           "AND is_external=0 ORDER BY entry", (binary_id,)).fetchall()
    ent = [f[0] for f in fns]
    out = []
    for (t,) in store.db.execute("SELECT DISTINCT dst_addr FROM edge WHERE binary_id=? AND kind='call' "
                                 "AND dst_fn IS NULL", (binary_id,)).fetchall():
        i = bisect.bisect_right(ent, t) - 1
        if i >= 0 and fns[i][0] <= t < fns[i][0] + fns[i][1]:
            continue
        out.append(t)
    return out


def _merge(total: dict[str, Any], r: dict[str, Any]) -> None:
    for k in ("created", "skipped", "failed"):
        total[k] += int(r.get(k) or 0)
    for k, n in (r.get("reasons") or {}).items():
        total["reasons"][k] = total["reasons"].get(k, 0) + n
    for k, v in (r.get("sample") or {}).items():
        total["sample"].setdefault(k, []).extend(v)


def run(store: Store, binary_id: int, worker: Any, program: str,
        recover: Callable[[], None] | None = None, log: Callable[[str], None] | None = None,
        progress: Callable[[int, int], None] | None = None) -> dict[str, Any]:
    """Call ``create_functions`` for the candidates of one binary in chunks of ``BATCH`` (one Ghidra
    transaction and save per chunk, the conventions pass only with the last); returns the merged summary
    (created, skipped, failed, reasons, requested). Does not touch the version meta.

    When the worker process exits during a chunk (``worker_exited``, ``timeout``) the cause is logged,
    ``recover()`` reopens the program and re-reads the functions the finished chunks created, and the
    candidates still missing are sent once more. A second exit raises."""
    say = log or (lambda _msg: None)
    cands = candidates(store, binary_id)
    total: dict[str, Any] = {"requested": len(cands), "created": 0, "skipped": 0, "failed": 0,
                             "reasons": {}, "sample": {}}
    retried = False
    pending = cands
    done = 0
    if progress:
        progress(0, len(cands))
    while pending:
        chunk, rest = pending[:BATCH], pending[BATCH:]
        try:
            r = worker.request("create_functions", {"program": program, "addresses": chunk,
                                                    "conventions": not rest, "known_code": True}, timeout=3600)
        except WorkerError as e:
            if e.code not in RESTARTED or retried or recover is None:
                raise
            retried = True
            say(f"worker lost during create_functions ({e.code}: {e.message}) after {done} of "
                f"{len(cands)} addresses; restarting and retrying the rest")
            recover()
            pending = candidates(store, binary_id)      # the chunks that were saved are indexed now
            total["requested"] = done + len(pending)
            continue
        _merge(total, r)
        done += len(chunk)
        if progress:
            progress(done, len(cands))
        say(f"create_functions {done} of {len(cands)} addresses, {total['created']} created")
        pending = rest
    return total


def record(store: Store, binary_id: int, summary: dict[str, Any]) -> None:
    small = {k: summary[k] for k in ("requested", "created", "skipped", "failed", "reasons")}
    with store.db:      # set_meta alone leaves the transaction open and locks the other threads
        store.set_meta(info_key(binary_id), json.dumps(small, separators=(",", ":")))
        store.set_meta(meta_key(binary_id), str(FIX_VERSION))
