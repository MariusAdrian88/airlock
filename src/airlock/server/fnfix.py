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
from typing import Any

from airlock.index.store import Store

FIX_VERSION = 2          # 2: Delphi method and event addresses
BATCH = 4000          # addresses per worker call (the op accepts 20000)


def meta_key(binary_id: int) -> str:
    return f"fnfix_version:{binary_id}"


def info_key(binary_id: int) -> str:
    return f"fnfix_info:{binary_id}"


def stale(store: Store, binary_id: int) -> bool:
    return store.get_meta(meta_key(binary_id)) != str(FIX_VERSION)


def candidates(store: Store, binary_id: int) -> list[int]:
    """Sorted addresses of message map handlers, vtable slot targets and Delphi methods (published and
    virtual) and DFM event handlers that are no function entry of the binary."""
    sql = ("SELECT DISTINCT {col} FROM {tab} WHERE binary_id=?1 AND {col} IS NOT NULL AND {col} NOT IN "
           "(SELECT entry FROM function WHERE binary_id=?1 AND space='ram')")
    out: set[int] = set()
    for tab, col in (("msgmap_entry", "handler"), ("vtable_slot", "target"), ("dl_method", "addr"),
                     ("dl_event", "addr")):
        out.update(r[0] for r in store.db.execute(sql.format(tab=tab, col=col), (binary_id,)))
    return sorted(out)


def run(store: Store, binary_id: int, worker: Any, program: str) -> dict[str, Any]:
    """Call ``create_functions`` for the candidates of one binary; returns the merged summary
    (created, skipped, failed, reasons, requested). Does not touch the version meta."""
    cands = candidates(store, binary_id)
    total: dict[str, Any] = {"requested": len(cands), "created": 0, "skipped": 0, "failed": 0,
                             "reasons": {}, "sample": {}}
    for i in range(0, len(cands), BATCH):
        r = worker.request("create_functions", {"program": program, "addresses": cands[i:i + BATCH]},
                           timeout=3600)
        for k in ("created", "skipped", "failed"):
            total[k] += int(r.get(k) or 0)
        for k, n in (r.get("reasons") or {}).items():
            total["reasons"][k] = total["reasons"].get(k, 0) + n
        for k, v in (r.get("sample") or {}).items():
            total["sample"].setdefault(k, []).extend(v)
    return total


def record(store: Store, binary_id: int, summary: dict[str, Any]) -> None:
    small = {k: summary[k] for k in ("requested", "created", "skipped", "failed", "reasons")}
    with store.db:      # set_meta alone leaves the transaction open and locks the other threads
        store.set_meta(info_key(binary_id), json.dumps(small, separators=(",", ":")))
        store.set_meta(meta_key(binary_id), str(FIX_VERSION))
