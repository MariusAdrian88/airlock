"""Server <-> worker protocol: one JSON object per line, UTF-8.

Request:  {"id": 17, "op": "start_ghidra", "args": {...}}
Response: {"id": 17, "ok": true, "data": {...}}
          {"id": 17, "ok": false, "error": {"code": "...", "message": "..."}}
Event:    {"event": "progress", "job": "...", "pct": 62}   (no id)
"""

from __future__ import annotations

import json
from typing import Any


class WorkerError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def encode(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def decode(line: bytes) -> dict[str, Any]:
    obj = json.loads(line.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("protocol message must be an object")
    return obj
