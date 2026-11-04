"""Reader/writer lock for a Ghidra program (no Ghidra imports, unit-testable).

Rules
- Any number of readers (decompilation of different functions), or exactly one writer
  (analysis, link_externals, save, renames, closing the project).
- Writer-preferring: once a writer waits, new readers queue behind it, so a write never
  starves behind a continuous stream of decompiles.
- A writer is re-entrant, and may take the read side while it holds the write side.
- Readers are NOT re-entrant: never take read() while already holding read() on the same
  lock (a waiting writer would deadlock the pair).
- `with lock:` is the write side, so code written for an RLock keeps working unchanged.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator


class RWLock:
    def __init__(self) -> None:
        self._cond = threading.Condition(threading.Lock())
        self._readers = 0
        self._writer: int | None = None
        self._depth = 0
        self._waiting_writers = 0

    # -- write side ---------------------------------------------------------

    def acquire_write(self) -> None:
        me = threading.get_ident()
        with self._cond:
            if self._writer == me:
                self._depth += 1
                return
            self._waiting_writers += 1
            try:
                while self._writer is not None or self._readers:
                    self._cond.wait()
            finally:
                self._waiting_writers -= 1
            self._writer, self._depth = me, 1

    def release_write(self) -> None:
        with self._cond:
            if self._writer != threading.get_ident():
                raise RuntimeError("release_write by a thread that does not hold the write lock")
            self._depth -= 1
            if self._depth == 0:
                self._writer = None
                self._cond.notify_all()

    # -- read side ----------------------------------------------------------

    def acquire_read(self) -> bool:
        """Returns True when the call nested inside this thread's own write lock."""
        me = threading.get_ident()
        with self._cond:
            if self._writer == me:
                self._depth += 1
                return True
            while self._writer is not None or self._waiting_writers:
                self._cond.wait()
            self._readers += 1
            return False

    def release_read(self, nested: bool = False) -> None:
        if nested:
            self.release_write()
            return
        with self._cond:
            self._readers -= 1
            if self._readers == 0:
                self._cond.notify_all()

    # -- context managers ---------------------------------------------------

    @contextmanager
    def read(self) -> Iterator[None]:
        nested = self.acquire_read()
        try:
            yield
        finally:
            self.release_read(nested)

    @contextmanager
    def write(self) -> Iterator[None]:
        self.acquire_write()
        try:
            yield
        finally:
            self.release_write()

    def __enter__(self) -> "RWLock":
        self.acquire_write()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release_write()

    @property
    def readers(self) -> int:
        return self._readers
