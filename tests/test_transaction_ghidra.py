"""Ghidra 12.1.4: ending an EMPTY transaction with commit=false makes the commits after it vanish
(they are visible in memory but are not in the saved program). airlock's `session.transaction`
must never do that.

    pytest -q -m ghidra --binary=<exe>

Runs Ghidra in this process on a copy-free temp project; no other test in this file set shares the JVM.
"""

from __future__ import annotations

import pytest

from airlock.config.loader import load_config

pytestmark = pytest.mark.ghidra


@pytest.fixture(scope="module")
def gp(binary_path, tmp_path_factory):
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    HeadlessPyGhidraLauncher(verbose=False, install_dir=str(load_config().ghidra_dir)).start()
    from ghidra.base.project import GhidraProject  # type: ignore
    from java.io import File  # type: ignore

    proj = GhidraProject.createProject(str(tmp_path_factory.mktemp("txproj")), "tx", True)
    prog = proj.importProgram(File(binary_path))
    proj.saveAs(prog, "/", "p", True)
    proj.close(prog)
    yield proj
    proj.close()


class _Prog:
    """One program of the project: write a byte, save, reopen, read what was saved."""

    def __init__(self, gp, name):
        self.gp, self.name = gp, name
        self.p = gp.openProgram("/", name, False)
        self.addr = self.p.getMinAddress().add(0x1000)

    def put(self, v, commit=True):
        tx = self.p.startTransaction("w")
        self.p.getMemory().setByte(self.addr, v)
        self.p.endTransaction(tx, commit)

    def saved(self):
        self.gp.save(self.p)
        self.gp.close(self.p)
        self.p = self.gp.openProgram("/", self.name, False)
        return self.p.getMemory().getByte(self.addr) & 0xFF


def _copy(gp, name):
    prog = gp.openProgram("/", "p", False)
    gp.saveAs(prog, "/", name, True)
    gp.close(prog)
    return _Prog(gp, name)


def test_ghidra_empty_rollback_loses_later_commits(gp):
    """The reproduction (documents the Ghidra behaviour the helper works around)."""
    t = _copy(gp, "raw")
    t.put(0x11)
    tx = t.p.startTransaction("empty")
    t.p.endTransaction(tx, False)                  # nothing changed, commit=false
    t.put(0x31)
    assert t.saved() != 0x31, "Ghidra no longer loses commits after an empty rollback: the helper is not needed"


def test_session_transaction_keeps_later_commits(gp):
    from airlock.worker.ghidra_ops import session as S

    t = _copy(gp, "helper")
    t.put(0x11)
    with pytest.raises(RuntimeError):
        with S.transaction(t.p, "refused"):
            raise RuntimeError("refused before any change")
    tx = t.p.startTransaction("later")
    t.p.getMemory().setByte(t.addr, 0x31)
    t.p.endTransaction(tx, True)
    assert t.saved() == 0x31


def test_session_transaction_rolls_back_a_real_partial_change(gp):
    from airlock.worker.ghidra_ops import session as S

    t = _copy(gp, "partial")
    t.put(0x11)
    t.gp.save(t.p)     # every worker write saves; a rollback goes back to the last saved state
    with pytest.raises(RuntimeError):
        with S.transaction(t.p, "partial"):
            t.p.getMemory().setByte(t.addr, 0x22)
            raise RuntimeError("failed after a change")
    assert t.saved() == 0x11
