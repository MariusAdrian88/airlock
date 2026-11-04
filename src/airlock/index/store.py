"""SQLite index store (DESIGN.md section 4). No Ghidra imports here."""

from __future__ import annotations

import bisect
import re
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from airlock.index.migrations import MIGRATIONS

SCHEMA_VERSION = 5

FTS_KINDS = ("function", "string", "import")
CODE_EDGES = ("call", "call_ind", "jump")


@dataclass(frozen=True)
class Binary:
    id: int
    sha256: str
    name: str
    original_path: str | None
    format: str | None
    arch: str | None
    pointer_size: int | None
    image_base: int | None
    toolchain: str | None
    toolchain_ver: str | None
    analysis_profile: str | None
    imported_at: str | None
    analysed_at: str | None


@dataclass(frozen=True)
class Function:
    id: int
    binary_id: int
    space: str
    entry: int
    name: str
    name_state: str
    namespace: str | None
    signature: str | None
    calling_conv: str | None
    size: int | None
    is_thunk: bool
    is_external: bool
    bytes_hash: str | None
    masked_hash: str | None
    version: int

    @property
    def qualified_name(self) -> str:
        return f"{self.namespace}::{self.name}" if self.namespace else self.name


@dataclass(frozen=True)
class Xref:
    """One edge. ``src_fn``/``dst_fn`` are function rows when known."""

    src_addr: int
    dst_addr: int
    kind: str
    src_fn: Function | None
    dst_fn: Function | None


@dataclass(frozen=True)
class CrossRef:
    """One cross-binary edge: an import slot or thunk in ``src_binary`` bound to the exporting
    function ``dst_entry`` of ``dst_binary``. ``src_fn``/``dst_fn`` are function rows when known."""

    src_binary: int
    src_addr: int
    dst_binary: int
    dst_entry: int
    kind: str
    src_fn: Function | None
    dst_fn: Function | None


@dataclass(frozen=True)
class StringHit:
    id: int
    address: int
    encoding: str
    value: str
    refs: tuple[Function, ...] = ()


@dataclass(frozen=True)
class FtsHit:
    kind: str
    ref_id: int
    text: str


@dataclass(frozen=True)
class Decomp:
    function_id: int
    fn_version: int
    analysis_profile: str
    c_text: str | None
    status: str
    error: str | None
    produced_at: str | None


_BINARY_COLS = (
    "id sha256 name original_path format arch pointer_size image_base "
    "toolchain toolchain_ver analysis_profile imported_at analysed_at"
).split()
_FUNCTION_COLS = (
    "id binary_id space entry name name_state namespace signature calling_conv "
    "size is_thunk is_external bytes_hash masked_hash version"
).split()
_FN_SELECT = ", ".join(f"f.{c}" for c in _FUNCTION_COLS)
_LIKE_ESC = str.maketrans({"\\": "\\\\", "%": "\\%", "_": "\\_"})


def _binary(row: sqlite3.Row) -> Binary:
    return Binary(**{c: row[c] for c in _BINARY_COLS})


def _function(row: sqlite3.Row, prefix: str = "") -> Function:
    d = {c: row[prefix + c] for c in _FUNCTION_COLS}
    d["is_thunk"] = bool(d["is_thunk"])
    d["is_external"] = bool(d["is_external"])
    return Function(**d)


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _camel_words(text: str | None) -> str:
    """'CreateFileW' -> 'Create File W', so name parts are searchable."""
    return _CAMEL.sub(" ", text) if text else ""


def _fts_query(text: str) -> str | None:
    toks = re.findall(r"[^\W_]+", text)
    if not toks:
        return None
    # Restrict to the text column: `kind` is indexed too, and a query such as "fun"
    # or "import" would otherwise match every row of that kind.
    return "text : (" + " ".join(f'"{t}"*' for t in toks) + ")"


class Store:
    """One index.sqlite. Not thread-safe; use one Store per thread."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.row_factory = sqlite3.Row
        self.db.create_function("camel_words", 1, _camel_words, deterministic=True)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.execute("PRAGMA synchronous = NORMAL")
        self._init_schema()

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _init_schema(self) -> None:
        has = self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if not has:
            sql = resources.files("airlock.index").joinpath("schema.sql").read_text("utf-8")
            self.db.executescript(sql)
            with self.db:
                self.set_meta("schema_version", str(SCHEMA_VERSION))
            return
        cur = self.schema_version
        if cur > SCHEMA_VERSION:
            raise RuntimeError(f"index schema {cur} is newer than supported {SCHEMA_VERSION}")
        while cur < SCHEMA_VERSION:
            cur += 1
            mig = MIGRATIONS.get(cur)
            if mig is None:
                raise RuntimeError(f"no migration to schema version {cur}")
            with self.db:
                mig(self.db)
                self.set_meta("schema_version", str(cur))

    @property
    def schema_version(self) -> int:
        v = self.get_meta("schema_version")
        return int(v) if v else 0

    def get_meta(self, key: str) -> str | None:
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # -- binaries ----------------------------------------------------------

    def upsert_binary(self, sha256: str, name: str, **fields: Any) -> int:
        """Insert or update by sha256; returns the binary id. ``fields`` are
        other ``binary`` columns (format, arch, image_base, ...)."""
        bad = set(fields) - set(_BINARY_COLS) - {"id", "sha256", "name"}
        if bad:
            raise ValueError(f"unknown binary columns: {sorted(bad)}")
        cols = ["sha256", "name", *fields]
        vals = [sha256, name, *fields.values()]
        upd = ", ".join(f"{c}=excluded.{c}" for c in cols[1:])
        with self.db:
            self.db.execute(
                f"INSERT INTO binary({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) "
                f"ON CONFLICT(sha256) DO UPDATE SET {upd}",
                vals,
            )
            r = self.db.execute("SELECT id FROM binary WHERE sha256=?", (sha256,)).fetchone()
        return int(r["id"])

    def list_binaries(self) -> list[Binary]:
        return [_binary(r) for r in self.db.execute("SELECT * FROM binary ORDER BY id")]

    def find_binaries(self, ref: str) -> list[Binary]:
        """All binaries matching ``ref`` by exact name (case-insensitive) or
        sha256 prefix."""
        rows = self.db.execute(
            "SELECT * FROM binary WHERE lower(name)=lower(?) OR sha256 LIKE ? ESCAPE '\\' "
            "ORDER BY id",
            (ref, ref.lower().translate(_LIKE_ESC) + "%"),
        ).fetchall()
        return [_binary(r) for r in rows]

    def get_binary(self, ref: str) -> Binary | None:
        """The unique match for ``ref`` (name or sha256 prefix), else None."""
        found = self.find_binaries(ref)
        return found[0] if len(found) == 1 else None

    def get_binary_by_id(self, binary_id: int) -> Binary | None:
        r = self.db.execute("SELECT * FROM binary WHERE id=?", (binary_id,)).fetchone()
        return _binary(r) if r else None

    # -- batch inserts (each call is one transaction) ------------------------

    def clear_binary_data(self, binary_id: int) -> None:
        """Drop all derived rows of a binary (before a re-extract)."""
        fids = "SELECT id FROM function WHERE binary_id=?"
        with self.db:
            q = self.db.execute
            q(f"DELETE FROM ast_node WHERE function_id IN ({fids})", (binary_id,))
            q(f"DELETE FROM decomp WHERE function_id IN ({fids})", (binary_id,))
            q("DELETE FROM edge WHERE binary_id=?", (binary_id,))
            q("DELETE FROM string WHERE binary_id=?", (binary_id,))
            q("DELETE FROM import WHERE binary_id=?", (binary_id,))
            q("DELETE FROM export WHERE binary_id=?", (binary_id,))
            q("DELETE FROM xedge WHERE src_binary=? OR dst_binary=?", (binary_id, binary_id))
            q("DELETE FROM feature_entry WHERE binary_id=?", (binary_id,))
            q("DELETE FROM function WHERE binary_id=?", (binary_id,))
            q("DELETE FROM fts WHERE binary_id=?", (binary_id,))

    def insert_functions(self, binary_id: int, rows: Iterable[dict[str, Any]]) -> None:
        """Rows: dicts with ``entry``, ``name``, ``name_state`` and optional
        space, namespace, signature, calling_conv, size, is_thunk, is_external,
        bytes_hash, masked_hash. A row for an existing (space, entry) updates it;
        ``version`` is bumped only if name, namespace, signature, calling_conv
        or size changed."""
        data = [
            (
                binary_id, r.get("space", "ram"), r["entry"], r["name"], r["name_state"],
                r.get("namespace"), r.get("signature"), r.get("calling_conv"), r.get("size"),
                int(bool(r.get("is_thunk", 0))), int(bool(r.get("is_external", 0))),
                r.get("bytes_hash"), r.get("masked_hash"),
            )
            for r in rows
        ]
        with self.db:
            self.db.executemany(
                "INSERT INTO function(binary_id, space, entry, name, name_state, namespace, "
                "signature, calling_conv, size, is_thunk, is_external, bytes_hash, masked_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(binary_id, space, entry) DO UPDATE SET "
                "name=excluded.name, name_state=excluded.name_state, "
                "namespace=excluded.namespace, signature=excluded.signature, "
                "calling_conv=excluded.calling_conv, size=excluded.size, "
                "is_thunk=excluded.is_thunk, is_external=excluded.is_external, "
                "bytes_hash=excluded.bytes_hash, masked_hash=excluded.masked_hash, "
                "version=function.version + CASE WHEN "
                "function.name IS NOT excluded.name OR "
                "function.namespace IS NOT excluded.namespace OR "
                "function.signature IS NOT excluded.signature OR "
                "function.calling_conv IS NOT excluded.calling_conv OR "
                "function.size IS NOT excluded.size THEN 1 ELSE 0 END",
                data,
            )

    def insert_edges(self, binary_id: int, rows: Iterable[tuple[int, int, str]]) -> None:
        """Rows: (src_addr, dst_addr, kind). Call ``link_edges`` afterwards to
        fill src_fn / dst_fn."""
        with self.db:
            self.db.executemany(
                "INSERT INTO edge(binary_id, src_addr, dst_addr, kind) VALUES (?,?,?,?)",
                [(binary_id, s, d, k) for s, d, k in rows],
            )

    def link_edges(self, binary_id: int) -> None:
        """Fill edge.src_fn / dst_fn with the function containing each address
        (ram space; size NULL/0 counts as 1 byte)."""
        # Done in Python with a sorted entry table: a correlated SQL lookup is
        # O(functions) per address that lies in no function (data, strings).
        fns = self.db.execute(
            "SELECT id, entry, MAX(COALESCE(size,0),1) AS sz FROM function "
            "WHERE binary_id=? AND space='ram' ORDER BY entry", (binary_id,)
        ).fetchall()
        entries = [r["entry"] for r in fns]

        def find(addr: int) -> int | None:
            i = bisect.bisect_right(entries, addr) - 1
            for k in range(i, max(i - 8, -1), -1):  # overlapping bodies are rare
                if addr < fns[k]["entry"] + fns[k]["sz"]:
                    return fns[k]["id"]
            return None

        rows = self.db.execute(
            "SELECT rowid, src_addr, dst_addr FROM edge WHERE binary_id=?", (binary_id,)
        ).fetchall()
        with self.db:
            self.db.executemany(
                "UPDATE edge SET src_fn=?, dst_fn=? WHERE rowid=?",
                [(find(r["src_addr"]), find(r["dst_addr"]), r["rowid"]) for r in rows],
            )

    def insert_strings(self, binary_id: int, rows: Iterable[tuple[int, str, str]]) -> None:
        """Rows: (address, encoding, value)."""
        with self.db:
            self.db.executemany(
                "INSERT INTO string(binary_id, address, encoding, value) VALUES (?,?,?,?)",
                [(binary_id, a, e, v) for a, e, v in rows],
            )

    def insert_imports(
        self, binary_id: int, rows: Iterable[tuple[str | None, str | None, int | None, int | None]]
    ) -> None:
        """Rows: (dll, name, ordinal, address)."""
        with self.db:
            self.db.executemany(
                "INSERT INTO import(binary_id, dll, name, ordinal, address) VALUES (?,?,?,?,?)",
                [(binary_id, *r) for r in rows],
            )

    def insert_exports(
        self, binary_id: int, rows: Iterable[tuple[str | None, int | None, int]]
    ) -> None:
        """Rows: (name, ordinal, address)."""
        with self.db:
            self.db.executemany(
                "INSERT INTO export(binary_id, name, ordinal, address) VALUES (?,?,?,?)",
                [(binary_id, *r) for r in rows],
            )

    def insert_ast_nodes(self, function_id: int, rows: Iterable[dict[str, Any]]) -> None:
        """Replace all ast nodes of the function. Rows: kind, start_off,
        end_off and optional address, target, text."""
        with self.db:
            self.db.execute("DELETE FROM ast_node WHERE function_id=?", (function_id,))
            self.db.executemany(
                "INSERT INTO ast_node(function_id, kind, start_off, end_off, address, target, "
                "text) VALUES (?,?,?,?,?,?,?)",
                [
                    (function_id, r["kind"], r["start_off"], r["end_off"], r.get("address"),
                     r.get("target"), r.get("text"))
                    for r in rows
                ],
            )

    def upsert_decomp(
        self, function_id: int, fn_version: int, analysis_profile: str, status: str,
        c_text: str | None = None, error: str | None = None, produced_at: str | None = None,
    ) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO decomp(function_id, fn_version, analysis_profile, c_text, status, "
                "error, produced_at) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(function_id) DO UPDATE SET fn_version=excluded.fn_version, "
                "analysis_profile=excluded.analysis_profile, c_text=excluded.c_text, "
                "status=excluded.status, error=excluded.error, produced_at=excluded.produced_at",
                (function_id, fn_version, analysis_profile, c_text, status, error, produced_at),
            )

    # -- FTS ---------------------------------------------------------------

    def rebuild_fts(self, binary_id: int) -> None:
        """Repopulate fts rows (function names, strings, imports) of a binary.
        ref_id is function.id, string.id or import rowid."""
        with self.db:
            self.db.execute("DELETE FROM fts WHERE binary_id=?", (binary_id,))
            self.db.execute(
                "INSERT INTO fts(kind, ref_id, binary_id, text) "
                "SELECT 'function', id, binary_id, "
                "CASE WHEN namespace IS NULL OR namespace='' THEN name "
                "ELSE namespace || '::' || name END || ' ' || "
                "camel_words(COALESCE(namespace || ' ', '') || name) "
                "FROM function WHERE binary_id=?",
                (binary_id,),
            )
            self.db.execute(
                "INSERT INTO fts(kind, ref_id, binary_id, text) "
                "SELECT 'string', id, binary_id, value FROM string WHERE binary_id=?",
                (binary_id,),
            )
            self.db.execute(
                "INSERT INTO fts(kind, ref_id, binary_id, text) "
                "SELECT 'import', rowid, binary_id, "
                "COALESCE(dll || '!', '') || COALESCE(name, '#' || ordinal) || ' ' || "
                "camel_words(COALESCE(name, '')) "
                "FROM import WHERE binary_id=?",
                (binary_id,),
            )

    def fts_search(
        self, binary_id: int, query: str, kind: str | None = None, limit: int = 50
    ) -> list[FtsHit]:
        """Token-prefix AND search; ``kind`` is function | string | import."""
        q = _fts_query(query)
        if q is None:
            return []
        sql = "SELECT kind, ref_id, text FROM fts WHERE fts MATCH ? AND binary_id=?"
        args: list[Any] = [q, binary_id]
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        sql += " ORDER BY rank LIMIT ?"
        args.append(limit)
        return [FtsHit(r["kind"], r["ref_id"], r["text"]) for r in self.db.execute(sql, args)]

    def has_local_twin(self, binary_id: int, name: str) -> bool:
        """True when a non-external function or an import row has exactly ``name``
        (so an EXTERNAL function row of that name adds nothing to search output)."""
        if self.db.execute(
            "SELECT 1 FROM function WHERE binary_id=? AND is_external=0 AND name=? LIMIT 1",
            (binary_id, name),
        ).fetchone():
            return True
        return self.db.execute(
            "SELECT 1 FROM import WHERE binary_id=? AND name=? LIMIT 1", (binary_id, name),
        ).fetchone() is not None

    def has_import_named(self, binary_id: int, name: str) -> bool:
        """True when an import row has exactly ``name`` (case-sensitive); a string with
        that value is the import name table entry."""
        return self.db.execute(
            "SELECT 1 FROM import WHERE binary_id=? AND name=? LIMIT 1", (binary_id, name),
        ).fetchone() is not None

    def string_copies(self, binary_id: int, value: str) -> int:
        """Number of string rows with exactly this value."""
        return self.db.execute(
            "SELECT COUNT(*) FROM string WHERE binary_id=? AND value=?", (binary_id, value),
        ).fetchone()[0]

    # -- functions ---------------------------------------------------------

    def get_function(self, function_id: int) -> Function | None:
        r = self.db.execute(
            f"SELECT {_FN_SELECT} FROM function f WHERE f.id=?", (function_id,)
        ).fetchone()
        return _function(r) if r else None

    def function_at(self, binary_id: int, entry: int, space: str = "ram") -> Function | None:
        r = self.db.execute(
            f"SELECT {_FN_SELECT} FROM function f WHERE binary_id=? AND space=? AND entry=?",
            (binary_id, space, entry),
        ).fetchone()
        return _function(r) if r else None

    def function_containing(
        self, binary_id: int, addr: int, space: str = "ram"
    ) -> Function | None:
        """Function with entry <= addr < entry+size (size NULL/0 counts as 1)."""
        r = self.db.execute(
            f"SELECT {_FN_SELECT} FROM function f WHERE binary_id=? AND space=? AND entry<=? "
            "ORDER BY entry DESC LIMIT 1",
            (binary_id, space, addr),
        ).fetchone()
        if not r:
            return None
        fn = _function(r)
        return fn if addr < fn.entry + max(fn.size or 0, 1) else None

    def functions_by_name(self, binary_id: int, name: str) -> list[Function]:
        """Exact match on ``name`` or ``namespace::name``, ordered by address."""
        rows = self.db.execute(
            f"SELECT {_FN_SELECT} FROM function f WHERE binary_id=? AND "
            "(name=? OR (namespace IS NOT NULL AND namespace<>'' AND namespace || '::' || name=?)) "
            "ORDER BY space, entry",
            (binary_id, name, name),
        ).fetchall()
        return [_function(r) for r in rows]

    def list_functions(
        self, binary_id: int, name_state: str | None = None, limit: int = 100, offset: int = 0
    ) -> list[Function]:
        sql = f"SELECT {_FN_SELECT} FROM function f WHERE binary_id=?"
        args: list[Any] = [binary_id]
        if name_state:
            sql += " AND name_state=?"
            args.append(name_state)
        sql += " ORDER BY space, entry LIMIT ? OFFSET ?"
        args += [limit, offset]
        return [_function(r) for r in self.db.execute(sql, args)]

    def count_by_name_state(self, binary_id: int) -> dict[str, int]:
        rows = self.db.execute(
            "SELECT name_state, COUNT(*) AS n FROM function WHERE binary_id=? "
            "GROUP BY name_state ORDER BY name_state",
            (binary_id,),
        ).fetchall()
        return {r["name_state"]: r["n"] for r in rows}

    # -- xrefs -------------------------------------------------------------

    def _xrefs(
        self, where: str, args: list[Any], kinds: Sequence[str] | None, limit: int
    ) -> list[Xref]:
        if kinds:
            where += f" AND e.kind IN ({','.join('?' * len(kinds))})"
            args = args + list(kinds)
        sel_s = ", ".join(f"s.{c} AS s_{c}" for c in _FUNCTION_COLS)
        sel_d = ", ".join(f"d.{c} AS d_{c}" for c in _FUNCTION_COLS)
        rows = self.db.execute(
            f"SELECT e.src_addr, e.dst_addr, e.kind, {sel_s}, {sel_d} FROM edge e "
            "LEFT JOIN function s ON s.id=e.src_fn LEFT JOIN function d ON d.id=e.dst_fn "
            f"WHERE {where} ORDER BY e.src_addr, e.dst_addr, e.kind LIMIT ?",
            [*args, limit],
        ).fetchall()
        return [
            Xref(
                r["src_addr"], r["dst_addr"], r["kind"],
                _function(r, "s_") if r["s_id"] is not None else None,
                _function(r, "d_") if r["d_id"] is not None else None,
            )
            for r in rows
        ]

    def xrefs_to_address(
        self, binary_id: int, addr: int, kinds: Sequence[str] | None = None, limit: int = 200
    ) -> list[Xref]:
        return self._xrefs("e.binary_id=? AND e.dst_addr=?", [binary_id, addr], kinds, limit)

    def xrefs_from_address(
        self, binary_id: int, addr: int, kinds: Sequence[str] | None = None, limit: int = 200
    ) -> list[Xref]:
        return self._xrefs("e.binary_id=? AND e.src_addr=?", [binary_id, addr], kinds, limit)

    def xrefs_to_function(
        self, fn: Function, kinds: Sequence[str] | None = None, limit: int = 200
    ) -> list[Xref]:
        """Edges whose destination is the function's entry (or lies in its body)."""
        return self._xrefs(
            "e.binary_id=? AND e.dst_addr>=? AND e.dst_addr<?",
            [fn.binary_id, fn.entry, fn.entry + max(fn.size or 0, 1)], kinds, limit,
        )

    def xrefs_from_function(
        self, fn: Function, kinds: Sequence[str] | None = None, limit: int = 200
    ) -> list[Xref]:
        return self._xrefs("e.binary_id=? AND e.src_fn=?", [fn.binary_id, fn.id], kinds, limit)

    def callers(self, fn: Function, limit: int = 200) -> list[Function]:
        """Distinct other functions with a call/call_ind/jump edge to fn's entry."""
        rows = self.db.execute(
            f"SELECT DISTINCT {_FN_SELECT} FROM edge e JOIN function f ON f.id=e.src_fn "
            "WHERE e.binary_id=? AND e.dst_addr=? AND e.kind IN ('call','call_ind','jump') "
            "AND f.id<>? ORDER BY f.entry LIMIT ?",
            (fn.binary_id, fn.entry, fn.id, limit),
        ).fetchall()
        return [_function(r) for r in rows]

    def callees(self, fn: Function, limit: int = 200) -> list[Function]:
        """Distinct other functions entered by a call/call_ind/jump edge from fn."""
        rows = self.db.execute(
            f"SELECT DISTINCT {_FN_SELECT} FROM edge e JOIN function f ON f.id=e.dst_fn "
            "WHERE e.src_fn=? AND e.kind IN ('call','call_ind','jump') "
            "AND f.entry=e.dst_addr AND f.id<>? ORDER BY f.entry LIMIT ?",
            (fn.id, fn.id, limit),
        ).fetchall()
        return [_function(r) for r in rows]

    # -- strings / imports -------------------------------------------------

    def search_strings(
        self, binary_id: int, pattern: str, regex: bool = False, limit: int = 50,
        with_refs: bool = True,
    ) -> list[StringHit]:
        """Case-insensitive substring or regex search over defined strings,
        each with the functions holding a read/write/data edge to its address."""
        if regex:
            rx = re.compile(pattern, re.IGNORECASE)
            hits: list[sqlite3.Row] = []
            for r in self.db.execute(
                "SELECT id, address, encoding, value FROM string WHERE binary_id=? "
                "ORDER BY address", (binary_id,)
            ):
                if rx.search(r["value"]):
                    hits.append(r)
                    if len(hits) >= limit:
                        break
        else:
            hits = self.db.execute(
                "SELECT id, address, encoding, value FROM string WHERE binary_id=? "
                "AND value LIKE ? ESCAPE '\\' ORDER BY address LIMIT ?",
                (binary_id, f"%{pattern.translate(_LIKE_ESC)}%", limit),
            ).fetchall()
        out = []
        for r in hits:
            refs: tuple[Function, ...] = ()
            if with_refs:
                rr = self.db.execute(
                    f"SELECT DISTINCT {_FN_SELECT} FROM edge e JOIN function f ON f.id=e.src_fn "
                    "WHERE e.binary_id=? AND e.dst_addr=? AND e.kind IN ('read','write','data') "
                    "ORDER BY f.entry",
                    (binary_id, r["address"]),
                ).fetchall()
                refs = tuple(_function(x) for x in rr)
            out.append(StringHit(r["id"], r["address"], r["encoding"], r["value"], refs))
        return out

    def get_string(self, string_id: int) -> StringHit | None:
        r = self.db.execute(
            "SELECT id, address, encoding, value FROM string WHERE id=?", (string_id,)
        ).fetchone()
        return StringHit(r["id"], r["address"], r["encoding"], r["value"]) if r else None

    def list_imports(
        self, binary_id: int, dll: str | None = None, limit: int = 200
    ) -> list[sqlite3.Row]:
        sql = "SELECT dll, name, ordinal, address, resolved FROM import WHERE binary_id=?"
        args: list[Any] = [binary_id]
        if dll:
            sql += " AND lower(dll)=lower(?)"
            args.append(dll)
        sql += " ORDER BY dll, name LIMIT ?"
        args.append(limit)
        return self.db.execute(sql, args).fetchall()

    # -- cross-binary links --------------------------------------------------

    def exports_of(self, binary_id: int) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT name, ordinal, address FROM export WHERE binary_id=? ORDER BY address",
            (binary_id,)).fetchall()

    def _link_pair(self, src_id: int, dst_id: int) -> int:
        """Rebuild the edges from src's imports of dst's DLL name to dst's exports; returns
        the number of imports bound. An import is matched by name, else by ordinal. Edges start
        at the import slot and at each thunk function named like the import."""
        dst = self.get_binary_by_id(dst_id)
        with self.db:
            self.db.execute("DELETE FROM xedge WHERE src_binary=? AND dst_binary=? "
                            "AND kind='import'", (src_id, dst_id))
            self.db.execute("UPDATE import SET resolved=NULL WHERE binary_id=? AND lower(dll)=? "
                            "AND resolved IS NOT NULL", (src_id, dst.name.lower() if dst else ""))
            if dst is None or src_id == dst_id:
                return 0
            imps = self.db.execute(
                "SELECT rowid AS rid, dll, name, ordinal, address FROM import "
                "WHERE binary_id=? AND lower(dll)=?", (src_id, dst.name.lower())).fetchall()
            if not imps:
                return 0
            by_name: dict[str, int] = {}
            by_ord: dict[int, int] = {}
            ord_name: dict[int, str] = {}
            for e in self.exports_of(dst_id):
                named = bool(e["name"]) and not e["name"].startswith("Ordinal_")
                if named:
                    by_name.setdefault(e["name"], e["address"])
                if e["ordinal"] is not None:
                    by_ord.setdefault(e["ordinal"], e["address"])
                    if named:
                        ord_name.setdefault(e["ordinal"], e["name"])
            rows: list[tuple[int, int, int, int, str]] = []
            bound = 0
            for i in imps:
                addr = by_name.get(i["name"]) if i["name"] else None
                if addr is None and i["ordinal"] is not None:
                    addr = by_ord.get(i["ordinal"])
                    nm = ord_name.get(i["ordinal"])
                    if addr is not None and nm:
                        self.db.execute("UPDATE import SET resolved=? WHERE rowid=?",
                                        (f"{i['dll']}!{nm} (ordinal {i['ordinal']})", i["rid"]))
                if addr is None:
                    continue
                fn = self.function_containing(dst_id, addr)
                entry = fn.entry if fn is not None else addr
                bound += 1
                if i["address"] is not None:
                    rows.append((src_id, i["address"], dst_id, entry, "import"))
                for t in self.db.execute(
                    "SELECT entry FROM function WHERE binary_id=? AND space='ram' AND is_thunk=1 "
                    "AND is_external=0 AND name=?", (src_id, i["name"])).fetchall():
                    rows.append((src_id, t["entry"], dst_id, entry, "import"))
            self.db.executemany(
                "INSERT INTO xedge(src_binary, src_addr, dst_binary, dst_entry, kind) "
                "VALUES (?,?,?,?,?)", rows)
            return bound

    def link_cross_binary(self, binary_id: int, others: Iterable[int]) -> int:
        """(Re)build cross-binary edges between ``binary_id`` and each binary in ``others``, in
        both directions (``binary_id`` importing from them and them importing from it). Returns
        the number of imports bound. Call after ``binary_id`` has been extracted."""
        n = 0
        for o in others:
            if o == binary_id:
                continue
            n += self._link_pair(binary_id, o) + self._link_pair(o, binary_id)
        return n

    @staticmethod
    def import_label(imp: sqlite3.Row) -> str:
        """``dll!Name``; an ordinal import whose exporter is in the project reads
        ``dll!ExportName (ordinal N)``."""
        try:
            if imp["resolved"]:
                return str(imp["resolved"])
        except (IndexError, KeyError):
            pass
        return f"{imp['dll']}!{imp['name'] or '#' + str(imp['ordinal'])}"

    def _crossrefs(self, where: str, args: list[Any], limit: int) -> list[CrossRef]:
        rows = self.db.execute(
            "SELECT src_binary, src_addr, dst_binary, dst_entry, kind FROM xedge "
            f"WHERE {where} ORDER BY src_binary, src_addr, dst_entry LIMIT ?", [*args, limit],
        ).fetchall()
        return [CrossRef(r["src_binary"], r["src_addr"], r["dst_binary"], r["dst_entry"], r["kind"],
                         self.function_containing(r["src_binary"], r["src_addr"]),
                         self.function_at(r["dst_binary"], r["dst_entry"])) for r in rows]

    def cross_to_function(self, fn: Function, limit: int = 200) -> list[CrossRef]:
        """Import slots/thunks of other binaries bound to this function (an exported one)."""
        return self._crossrefs("dst_binary=? AND dst_entry=? AND kind<>'dynlib'", [fn.binary_id, fn.entry], limit)

    def cross_from_address(self, binary_id: int, addr: int, limit: int = 20) -> list[CrossRef]:
        """The exporting function(s) an import slot or thunk address of this binary resolves to."""
        return self._crossrefs("src_binary=? AND src_addr=? AND kind<>'dynlib'", [binary_id, addr], limit)

    def cross_from_binary(self, binary_id: int, limit: int = 1000) -> list[CrossRef]:
        return self._crossrefs("src_binary=?", [binary_id], limit)

    def cross_from_function(self, fn: Function, limit: int = 200) -> list[CrossRef]:
        """Cross-binary links reached from ``fn``: its own entry (a thunk) or an import slot
        it has an edge to."""
        return self._crossrefs(
            "src_binary=? AND kind<>'dynlib' AND (src_addr=? OR src_addr IN (SELECT dst_addr FROM edge WHERE src_fn=? AND dst_fn IS NULL))",
            [fn.binary_id, fn.entry, fn.id], limit)

    def cross_counts(self, binary_id: int) -> tuple[int, int]:
        """(edges from this binary into others, edges from other binaries into it)."""
        a = self.db.execute("SELECT COUNT(*) FROM xedge WHERE src_binary=?", (binary_id,)).fetchone()[0]
        b = self.db.execute("SELECT COUNT(*) FROM xedge WHERE dst_binary=?", (binary_id,)).fetchone()[0]
        return int(a), int(b)

    # -- decomp cache ------------------------------------------------------

    def get_decomp(self, fn: Function, analysis_profile: str) -> Decomp | None:
        """Cached decompilation, only if fn_version and analysis_profile match."""
        r = self.db.execute(
            "SELECT * FROM decomp WHERE function_id=? AND fn_version=? AND analysis_profile=?",
            (fn.id, fn.version, analysis_profile),
        ).fetchone()
        if not r:
            return None
        return Decomp(r["function_id"], r["fn_version"], r["analysis_profile"], r["c_text"],
                      r["status"], r["error"], r["produced_at"])

    def decomp_candidates(self, binary_id: int, analysis_profile: str) -> list[sqlite3.Row]:
        """Functions the background pass should decompile: not thunk, not external, in ram,
        with no cached row for the current fn_version and analysis_profile. Columns: id,
        entry, version, callers (call and indirect-call edges into the function)."""
        return self.db.execute(
            "SELECT f.id, f.entry, f.version, "
            "(SELECT COUNT(*) FROM edge e WHERE e.dst_fn=f.id AND e.kind IN ('call','call_ind')) "
            "AS callers FROM function f WHERE f.binary_id=? AND f.is_thunk=0 AND f.is_external=0 "
            "AND f.space='ram' AND NOT EXISTS (SELECT 1 FROM decomp d WHERE d.function_id=f.id "
            "AND d.fn_version=f.version AND d.analysis_profile=?)",
            (binary_id, analysis_profile)).fetchall()

    def decomp_target_count(self, binary_id: int) -> int:
        """Functions the background pass covers (see decomp_candidates)."""
        return int(self.db.execute(
            "SELECT COUNT(*) FROM function WHERE binary_id=? AND is_thunk=0 AND is_external=0 "
            "AND space='ram'", (binary_id,)).fetchone()[0])

    def decomp_current_count(self, binary_id: int, analysis_profile: str) -> int:
        """Covered functions that have a cached row valid for fn_version and the profile."""
        return int(self.db.execute(
            "SELECT COUNT(*) FROM function f JOIN decomp d ON d.function_id=f.id "
            "WHERE f.binary_id=? AND f.is_thunk=0 AND f.is_external=0 AND f.space='ram' "
            "AND d.fn_version=f.version AND d.analysis_profile=?",
            (binary_id, analysis_profile)).fetchone()[0])

    def save_decomp_batch(self, analysis_profile: str, items: Iterable[dict[str, Any]],
                          produced_at: str | None = None) -> int:
        """Write many decompile results in one transaction. Items: function_id, fn_version,
        status, c_text, error, ast (list of dicts as insert_ast_nodes takes). A result whose
        function version changed meanwhile (a rename) is skipped. Returns rows written."""
        n = 0
        with self.db:
            for it in items:
                row = self.db.execute("SELECT version FROM function WHERE id=?",
                                      (it["function_id"],)).fetchone()
                if row is None or row[0] != it["fn_version"]:
                    continue
                fid = it["function_id"]
                self.db.execute(
                    "INSERT INTO decomp(function_id, fn_version, analysis_profile, c_text, "
                    "status, error, produced_at) VALUES (?,?,?,?,?,?,?) "
                    "ON CONFLICT(function_id) DO UPDATE SET fn_version=excluded.fn_version, "
                    "analysis_profile=excluded.analysis_profile, c_text=excluded.c_text, "
                    "status=excluded.status, error=excluded.error, "
                    "produced_at=excluded.produced_at",
                    (fid, it["fn_version"], analysis_profile, it.get("c_text"), it["status"],
                     it.get("error"), produced_at))
                self.db.execute("DELETE FROM ast_node WHERE function_id=?", (fid,))
                ast = it.get("ast") or []
                if ast:
                    self.db.executemany(
                        "INSERT INTO ast_node(function_id, kind, start_off, end_off, address, "
                        "target, text) VALUES (?,?,?,?,?,?,?)",
                        [(fid, r["kind"], r["start_off"], r["end_off"], r.get("address"),
                          r.get("target"), r.get("text")) for r in ast])
                n += 1
        return n

    def feature_entry_function_ids(self, binary_id: int) -> set[int]:
        """Function ids that are feature entry points. Empty when the feature index does not
        exist (an older index) or cannot be read."""
        try:
            return {int(r[0]) for r in self.db.execute(
                "SELECT DISTINCT f.id FROM feature_entry fe JOIN function f "
                "ON f.binary_id=fe.binary_id AND f.space=fe.space AND f.entry=fe.entry "
                "WHERE fe.binary_id=?", (binary_id,))}
        except sqlite3.Error:
            return set()

    def get_ast_nodes(self, function_id: int, kind: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM ast_node WHERE function_id=?"
        args: list[Any] = [function_id]
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        return self.db.execute(sql + " ORDER BY start_off", args).fetchall()

    # -- lookups for tools -------------------------------------------------

    def string_at(self, binary_id: int, addr: int) -> StringHit | None:
        r = self.db.execute(
            "SELECT id, address, encoding, value FROM string WHERE binary_id=? AND address=? "
            "LIMIT 1", (binary_id, addr)).fetchone()
        return StringHit(r["id"], r["address"], r["encoding"], r["value"]) if r else None

    def get_import(self, rowid: int) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT dll, name, ordinal, address FROM import WHERE rowid=?", (rowid,)
        ).fetchone()

    def imports_by_name(self, binary_id: int, name: str) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT dll, name, ordinal, address, resolved FROM import WHERE binary_id=? AND name=?",
            (binary_id, name)).fetchall()

    def import_at(self, binary_id: int, addr: int) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT dll, name, ordinal, address, resolved FROM import WHERE binary_id=? AND address=? "
            "LIMIT 1", (binary_id, addr)).fetchone()

    def counts(self, binary_id: int) -> dict[str, int]:
        """Row counts for index_status/outline, including stale cached decompiles."""
        def q(sql: str) -> int:
            return int(self.db.execute(sql, (binary_id,)).fetchone()[0])
        return {
            "functions": q("SELECT COUNT(*) FROM function WHERE binary_id=?"),
            "thunks": q("SELECT COUNT(*) FROM function WHERE binary_id=? AND is_thunk=1"),
            "externals": q("SELECT COUNT(*) FROM function WHERE binary_id=? AND is_external=1"),
            "strings": q("SELECT COUNT(*) FROM string WHERE binary_id=?"),
            "imports": q("SELECT COUNT(*) FROM import WHERE binary_id=?"),
            "edges": q("SELECT COUNT(*) FROM edge WHERE binary_id=?"),
            "decompiled": q(
                "SELECT COUNT(*) FROM decomp d JOIN function f ON f.id=d.function_id "
                "WHERE f.binary_id=?"),
            "timeouts": q(
                "SELECT COUNT(*) FROM decomp d JOIN function f ON f.id=d.function_id "
                "WHERE f.binary_id=? AND d.status='timeout' AND d.fn_version=f.version"),
            "decomp_stale": q(
                "SELECT COUNT(*) FROM decomp d JOIN function f ON f.id=d.function_id "
                "JOIN binary b ON b.id=f.binary_id WHERE f.binary_id=? AND "
                "(d.fn_version<>f.version OR d.analysis_profile IS NOT b.analysis_profile)"),
        }

    def import_dll_counts(self, binary_id: int) -> list[tuple[str, int]]:
        rows = self.db.execute(
            "SELECT COALESCE(dll,'?') AS d, COUNT(*) AS n FROM import WHERE binary_id=? "
            "GROUP BY d ORDER BY n DESC, d", (binary_id,)).fetchall()
        return [(r["d"], r["n"]) for r in rows]

    # -- feature index -------------------------------------------------------

    def replace_auto_features(
        self, features: Iterable[tuple[str, str, str]],
        entries: Iterable[tuple[str, int, str, int, str, str, int]], now: str,
    ) -> None:
        """Rebuild the derived part of the feature index. ``features``: (key, title, evidence);
        ``entries``: (key, binary_id, space, entry, reason, evidence, depth). Rows with source
        'agent' (features and entries) are kept; an auto entry never replaces an agent one."""
        with self.db:
            q = self.db.execute
            q("DELETE FROM feature_entry WHERE source='auto'")
            q("DELETE FROM feature WHERE source='auto'")
            self.db.executemany(
                "INSERT INTO feature(key, title, source, evidence, updated) VALUES (?,?, 'auto', ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET evidence=excluded.evidence",
                [(k, t, ev, now) for k, t, ev in features])
            self.db.executemany(
                "INSERT OR IGNORE INTO feature_entry(feature_key, binary_id, space, entry, reason, "
                "evidence, depth, source) VALUES (?,?,?,?,?,?,?, 'auto')", list(entries))

    def define_feature(self, key: str, title: str, topics: str, now: str) -> None:
        """Create or refine a feature as agent-owned (it then survives re-derivation)."""
        with self.db:
            self.db.execute(
                "INSERT INTO feature(key, title, source, topics, updated) VALUES (?,?, 'agent', ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET title=excluded.title, source='agent', "
                "topics=excluded.topics, updated=excluded.updated", (key, title, topics, now))

    def add_feature_entries(self, key: str, binary_id: int, rows: Iterable[tuple[str, int, str]]) -> None:
        """Agent entry points: (space, entry, reason). Replaces an auto row for the same function."""
        with self.db:
            self.db.executemany(
                "INSERT INTO feature_entry(feature_key, binary_id, space, entry, reason, evidence, "
                "depth, source) VALUES (?,?,?,?,?, '', 0, 'agent') "
                "ON CONFLICT(feature_key, binary_id, space, entry) DO UPDATE SET "
                "reason=excluded.reason, source='agent'",
                [(key, binary_id, sp, e, r) for sp, e, r in rows])

    def get_feature(self, key: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT key, title, source, topics, evidence FROM feature WHERE key=?",
                               (key,)).fetchone()

    def feature_stats(self) -> list[sqlite3.Row]:
        """Per feature: key, title, source, topics, n (entry points), named (name_state not auto)."""
        return self.db.execute(
            "SELECT f.key, f.title, f.source, f.topics, COUNT(e.entry) AS n, "
            "COALESCE(SUM(CASE WHEN fn.name_state IS NOT NULL AND fn.name_state<>'auto' "
            "THEN 1 ELSE 0 END), 0) AS named FROM feature f "
            "LEFT JOIN feature_entry e ON e.feature_key=f.key "
            "LEFT JOIN function fn ON fn.binary_id=e.binary_id AND fn.space=e.space AND fn.entry=e.entry "
            "GROUP BY f.key ORDER BY f.key").fetchall()

    def feature_entries(self, key: str) -> list[sqlite3.Row]:
        """Entry points with the live function row: binary_id, space, entry, reason, evidence, depth,
        source, name, namespace, name_state; unnamed (auto) ones first, then by binary and address."""
        return self.db.execute(
            "SELECT e.binary_id, e.space, e.entry, e.reason, e.evidence, e.depth, e.source, "
            "fn.name, fn.namespace, fn.name_state FROM feature_entry e "
            "LEFT JOIN function fn ON fn.binary_id=e.binary_id AND fn.space=e.space AND fn.entry=e.entry "
            "WHERE e.feature_key=? ORDER BY (COALESCE(fn.name_state,'auto')<>'auto'), e.depth, "
            "e.binary_id, e.entry", (key,)).fetchall()

    def callers_of_ids(self, binary_id: int) -> dict[int, set[int]]:
        """{callee function id: caller function ids} over call/call_ind/jump edges of a binary
        (self-calls dropped)."""
        out: dict[int, set[int]] = {}
        for r in self.db.execute(
            "SELECT src_fn, dst_fn FROM edge WHERE binary_id=? AND src_fn IS NOT NULL AND "
            "dst_fn IS NOT NULL AND src_fn<>dst_fn AND kind IN ('call','call_ind','jump')",
            (binary_id,)):
            out.setdefault(r["dst_fn"], set()).add(r["src_fn"])
        return out
