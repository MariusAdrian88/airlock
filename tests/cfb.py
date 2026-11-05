"""Minimal compound file (OLE) writer for tests: version 3, 512-byte sectors, no mini stream.

Streams must be at least 4096 bytes (olefile would look in the mini stream below that).
"""

from __future__ import annotations

import struct

END, FATSECT, FREE, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF
SS = 512


def build_cfb(streams: dict[str, bytes]) -> bytes:
    """``streams`` maps ``dir/sub/name`` (``\\x05`` allowed in names) to data."""
    nodes: list[dict] = [{"name": "Root Entry", "type": 5, "kids": [], "data": b""}]
    index = {(): 0}
    for path in sorted(streams):
        parts = tuple(path.split("/"))
        for i in range(1, len(parts)):
            if parts[:i] not in index:
                nodes.append({"name": parts[i - 1], "type": 1, "kids": [], "data": b""})
                index[parts[:i]] = len(nodes) - 1
                nodes[index[parts[:i - 1]]]["kids"].append(index[parts[:i]])
        data = streams[path]
        assert len(data) >= 4096, "streams must be >= 4096 bytes"
        nodes.append({"name": parts[-1], "type": 2, "kids": [], "data": data})
        index[parts] = len(nodes) - 1
        nodes[index[parts[:-1]]]["kids"].append(len(nodes) - 1)

    dir_sectors = -(-len(nodes) * 128 // SS)
    data_sectors = [-(-len(n["data"]) // SS) for n in nodes]
    body = dir_sectors + sum(data_sectors)
    n_fat = 1
    while n_fat * 128 < body + n_fat:
        n_fat += 1
    assert n_fat <= 109
    fat = [FREE] * (n_fat * 128)
    for i in range(n_fat):
        fat[i] = FATSECT
    dir_start = n_fat
    for i in range(dir_sectors):
        fat[dir_start + i] = dir_start + i + 1 if i + 1 < dir_sectors else END
    nxt = dir_start + dir_sectors
    starts = []
    for cnt in data_sectors:
        if not cnt:
            starts.append(END)
            continue
        starts.append(nxt)
        for i in range(cnt):
            fat[nxt + i] = nxt + i + 1 if i + 1 < cnt else END
        nxt += cnt

    left = [NOSTREAM] * len(nodes)
    right = [NOSTREAM] * len(nodes)
    child = [NOSTREAM] * len(nodes)
    for i, n in enumerate(nodes):
        kids = n["kids"]
        if kids:
            child[i] = kids[0]
            for a, b in zip(kids, kids[1:]):
                right[a] = b

    ents = b""
    for i, n in enumerate(nodes):
        name = n["name"].encode("utf-16le")
        ents += (name.ljust(64, b"\0") + struct.pack("<HBB", len(name) + 2, n["type"], 1)
                 + struct.pack("<III", left[i], right[i], child[i]) + b"\0" * 16 + b"\0" * 4
                 + b"\0" * 16 + struct.pack("<I", starts[i]) + struct.pack("<Q", len(n["data"])))
    ents = ents.ljust(dir_sectors * SS, b"\0")

    difat = list(range(n_fat)) + [FREE] * (109 - n_fat)
    hdr = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
           + b"\0" * 6 + struct.pack("<IIIIIIIII", 0, n_fat, dir_start, 0, 4096, END, 0, END, 0)
           + struct.pack("<109I", *difat))
    assert len(hdr) == 512
    out = hdr + struct.pack(f"<{len(fat)}I", *fat) + ents
    for n in nodes:
        out += n["data"].ljust(-(-len(n["data"]) // SS) * SS, b"\0")
    return out
