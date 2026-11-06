import pytest

from airlock.server.budget import (CursorError, CursorStore, estimate_tokens, fit_lines,
                                   fit_text, normalize_args, resume_lines)


def test_estimate():
    assert estimate_tokens("", "code") == 0
    assert estimate_tokens("a" * 7, "code") == 2
    assert estimate_tokens("a" * 8, "prose") == 2
    assert estimate_tokens("a" * 9, "prose") == 3
    with pytest.raises(ValueError):
        estimate_tokens("x", "bogus")


def test_fits_no_cursor():
    st = CursorStore()
    assert fit_lines(["a", "b"], 100, "prose", store=st) == ("a\nb", 0)
    assert len(st) == 0


def test_truncates_with_footer_and_resumes():
    st = CursorStore()
    lines = [f"line {i:03d} " + "x" * 30 for i in range(100)]
    text, rem = fit_lines(lines, 100, "prose", tool="t", args={"q": 1}, store=st)
    out = text.split("\n")
    assert 0 < rem < 100
    assert out[-1].startswith(f"… {rem} more lines. cursor=c_")
    assert len(out) - 1 + rem == 100
    assert estimate_tokens(text, "prose") <= 100
    cid = out[-1].split("cursor=")[1]
    text2, _ = resume_lines(cid, 100, "prose", tool="t", args={"q": 1, "cursor": cid}, store=st)
    assert text2.split("\n")[0] == lines[len(out) - 1]
    with pytest.raises(CursorError):  # consumed
        st.get(cid, "t")


def test_always_progress():
    text, rem = fit_lines(["x" * 1000, "y"], 5, "code", store=CursorStore())
    assert text.startswith("x" * 1000) and rem == 1


def test_errors():
    st = CursorStore()
    with pytest.raises(CursorError) as e:
        st.get("c_dead", "t")
    assert e.value.message.startswith("error bad_cursor: ") and e.value.message.endswith(".")
    cid = st.create_lines("t", {"a": 1}, ["x"])
    with pytest.raises(CursorError):
        st.get(cid, "other")
    # a known cursor wins over different arguments: it keeps its own
    cur = st.get(cid, "t", {"a": 2})
    assert cur.lines == ["x"] and cur.args == {"a": 1}
    assert st.get(cid, "t", {"a": 1, "cursor": cid, "budget": 5}).lines == ["x"]


def test_lru_bound():
    st = CursorStore(max_entries=3)
    ids = [st.create_lines("t", {"i": i}, ["x"]) for i in range(4)]
    assert len(st) == 3
    with pytest.raises(CursorError):
        st.get(ids[0], "t")
    st.get(ids[1], "t")  # touch: ids[2] becomes oldest
    st.create_lines("t", {"i": 9}, ["x"])
    st.get(ids[1], "t")
    with pytest.raises(CursorError):
        st.get(ids[2], "t")


def test_text_cursor_and_stale():
    st = CursorStore()
    src = "\n".join(f"stmt_{i};" for i in range(200))
    ident = ("app.exe", 0x401000, 3)
    text, rem = fit_text(src, 80, "code", tool="function", args={"target": "f"}, identity=ident, store=st)
    shown = text.split("\n")[:-1]
    cid = text.split("\n")[-1].split("cursor=")[1]
    assert rem == 200 - len(shown)
    cur = st.get(cid, "function", {"target": "f", "cursor": cid}, ident)
    assert src[cur.offset:].startswith(f"stmt_{len(shown)};")
    text2, _ = fit_text(src, 80, "code", offset=cur.offset, tool="function",
                        args={"target": "f"}, identity=ident, store=st)
    assert text2.startswith(f"stmt_{len(shown)};")
    with pytest.raises(CursorError) as e:
        st.get(cid, "function", None, ("app.exe", 0x401000, 4))
    assert e.value.code == "stale_cursor"


def test_normalize():
    assert normalize_args("t", {"b": 1, "a": 2, "z": None}) == normalize_args("t", {"a": 2, "b": 1, "cursor": "c"})


def test_cursor_wins_over_other_arguments_and_notes():
    from airlock.server import registry
    st = CursorStore()
    lines = [f"line {i:03d} " + "x" * 30 for i in range(100)]
    text, _ = fit_lines(lines, 100, "prose", tool="t", args={"offset": 0x40, "q": "a"}, store=st)
    cid = text.split("cursor=")[1]
    notes: list[str] = []
    token = registry._NOTES.set(notes)
    try:
        # cursor alone and cursor plus the same arguments: no note
        assert st.get(cid, "t", {"cursor": cid}).args == {"offset": 0x40, "q": "a"}
        st.get(cid, "t", {"offset": 0x40, "q": "a", "cursor": cid})
        assert notes == []
        # different arguments: the cursor's own are kept and one line says so
        text2, _ = resume_lines(cid, 100, "prose", tool="t", args={"offset": 0, "q": "a"}, store=st)
    finally:
        registry._NOTES.reset(token)
    assert notes == ["(cursor kept its arguments: offset=0x40)"]
    cid2 = text2.split("cursor=")[1]
    assert st.get(cid2, "t").args == {"offset": 0x40, "q": "a"}     # the next cursor keeps them too
    with pytest.raises(CursorError):                                  # unknown stays an error
        st.get("c_dead", "t", {"offset": 0})
