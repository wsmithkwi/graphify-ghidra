import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from synth import generate  # noqa: E402

from graphify_ghidra.similarity import (
    Params, engine_path, expr_hashes, find_similar, fnv1a64, make_record, minhash, shingle_hashes,
)

needs_engine = pytest.mark.skipif(engine_path() is None, reason="Rust engine not built (graphify-ghidra build-engine)")


def rec(i, mn, scope="a", **kw):
    toks = mn.split()
    return make_record(f"fn_{i}", scope, mnemonics=mn, instrs=kw.pop("instrs", len(toks)), **kw)


STREAM = "push push sub mov mov lea call test jz mov xor cmp jnz add mov call mov ret lea mov call test jnz mov and cmp jz sub mov ret"


def test_fnv_known_vectors():
    assert fnv1a64(b"") == 0xCBF29CE484222325
    assert fnv1a64(b"a") == 0xAF63DC4C8601EC8C


def test_minhash_estimates_jaccard():
    a = shingle_hashes(STREAM)
    b = shingle_hashes(STREAM.replace("cmp", "test", 2))
    exact = len(set(a.tolist()) & set(b.tolist())) / len(set(a.tolist()) | set(b.tolist()))
    est = float((minhash(a) == minhash(b)).mean())
    assert abs(exact - est) < 0.2


def test_identical_and_mutated_found_unrelated_not():
    recs = [rec(0, STREAM), rec(1, STREAM), rec(2, STREAM.replace("jz", "jnz", 1)),
            rec(3, " ".join(["xor", "ret", "inc", "dec"] * 10))]
    edges = find_similar(recs, engine="python")
    pairs = {(e["a"], e["b"]): e for e in edges}
    assert pairs[("fn_0", "fn_1")]["score"] == 1.0
    assert ("fn_0", "fn_2") in pairs and pairs[("fn_0", "fn_2")]["score"] > 0.72
    assert not any("fn_3" in k for k in pairs)


def test_threshold_topk_and_min_instrs():
    recs = [rec(i, STREAM) for i in range(6)]
    assert len(find_similar(recs, params=Params(top_k=1), engine="python")) <= 6
    assert find_similar(recs, params=Params(threshold=1.01), engine="python") == []
    short = [rec(0, "mov ret", instrs=2), rec(1, "mov ret", instrs=2)]
    assert find_similar(short, engine="python") == []
    assert find_similar(short, params=Params(min_instrs=2), engine="python")


def test_query_scope_limits_to_new_binary():
    recs = [rec(0, STREAM, "old"), rec(1, STREAM, "old"), rec(2, STREAM, "new")]
    pairs = {(e["a"], e["b"]) for e in find_similar(recs, query_scope="new", engine="python")}
    assert pairs == {("fn_0", "fn_2"), ("fn_1", "fn_2")}, "old-old pairs are not recomputed"


def test_other_features_can_bridge_different_compilers():
    # Different instruction streams (another compiler), same expressions + APIs + constants.
    pseudo = "x = CreateFileW(a, 0x80000000, 1, 0, 3, 0x80, 0);\nif (x == -1) {\n return 0;\n}\nReadFile(x, buf, 0x1000, &n, 0);\n"
    a = rec(0, STREAM, apis=["CreateFileW", "ReadFile", "CloseHandle"], consts=["0x80000000", "0x1000"], pseudo_c=pseudo)
    b = rec(1, " ".join(["lea", "mov", "call", "ret"] * 9), apis=["CreateFileW", "ReadFile", "CloseHandle"],
            consts=["0x80000000", "0x1000"], pseudo_c=pseudo.replace("iVar1", "uVar7").replace("param_1", "param_3"))
    # The mnemonic term (0.45 of the weight) is ~0 here, so the composite lands around 0.45:
    # below the default 0.72 ingest threshold (correct: not "the same routine"), but the pair is
    # still surfaced as a candidate at a lower threshold, e.g. for ghidra_similar deep=true.
    assert find_similar([a, b], engine="python") == []
    edge = find_similar([a, b], params=Params(threshold=0.4), engine="python")
    assert edge and edge[0]["api"] == 1.0 and edge[0]["expr"] is not None and edge[0]["mn"] < 0.5


def test_expression_hashes_ignore_variable_names_but_keep_apis_and_constants():
    one = "iVar1 = CreateFileW(param_1, 0x80000000, 0, 0, 3, 0x80, 0);\nif (iVar1 == -1) {\n  FUN_00401000(local_20);\n}\n"
    two = "uVar9 = CreateFileW(param_3, 0x80000000, 0, 0, 3, 0x80, 0);\nif (uVar9 == -1) {\n  FUN_00409999(local_88);\n}\n"
    three = one.replace("CreateFileW", "OpenFile")
    four = one.replace("0x80000000", "0x40000000")
    assert expr_hashes(one) == expr_hashes(two)
    assert expr_hashes(one) != expr_hashes(three)
    assert set(expr_hashes(one)) != set(expr_hashes(four))
    assert expr_hashes("") == [] and expr_hashes(None) == []
    assert expr_hashes("/* only a comment */\n{\n}\n") == []


def test_deterministic_and_boilerplate_buckets_do_not_explode():
    recs = generate(400, seed=3)
    assert find_similar(recs, engine="python") == find_similar(recs, engine="python")
    boiler = [rec(i, "push push sub mov mov " + " ".join(["mov", "add", "xor", "inc"][(i + j) % 4] for j in range(30)))
              for i in range(300)]   # shared prologue: huge candidate buckets must be skipped, not enumerated
    find_similar(boiler, engine="python")


@needs_engine
def test_rust_matches_python_reference():
    recs = generate(900, seed=5)
    py = {(e["a"], e["b"]): e for e in find_similar(recs, engine="python")}
    rs = {(e["a"], e["b"]): e for e in find_similar(recs, engine="rust")}
    assert set(py) == set(rs), "same pairs"
    for k in py:
        assert abs(py[k]["score"] - rs[k]["score"]) <= 1.5e-4
        for f in ("mn", "expr", "api", "const", "str"):
            a, b = py[k][f], rs[k][f]
            assert (a is None) == (b is None) and (a is None or abs(a - b) <= 1.5e-4)


@needs_engine
def test_rust_query_scope_threads_and_errors(tmp_path):
    recs = generate(300, seed=9, scopes=3)
    full = find_similar(recs, engine="rust")
    scoped = find_similar(recs, engine="rust", query_scope="bin0", threads=2)
    assert scoped and all(
        any(r["id"] in (e["a"], e["b"]) and r["scope"] == "bin0" for r in recs) for e in scoped)
    assert len(scoped) <= len(full)
    import subprocess
    p = subprocess.run([str(engine_path()), "similar", "--in", str(tmp_path / "nope"), "--out", str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert p.returncode == 2 and "read" in p.stderr
    p = subprocess.run([str(engine_path()), "bogus"], capture_output=True, text=True)
    assert p.returncode == 2 and "usage" in p.stderr


def test_engine_auto_falls_back_without_binary(monkeypatch):
    monkeypatch.setattr("graphify_ghidra.similarity.engine_path", lambda: None)
    recs = [rec(0, STREAM), rec(1, STREAM)]
    assert find_similar(recs)[0]["score"] == 1.0
    with pytest.raises(RuntimeError, match="build-engine"):
        find_similar(recs, engine="rust")
