"""Functional-similarity search across every function in the graph.

"Which other functions do the same thing as this one?" is the question that lets
understanding spread: name one function, and the near-copies elsewhere (other
call sites of an inlined helper, the same routine in another build, a statically
linked copy of a library function) follow. Matching must survive what recompiling
changes (register allocation, addresses, small edits) and so works on features
that do:

``mn``     the **mnemonic stream** (operands stripped), compared as 4-gram shingles
``expr``   normalised **pseudo-C statements** (variable names erased, constants and
           callee names kept), when the function has been decompiled
``apis``   the set of imported APIs it calls
``consts`` large scalar constants (magic numbers, crypto tables, flags)
``strs``   normalised string literals it references

Specification (shared by the Python fallback below and the Rust engine in
``engine/`` - the two are tested against each other):

* shingle hash  = FNV-1a 64 over ``" ".join(4 consecutive mnemonics)``; a stream
  shorter than 4 is one shingle of the whole stream;
* signature     = 64 MinHash slots, ``slot_i = min over shingles of mix(h ^ seed_i)``,
  ``seed_i = mix(i + 1)``, ``mix`` = splitmix64 finaliser;
* candidates    = pairs sharing any of 16 LSH bands (4 slots each), buckets larger
  than ``BUCKET_CAP`` skipped (boilerplate prologues), plus pairs with identical
  expression-set / API-set (>= 3) / constant-set (>= 2) keys;
* score         = weighted mean of the exact Jaccard of the features both
  functions have (mn .45, expr .25, api .15, const .10, str .05);
* edges kept    = score >= threshold, and in the top-k of at least one endpoint.

A high score means "very probably the same routine"; it is not proof. Edges are
emitted ``INFERRED`` with the score as confidence and the per-feature breakdown
as context.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np

__all__ = ["Params", "find_similar", "make_record", "expr_hashes", "fnv1a64", "engine_path", "WEIGHTS",
           "BUCKET_CAP", "NUM_PERM", "BANDS", "ROWS"]

NUM_PERM = 64
BANDS = 16
ROWS = 4
SHINGLE_K = 4
BUCKET_CAP = 64
WEIGHTS = {"mn": 0.45, "expr": 0.25, "api": 0.15, "const": 0.10, "str": 0.05}
_M64 = (1 << 64) - 1


@dataclass(frozen=True)
class Params:
    threshold: float = 0.72
    top_k: int = 5
    min_instrs: int = 10


# --------------------------------------------------------------------- hashing

def fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & _M64
    return h


def _mix_int(x: int) -> int:
    x = (x + 0x9E3779B97F4A7C15) & _M64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & _M64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & _M64
    return x ^ (x >> 31)


def _mix(x: np.ndarray) -> np.ndarray:
    with np.errstate(over="ignore"):
        x = x + np.uint64(0x9E3779B97F4A7C15)
        x = (x ^ (x >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
        x = (x ^ (x >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
        return x ^ (x >> np.uint64(31))


_SEEDS = np.array([_mix_int(i + 1) for i in range(NUM_PERM)], dtype=np.uint64)


def shingle_hashes(mn: str) -> np.ndarray:
    toks = mn.split()
    if not toks:
        return np.empty(0, dtype=np.uint64)
    if len(toks) < SHINGLE_K:
        grams = [" ".join(toks)]
    else:
        grams = [" ".join(toks[i:i + SHINGLE_K]) for i in range(len(toks) - SHINGLE_K + 1)]
    return np.unique(np.array([fnv1a64(g.encode()) for g in set(grams)], dtype=np.uint64))


def minhash(sh: np.ndarray) -> np.ndarray:
    if sh.size == 0:
        return np.full(NUM_PERM, np.iinfo(np.uint64).max, dtype=np.uint64)
    return _mix(sh[:, None] ^ _SEEDS[None, :]).min(axis=0)


def band_keys(sig: np.ndarray) -> np.ndarray:
    """(n, 64) signatures -> (n, 16) band keys: acc = mix(acc ^ slot) folded over the band's 4 slots."""
    n = sig.shape[0]
    out = np.empty((n, BANDS), dtype=np.uint64)
    for b in range(BANDS):
        acc = np.full(n, b + 1, dtype=np.uint64)
        for r in range(ROWS):
            acc = _mix(acc ^ sig[:, b * ROWS + r])
        out[:, b] = acc
    return out


# ------------------------------------------------------------------ expressions

_VAR = re.compile(r"^(?:param_\d+|local_\w+|[a-z]{1,3}Var\d+|[a-z]+Stack\w+|[a-z]Stack_\w+|in_\w+|unaff_\w+|extraout_\w+|[a-z]{2}Stack\w+)$")
_CAST = re.compile(r"\((?:undefined\d*|u?int\d*|u?long(?:long)?|u?short|u?char|byte|bool|code|float|double|[A-Za-z_]\w*\s*\*+)\)")
_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|0x[0-9a-fA-F]+|\d+|[A-Za-z_]\w*|==|!=|<=|>=|&&|\|\||<<|>>|->|[-+*/%&|^~!<>=?:.,;(){}\[\]]')


def expr_hashes(pseudo_c: str | None) -> list[int]:
    """Normalised statement hashes of decompiled code (the "expressions" feature)."""
    if not pseudo_c:
        return []
    out: set[int] = set()
    for raw in pseudo_c.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line or line.startswith(("/*", "//", "*", "}")) or line in ("{", "}"):
            continue
        line = _CAST.sub("", line)
        toks: list[str] = []
        for t in _TOKEN.findall(line):
            if t[0] == '"':
                toks.append('"s"')
            elif t.startswith("0x") or t.isdigit():
                try:
                    v = int(t, 0)
                except ValueError:
                    v = 0
                toks.append(t.lower() if v >= 0x100 else "n")
            elif t[0].isalpha() or t[0] == "_":
                if _VAR.match(t):
                    toks.append("v")
                elif t.startswith(("FUN_", "DAT_", "LAB_", "PTR_", "thunk_FUN_")):
                    toks.append("F")
                else:
                    toks.append(t)
            else:
                toks.append(t)
        if len(toks) >= 3:
            out.add(fnv1a64(" ".join(toks).encode()))
    return sorted(out)


# --------------------------------------------------------------------- records

def make_record(node_id: str, scope: str, *, mnemonics: str, consts: Iterable[str] = (), apis: Iterable[str] = (),
                strings: Iterable[str] = (), instrs: int = 0, blocks: int = 0, pseudo_c: str | None = None) -> dict[str, Any]:
    return {
        "id": node_id, "scope": scope, "mn": mnemonics or "",
        "consts": sorted({str(c).lower() for c in consts})[:48],
        "apis": sorted({str(a) for a in apis})[:64],
        "strs": sorted({re.sub(r"\s+", " ", s.strip().lower())[:64] for s in strings if len(s.strip()) >= 4})[:32],
        "instrs": int(instrs), "blocks": int(blocks), "expr": expr_hashes(pseudo_c),
    }


# ---------------------------------------------------------------------- engine

def engine_path() -> Path | None:
    """Locate the Rust engine: $GG_ENGINE, packaged bin/, a dev build, then PATH."""
    cands: list[Path] = []
    if os.environ.get("GG_ENGINE"):
        cands.append(Path(os.environ["GG_ENGINE"]))
    exe = "gg-engine.exe" if os.name == "nt" else "gg-engine"
    here = Path(__file__).parent
    cands += [here / "bin" / exe, here.parent.parent / "engine" / "target" / "release" / exe]
    for c in cands:
        if c.is_file():
            return c
    found = shutil.which("gg-engine")
    return Path(found) if found else None


def find_similar(records: list[dict[str, Any]], *, params: Params = Params(), query_scope: str | None = None,
                 engine: str = "auto", threads: int | None = None) -> list[dict[str, Any]]:
    """Similar-function pairs among ``records``.

    ``query_scope`` restricts output to pairs involving that scope (incremental
    ingest of one new binary against everything already indexed).
    ``engine``: ``"rust"`` / ``"python"`` / ``"auto"`` (Rust when the binary exists).
    """
    if len(records) < 2:
        return []
    use_rust = engine == "rust" or (engine == "auto" and engine_path() is not None)
    if use_rust:
        path = engine_path()
        if path is None:
            raise RuntimeError("Rust engine requested but not built; run `graphify-ghidra build-engine`")
        return _rust(records, params, query_scope, path, threads)
    return _python(records, params, query_scope)


def _rust(records, params: Params, query_scope, path: Path, threads) -> list[dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="gg-engine-") as tmp:
        src, dst = Path(tmp) / "records.jsonl", Path(tmp) / "edges.json"
        with src.open("w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")
        cmd = [str(path), "similar", "--in", str(src), "--out", str(dst), "--threshold", str(params.threshold),
               "--top-k", str(params.top_k), "--min-instrs", str(params.min_instrs)]
        if query_scope:
            cmd += ["--query-scope", query_scope]
        if threads:
            cmd += ["--threads", str(threads)]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if proc.returncode != 0 or not dst.is_file():
            raise RuntimeError(f"gg-engine failed ({proc.returncode}): {proc.stderr[-400:]}")
        return json.loads(dst.read_text(encoding="utf-8"))


def _jaccard(a: set | frozenset, b: set | frozenset) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / (len(a) + len(b) - inter)


def _python(records: list[dict[str, Any]], params: Params, query_scope: str | None) -> list[dict[str, Any]]:
    n = len(records)
    eligible = [i for i, r in enumerate(records) if r["instrs"] >= params.min_instrs and r["mn"]]
    shingles: dict[int, np.ndarray] = {i: shingle_hashes(records[i]["mn"]) for i in eligible}
    sets = {i: {"api": frozenset(records[i]["apis"]), "const": frozenset(records[i]["consts"]),
                "str": frozenset(records[i]["strs"]), "expr": frozenset(records[i]["expr"])} for i in eligible}
    cand: set[tuple[int, int]] = set()

    if eligible:
        sig = np.stack([minhash(shingles[i]) for i in eligible])
        keys = band_keys(sig)
        for b in range(BANDS):
            buckets: dict[int, list[int]] = {}
            for row, i in enumerate(eligible):
                buckets.setdefault(int(keys[row, b]), []).append(i)
            for members in buckets.values():
                _pairs(members, cand)
    for feat, minsize in (("expr", 1), ("api", 3), ("const", 2)):
        buckets: dict[frozenset, list[int]] = {}
        for i in eligible:
            s = sets[i][feat]
            if len(s) >= minsize:
                buckets.setdefault(s, []).append(i)
        for members in buckets.values():
            _pairs(members, cand)

    scored: list[tuple[int, int, float, dict[str, float | None]]] = []
    for a, b in cand:
        ra, rb = records[a], records[b]
        if query_scope and ra["scope"] != query_scope and rb["scope"] != query_scope:
            continue
        j: dict[str, float | None] = {"mn": None, "expr": None, "api": None, "const": None, "str": None}
        sa, sb = shingles[a], shingles[b]
        if sa.size and sb.size:
            inter = np.intersect1d(sa, sb, assume_unique=True).size
            j["mn"] = inter / (sa.size + sb.size - inter)
        for feat in ("expr", "api", "const", "str"):
            fa, fb = sets[a][feat], sets[b][feat]
            if fa and fb:
                j[feat] = _jaccard(fa, fb)
        num = sum(WEIGHTS[k] * v for k, v in j.items() if v is not None)
        den = sum(WEIGHTS[k] for k, v in j.items() if v is not None)
        if den == 0:
            continue
        score = num / den
        if score >= params.threshold:
            scored.append((a, b, score, j))

    # top-k of at least one endpoint
    per: dict[int, list[tuple[float, int, int]]] = {}
    for a, b, s, _ in scored:
        per.setdefault(a, []).append((s, a, b))
        per.setdefault(b, []).append((s, a, b))
    keep: set[tuple[int, int]] = set()
    for lst in per.values():
        lst.sort(key=lambda t: (-t[0], records[t[1]]["id"], records[t[2]]["id"]))
        keep.update((a, b) for _, a, b in lst[: params.top_k])
    out = []
    for a, b, s, j in sorted(scored, key=lambda t: (-t[2], records[t[0]]["id"], records[t[1]]["id"])):
        if (a, b) in keep:
            ida, idb = records[a]["id"], records[b]["id"]
            lo, hi = (ida, idb) if ida <= idb else (idb, ida)
            out.append({"a": lo, "b": hi, "score": round(s, 4), **{k: (None if v is None else round(v, 4)) for k, v in j.items()}})
    return out


def _pairs(members: list[int], cand: set[tuple[int, int]]) -> None:
    if len(members) < 2 or len(members) > BUCKET_CAP:
        return
    m = sorted(members)
    for x in range(len(m)):
        for y in range(x + 1, len(m)):
            cand.add((m[x], m[y]))


def describe(edge: dict[str, Any]) -> str:
    parts = [f"{k} {edge[k]:.2f}" for k in ("mn", "expr", "api", "const", "str") if edge.get(k) is not None]
    return ", ".join(parts)
