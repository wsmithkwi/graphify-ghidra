"""Deterministic synthetic function features with planted near-duplicates.

Used by the Python/Rust parity test and the benchmark. Real binaries are full
of near-copies (inlined helpers, CRT, templates), so the generator plants
clusters: a base routine plus lightly mutated variants, drowned in unrelated
noise functions that share a common vocabulary and prologues (the case that
stresses LSH bucket explosion).
"""

from __future__ import annotations

import random

from graphify_ghidra.similarity import make_record

VOCAB = ("mov push pop lea add sub xor and or cmp test jmp jz jnz call ret shl shr imul idiv inc dec movzx movsx "
         "cmovz cmovnz setz nop leave sar neg not").split()
PROLOGUE = "push push sub mov mov".split()
APIS = [f"Api{i}" for i in range(400)]


def _stream(rng: random.Random, n: int) -> list[str]:
    return PROLOGUE + [rng.choice(VOCAB) for _ in range(n)]


def _mutate(rng: random.Random, toks: list[str], rate: float) -> list[str]:
    out = []
    for t in toks:
        r = rng.random()
        if r < rate / 3:
            continue
        if r < 2 * rate / 3:
            out.append(rng.choice(VOCAB))
        else:
            out.append(t)
        if rng.random() < rate / 3:
            out.append(rng.choice(VOCAB))
    return out


def generate(n: int, *, seed: int = 7, scopes: int = 2, cluster_frac: float = 0.3) -> list[dict]:
    rng = random.Random(seed)
    recs: list[dict] = []
    i = 0
    while i < n:
        scope = f"bin{rng.randrange(scopes)}"
        if rng.random() < cluster_frac and i + 6 < n:
            base = _stream(rng, rng.randint(20, 150))
            apis = rng.sample(APIS, rng.randint(0, 5))
            consts = [f"0x{rng.randrange(1 << 16, 1 << 32):x}" for _ in range(rng.randint(0, 3))]
            for _ in range(rng.randint(2, 6)):
                toks = _mutate(rng, base, rng.choice([0.0, 0.04, 0.1]))
                recs.append(make_record(f"fn_{i}", f"bin{rng.randrange(scopes)}", mnemonics=" ".join(toks),
                                        consts=consts, apis=apis, instrs=len(toks), blocks=len(toks) // 6))
                i += 1
        else:
            toks = _stream(rng, rng.randint(12, 200))
            recs.append(make_record(f"fn_{i}", scope, mnemonics=" ".join(toks),
                                    apis=rng.sample(APIS, rng.randint(0, 4)), instrs=len(toks), blocks=len(toks) // 6))
            i += 1
    return recs
