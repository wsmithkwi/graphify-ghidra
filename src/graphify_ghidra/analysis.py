"""Reverse-engineering analysis over a :class:`~graphify_ghidra.program.Program`.

This module produces **triage aids**, not conclusions. Each output is labelled
with how it was derived so a reader (or an agent) never mistakes a heuristic
for an observation:

* *observed*  - read directly from Ghidra (fan-in, fan-out, complexity, ...)
* *derived*   - computed exactly from observed facts (reachability, depth)
* *inferred*  - a heuristic over names/APIs/strings (capabilities, roles, score)

The triage score exists to answer "which five functions should I read first?".
It is deliberately transparent: every score carries the reasons that produced
it.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .capabilities import CAPABILITIES
from .program import Program

__all__ = ["FunctionMetrics", "ProgramAnalysis", "analyze"]


@dataclass
class FunctionMetrics:
    address: str
    fan_in: int = 0
    fan_out: int = 0
    depth: int | None = None               # shortest call distance from an entry point
    reachable: bool = False                 # reachable from an entry/export via direct calls
    capabilities: dict[str, list[str]] = field(default_factory=dict)  # cap -> evidence
    roles: list[str] = field(default_factory=list)
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)


@dataclass
class ProgramAnalysis:
    metrics: dict[str, FunctionMetrics]
    summary: dict[str, Any]
    ranked: list[str]                       # function addresses, most interesting first
    capability_members: dict[str, list[str]]  # capability -> function addresses (score order)
    external_library_usage: dict[str, int]  # library -> distinct imported APIs actually called


def analyze(program: Program) -> ProgramAnalysis:
    metrics = {addr: FunctionMetrics(addr) for addr in program.order}
    _degrees(program, metrics)
    _reachability(program, metrics)
    _capabilities(program, metrics)
    _roles(program, metrics)
    _score(program, metrics)

    ranked = sorted(metrics, key=lambda a: (-metrics[a].score, a))
    cap_members: dict[str, list[str]] = {}
    for addr in ranked:
        for cap in metrics[addr].capabilities:
            cap_members.setdefault(cap, []).append(addr)

    return ProgramAnalysis(
        metrics=metrics,
        summary=_summary(program, metrics),
        ranked=ranked,
        capability_members=cap_members,
        external_library_usage=_library_usage(program),
    )


# --------------------------------------------------------------------- steps

def _degrees(program: Program, metrics: dict[str, FunctionMetrics]) -> None:
    for (src, dst) in program.call_edges:
        if src == dst:
            continue  # direct recursion does not make a function "popular"
        metrics[src].fan_out += 1
        metrics[dst].fan_in += 1
    for (src, _key) in program.external_calls:
        metrics[src].fan_out += 1


def _reachability(program: Program, metrics: dict[str, FunctionMetrics]) -> None:
    """BFS over direct call edges from every entry point / export."""
    queue: deque[str] = deque()
    for ep in program.entry_points:
        if ep in metrics:
            metrics[ep].depth = 0
            metrics[ep].reachable = True
            queue.append(ep)
    while queue:
        cur = queue.popleft()
        for nxt in program.callees.get(cur, ()):
            m = metrics[nxt]
            if m.depth is None:
                m.depth = metrics[cur].depth + 1  # type: ignore[operator]
                m.reachable = True
                queue.append(nxt)


def _capabilities(program: Program, metrics: dict[str, FunctionMetrics]) -> None:
    for addr, caps in program.fn_caps.items():
        if addr in metrics:
            metrics[addr].capabilities = {k: sorted(v) for k, v in caps.items()}
    # Propagate nothing: a capability belongs to the function that holds the
    # evidence. Callers get it transitively only in the graph, via `calls`.


def _roles(program: Program, metrics: dict[str, FunctionMetrics]) -> None:
    fan_ins = sorted(m.fan_in for m in metrics.values() if m.fan_in)
    hub_cut = fan_ins[int(len(fan_ins) * 0.95)] if len(fan_ins) >= 20 else None
    entry_set = set(program.entry_points)
    for addr, m in metrics.items():
        fn = program.functions[addr]
        instr = fn.get("instruction_count") or 0
        calls_out = m.fan_out
        if addr in entry_set:
            m.roles.append("entry")
        if fn.get("is_library"):
            m.roles.append("library")
        if fn.get("is_thunk"):
            m.roles.append("thunk")
        elif instr and instr <= 24 and calls_out == 1 and m.fan_in >= 1:
            m.roles.append("wrapper")
        if calls_out == 0 and not fn.get("is_thunk"):
            m.roles.append("leaf")
        if hub_cut is not None and m.fan_in >= max(hub_cut, 5):
            m.roles.append("hub")
        indirect = fn.get("indirect_calls") or 0
        cc = fn.get("cyclomatic_complexity") or 0
        if not fn.get("is_library") and (indirect >= 3 or (cc >= 40 and calls_out >= 15)):
            m.roles.append("dispatcher")
        if m.fan_in == 0 and addr not in entry_set and not fn.get("is_thunk"):
            m.roles.append("unreferenced")  # candidate callback / vtable / exported-by-pointer target


def _score(program: Program, metrics: dict[str, FunctionMetrics]) -> None:
    for addr, m in metrics.items():
        fn = program.functions[addr]
        if fn.get("is_thunk"):
            continue
        score = 0.0
        reasons: list[str] = []

        cap_risk = 0
        for cap in m.capabilities:
            cap_risk += CAPABILITIES[cap].risk if cap in CAPABILITIES else 0
        if cap_risk:
            score += 2.5 * cap_risk
            risky = [c for c in m.capabilities if c in CAPABILITIES and CAPABILITIES[c].risk >= 2]
            if risky:
                reasons.append("touches " + ", ".join(sorted(risky)))
        distinct_caps = len(m.capabilities)
        if distinct_caps >= 3:
            score += distinct_caps
            reasons.append(f"{distinct_caps} distinct capabilities")

        if m.fan_in >= 3:
            score += math.log2(m.fan_in) * 1.5
            reasons.append(f"called from {m.fan_in} functions")
        cc = fn.get("cyclomatic_complexity") or 0
        if cc >= 10:
            score += min(cc, 120) ** 0.5
            reasons.append(f"complexity {cc}")
        if fn.get("is_entry"):
            score += 12
            reasons.append("program entry point")
        if "dispatcher" in m.roles:
            score += 4
            reasons.append("dispatcher-like (many/indirect calls)")
        if fn.get("user_named"):
            score += 10
            reasons.append("named by an analyst")
        if fn.get("comment") or fn.get("repeatable_comment"):
            score += 6
            reasons.append("annotated by an analyst")

        strs = len(program.fn_strings.get(addr, ()))
        if strs >= 3:
            score += min(strs, 20) ** 0.5
            reasons.append(f"{strs} string references")
        if "wrapper" in m.roles:
            score *= 0.4
        if "library" in m.roles:
            # Statically linked runtime/STL code: rarely what a reverse engineer
            # is hunting for. Keep it findable, but push it down the ranking.
            score *= 0.2
            reasons.append("library code (Function ID match)")
        if "unreferenced" in m.roles and m.capabilities:
            score += 3
            reasons.append("unreferenced but capable (indirect/callback target?)")

        m.score = round(score, 2)
        m.reasons = reasons


# ------------------------------------------------------------------- summary

def _library_usage(program: Program) -> dict[str, int]:
    called: dict[str, set[str]] = {}
    for (_src, key) in program.external_calls:
        imp = program.imports[key]
        called.setdefault(imp["lib_norm"], set()).add(imp["name"])
    return {lib: len(names) for lib, names in sorted(called.items(), key=lambda kv: -len(kv[1]))}


def _summary(program: Program, metrics: dict[str, FunctionMetrics]) -> dict[str, Any]:
    fns = [program.functions[a] for a in program.order]
    real = [f for f in fns if not f.get("is_thunk")]
    total = len(fns)
    named = sum(1 for f in fns if f.get("user_named"))
    auto = sum(1 for f in fns if f.get("auto_named"))
    indirect = sum(int(f.get("indirect_calls") or 0) for f in fns)
    call_sites = sum(int(f.get("call_sites") or 0) for f in fns)
    cap_counts: dict[str, int] = {}
    for m in metrics.values():
        for cap in m.capabilities:
            cap_counts[cap] = cap_counts.get(cap, 0) + 1
    reach = sum(1 for m in metrics.values() if m.reachable)
    return {
        "functions": total,
        "non_thunk_functions": len(real),
        "thunks": total - len(real),
        "library_functions": sum(1 for f in fns if f.get("is_library")),
        "analyst_named": named,
        "auto_named": auto,
        "auto_named_ratio": round(auto / total, 3) if total else 0.0,
        "decompiled": sum(1 for f in fns if f.get("pseudo_c")),
        "imports": len(program.imports),
        "strings_total": len(program.strings),
        "call_edges": len(program.call_edges),
        "external_call_edges": len(program.external_calls),
        "call_sites": call_sites,
        "indirect_call_sites": indirect,
        "unresolved_call_sites": len(program.unresolved_calls),
        "entry_points": list(program.entry_points),
        "reachable_from_entry": reach,
        "unreachable_functions": total - reach,
        "capability_function_counts": dict(sorted(cap_counts.items(), key=lambda kv: -kv[1])),
    }
