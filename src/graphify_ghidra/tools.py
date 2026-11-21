"""The agent-facing tool layer: ``ghidra_*`` tools over a Ghidra graph.

Each tool is ``fn(ws: Workspace, args: dict) -> str``. Tool text is written for
language models with small context windows: compact, hard-capped, and ending
with the next useful step. A model working through a large program is nudged
toward the loop that builds understanding::

    worklist -> function/decompile/refs -> name (+behavior/link) -> worklist ...

Every mutating tool (name, link, behavior) writes the annotation store, then
re-applies annotations to ``graph.json`` and reloads, so the graph is always the
single source of truth the next tool reads.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

from .annotations import CONFIDENCES, LINK_KINDS, AnnotationStore, validate_name
from .capabilities import CAPABILITIES, normalize_api_name
from .model import canon_addr
from .workspace import Ambiguous, NoGhidraData, NotFound, Workspace

MAX_TEXT = 7000          # hard ceiling on any tool's text
HARD_LIMIT = 200         # ceiling on any caller-supplied row limit


# =============================================================== small helpers

def _cap(text: str, limit: int = MAX_TEXT) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 80].rstrip() + f"\n... [output capped at {limit} chars; narrow the request or page with offset]"


def _int(v: Any, default: int, lo: int = 0, hi: int = HARD_LIMIT) -> int:
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def _addr(ws: Workspace, nid: str) -> str:
    return str(ws.meta(nid).get("address") or "")


def _label(ws: Workspace, nid: str) -> str:
    return str(ws.nodes[nid].get("label", nid)).split(" @")[0]


def _short(text: Any, n: int = 60) -> str:
    s = re.sub(r"\s+", " ", str(text)).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _is_unnamed_fn(ws: Workspace, nid: str) -> bool:
    m = ws.meta(nid)
    return m.get("ghidra_kind") == "function" and not ws.is_named(nid)


def coverage(ws: Workspace, scope: str) -> dict[str, int]:
    fns = ws.functions(scope)
    c: Counter[str] = Counter()
    for nid in fns:
        m = ws.meta(nid)
        if m.get("ghidra_kind") == "thunk":
            c["thunks"] += 1
            continue
        by = ws.named_by(nid)
        if by is None:
            c["unnamed"] += 1
        else:
            c[by] += 1
    store = ws.stores.get(scope)
    c["examined"] = len(store.data["examined"]) if store else 0
    c["behaviors"] = len(store.data["behaviors"]) if store else 0
    c["total"] = len(fns) - c["thunks"]
    return dict(c)


def nudge(ws: Workspace, scope: str) -> str:
    c = coverage(ws, scope)
    total = max(c.get("total", 0), 1)
    done = total - c.get("unnamed", 0)
    pct = 100 * done / total
    ai = c.get("ai", 0) + c.get("heuristic", 0) + c.get("propagated", 0)
    msg = (f"Coverage: {done}/{total} functions named ({pct:.0f}%; {ai} by you). "
           f"{c.get('unnamed', 0)} still FUN_xxxx.")
    if c.get("unnamed", 0):
        msg += (" Name every function you understand now, even with confidence='low' (an honest guess beats an "
                "address and unlocks its callers); then call ghidra_worklist for the next batch.")
    else:
        msg += " All named. Group related functions with ghidra_behavior, then verify low-confidence names."
    return msg


def _pick(ws: Workspace, a: dict[str, Any]) -> str:
    return ws.pick_scope(a.get("binary"))


def _resolve_any(ws: Workspace, ref: str, binary: str | None) -> str:
    """Function, data, import, string or any node id."""
    if ref in ws.nodes:
        return ref
    if canon_addr(ref) is None and ":0x" not in ref:
        # An exact name beats any loose match: "connect" is the import, not thunk_connect.
        low = ref.lower()
        exact_fn, exact_imp = [], []
        for nid, n in ws.nodes.items():
            m = n.get("metadata") or {}
            k = m.get("ghidra_kind")
            if k not in ("function", "thunk", "import") or (binary and k != "import" and m.get("scope") != ws.pick_scope(binary)):
                continue
            names = {str(n.get("label", "")).split(" @")[0].lower(), str(m.get("original_label", "")).lower()}
            if low in names:
                (exact_imp if k == "import" else exact_fn).append(nid)
        if len(exact_fn) == 1:
            return exact_fn[0]
        if not exact_fn and len(exact_imp) == 1:
            return exact_imp[0]
    try:
        return ws.resolve(ref, binary)
    except NotFound:
        pass          # ambiguity is a real answer and propagates; only "not a function" falls through
    try:
        return ws.resolve(ref, binary, kinds=("data",))
    except NotFound:
        pass
    low = ref.lower()
    imps = [nid for nid, n in ws.nodes.items()
            if (n.get("metadata") or {}).get("ghidra_kind") == "import" and str(n.get("label", "")).lower() == low]
    if len(imps) == 1:
        return imps[0]
    strs = [nid for nid, n in ws.nodes.items()
            if (n.get("metadata") or {}).get("ghidra_kind") == "string" and low in str((n.get("metadata") or {}).get("value", "")).lower()]
    if len(strs) == 1:
        return strs[0]
    if len(strs) > 1:
        raise Ambiguous(ref, [f"{ws.meta(s).get('address')} {_short(ws.meta(s).get('value'), 40)}" for s in strs[:8]])
    raise NotFound(f"cannot find a function, data, import or string matching {ref!r}")


# ------------------------------------------------------------ pseudo-C readability

_AUTO_ID = re.compile(r"\b(?:thunk_)?(?:FUN|DAT|PTR|LAB)_([0-9a-fA-F]+)\b")


def substitute_names(ws: Workspace, scope: str, fn_nid: str | None, text: str) -> str:
    """Rewrite Ghidra's ``FUN_140003bc0`` / ``param_1`` in pseudo-C with the names we know."""
    def repl(m: re.Match) -> str:
        key = "0x" + m.group(1).lstrip("0").lower() or "0x0"
        nid = ws.fn_key.get((scope, key)) or ws.data_key.get((scope, key))
        if nid and ws.meta(nid).get("ai_name"):
            return _label(ws, nid)
        return m.group(0)

    out = _AUTO_ID.sub(repl, text)
    store = ws.stores.get(scope)
    if store and fn_nid:
        addr = _addr(ws, fn_nid)
        for v in store.data["variables"].values():
            if v["function"] == addr:
                out = re.sub(rf"\b{re.escape(v['old'])}\b", v["name"], out)
    return out


# ============================================================== suggestions

def suggestions_for(ws: Workspace, nid: str) -> list[tuple[str, str, str]]:
    """Rule-based name hints: ``(name, confidence, why)``. Hints, not facts."""
    m = ws.meta(nid)
    out: list[tuple[str, str, str]] = []
    callees = [(t, e) for t, e in ws.calls_out.get(nid, []) if (e.get("relation") != "thunks_to")]
    if m.get("ghidra_kind") == "thunk":
        for t, e in ws.calls_out.get(nid, []):
            if e.get("relation") == "thunks_to" and ws.meta(t).get("ghidra_kind") in ("function", "thunk"):
                out.append((f"thunk_{_label(ws, t)}", "high", "thunk to " + ws.display(t)))
        return out
    roles = m.get("roles") or []
    distinct = {t for t, _ in callees}
    instrs = int(m.get("instruction_count") or 0)
    if "wrapper" in roles and len(distinct) == 1:
        t = next(iter(distinct))
        tm = ws.meta(t)
        if tm.get("ghidra_kind") == "import":
            if re.fullmatch(r"[A-Za-z_]\w*", _label(ws, t)):   # skip C++-mangled / odd import names
                out.append((f"{normalize_api_name(_label(ws, t))}_wrapper", "medium", f"thin wrapper around import {_label(ws, t)}"))
        elif ws.is_named(t):
            out.append((f"{_label(ws, t)}_wrapper", "medium", f"thin wrapper around {ws.display(t)}"))
    elif instrs and instrs <= 60 and len(distinct) == 1 and ws.meta(next(iter(distinct))).get("ghidra_kind") == "import":
        api = _label(ws, next(iter(distinct)))
        if re.fullmatch(r"[A-Za-z_]\w*", api):
            out.append((f"do_{normalize_api_name(api)}", "low", f"only call is import {api}"))
    for t, e in ws.sim.get(nid, []):
        if ws.is_named(t) and float(e.get("confidence_score") or 0) >= 0.8:
            out.append((f"{_label(ws, t)}_like", "low", f"similar to named {ws.display(t)} ({e.get('confidence_score')})"))
            break
    return out


# ================================================================== tool: status

def _bootstrap_text(ws: Workspace) -> str:
    from .jobs import job_summary, read_job
    job = job_summary(read_job(ws.out))
    foreign = ''
    if ws.graph_path.is_file():
        foreign = (f'\n(An ordinary graphify graph exists at {ws.graph_path}; it holds no analysed binary and is left '
                   'untouched. Ghidra results go to their own folder.)')
    head = f'No Ghidra analysis is loaded yet (looked in {ws.out}).{foreign}'
    from .jobs import read_job as _rj
    _job = _rj(ws.out)
    if _job and _job.get('state') == 'running':
        # Already on its way: do not also tell the agent to start one.
        return head + '\n' + job + '\nNothing else is available until it finishes; poll ghidra_status (or carry on with other work).'
    steps = ('To make the naming loop (worklist -> name -> propagate -> behaviours) available, analyse a binary:' + '\n'
             '  ghidra_analyze {binary: "<absolute path to the DLL/EXE/ELF>"}' + '\n'
             'It runs in the background (minutes for a real DLL), keeps the Ghidra project for live decompile, and '
             'does not touch any existing graph. Start with ONE binary, ideally the one you are working on now.')
    return head + '\n' + (job + '\n' if job else '') + steps


def tool_status(ws: Workspace, a: dict[str, Any]) -> str:
    if not ws.scopes:
        return _bootstrap_text(ws)
    from .jobs import job_summary, read_job
    lines: list[str] = []
    job = read_job(ws.out)
    if job and job.get("state") in ("running", "failed", "died"):
        lines.append("JOB: " + job_summary(job))
    for scope, info in ws.scopes.items():
        if a.get("binary") and scope != ws.pick_scope(a["binary"]):
            continue
        c = coverage(ws, scope)
        store = ws.stores[scope]
        sc = store.counts()
        lines.append(f"{info['name']}  (scope {scope})")
        lines.append(f"  functions {c.get('total', 0)} (+{c.get('thunks', 0)} thunks): "
                     f"unnamed {c.get('unnamed', 0)}, ai {c.get('ai', 0)}, heuristic {c.get('heuristic', 0)}, "
                     f"propagated {c.get('propagated', 0)}, analyst {c.get('analyst', 0)}, "
                     f"library {c.get('library', 0)}, ghidra {c.get('ghidra', 0)}")
        lines.append(f"  your work: {sc['names']} names, {sc['variables']} variables, {sc['behaviors']} behaviours, "
                     f"{sc['links']} links, {sc['examined']} examined-unclear")
        live = (ws.out / "ghidra" / scope / "project" / "project.json").is_file()
        lines.append(f"  live decompile/disasm/xrefs: {'available' if live else 'NOT available (re-run analyze with project kept)'}")
    sim = sum(len(v) for v in ws.sim.values()) // 2
    lines.append(f"similarity edges: {sim}; binaries in graph: {len(ws.scopes)}")
    first = next(iter(ws.scopes))
    lines.append(nudge(ws, first if not a.get("binary") else ws.pick_scope(a["binary"])))
    return "\n".join(lines)


# =============================================================== tool: worklist

def tool_worklist(ws: Workspace, a: dict[str, Any]) -> str:
    scope = _pick(ws, a)
    limit = _int(a.get("limit"), 6, 1, 20)
    mode = a.get("mode") or "bottom_up"
    store = ws.stores[scope]
    examined = set(store.data["examined"])
    cands = []
    for nid in ws.functions(scope):
        if not _is_unnamed_fn(ws, nid) or _addr(ws, nid) in examined:
            continue
        m = ws.meta(nid)
        if "library" in (m.get("roles") or []):
            continue
        score = float(m.get("triage_score") or 0)
        callees = {t for t, e in ws.calls_out.get(nid, [])}
        known = sum(1 for t in callees if ws.meta(t).get("ghidra_kind") == "import" or ws.is_named(t))
        ready = known / len(callees) if callees else 1.0
        sim_named = any(ws.is_named(t) for t, _ in ws.sim.get(nid, []))
        if mode == "important":
            pri = score
        elif mode == "unreached":
            if m.get("reachable_from_entry"):
                continue
            pri = score + 2 * ready
        elif mode == "capable":
            if not m.get("capabilities"):
                continue
            pri = score + 3 * ready
        else:   # bottom_up: functions whose callees are already understood are the easiest to name
            pri = score + 8 * ready + (5 if sim_named else 0) + (2 if callees else 0)
        cands.append((pri, nid, ready))
    cands.sort(key=lambda t: (-t[0], _addr(ws, t[1])))
    if not cands:
        return "Worklist empty: every function is named or marked examined.\n" + nudge(ws, scope)
    out = [f"Next {min(limit, len(cands))} of {len(cands)} unnamed functions in {ws.scopes[scope]['name']} (mode={mode}):"]
    for i, (_p, nid, ready) in enumerate(cands[:limit], 1):
        m = ws.meta(nid)
        out.append(f"{i}. {_addr(ws, nid)}  {substitute_names(ws, scope, nid, m.get('signature') or _label(ws, nid))}")
        bits = []
        if m.get("roles"):
            bits.append("roles " + "/".join(m["roles"]))
        bits.append(f"{m.get('instruction_count', '?')} instrs, complexity {m.get('cyclomatic_complexity', '?')}")
        if m.get("capabilities"):
            bits.append("caps " + ",".join(m["capabilities"]))
        out.append("   " + "; ".join(bits))
        apis = [_label(ws, t) for t, _ in ws.calls_out.get(nid, []) if ws.meta(t).get("ghidra_kind") == "import"][:6]
        if apis:
            out.append("   apis: " + ", ".join(apis))
        callees = [t for t, e in ws.calls_out.get(nid, []) if ws.meta(t).get("ghidra_kind") in ("function", "thunk")]
        if callees:
            out.append("   calls: " + ", ".join(ws.display(t) for t in callees[:5]) + (f" +{len(callees) - 5}" if len(callees) > 5 else ""))
        callers = [s for s, _ in ws.calls_in.get(nid, [])]
        if callers:
            out.append("   called by: " + ", ".join(ws.display(s) for s in callers[:4]) + (f" +{len(callers) - 4}" if len(callers) > 4 else ""))
        strs = [ws.meta(t).get("value") for t, _ in ws.refs_out.get(nid, []) if ws.meta(t).get("ghidra_kind") == "string"][:3]
        if strs:
            out.append("   strings: " + " | ".join(f'"{_short(s, 40)}"' for s in strs))
        sims = [(t, e) for t, e in ws.sim.get(nid, [])][:2]
        if sims:
            out.append("   similar: " + ", ".join(f"{ws.display(t)} {float(e.get('confidence_score') or 0):.2f}" for t, e in sims))
        hints = suggestions_for(ws, nid)
        if hints:
            out.append("   hint: " + "; ".join(f"{n} [{c}] ({w})" for n, c, w in hints[:2]))
    out.append("Use ghidra_function / ghidra_decompile on these, then ghidra_name them all in ONE call "
               "(add note=... for any you cannot resolve so they leave the list).")
    out.append(nudge(ws, scope))
    return _cap("\n".join(out))


# ============================================================== tool: function

def tool_function(ws: Workspace, a: dict[str, Any]) -> str:
    nid = ws.resolve(a.get("address"), a.get("binary"))
    m, n = ws.meta(nid), ws.nodes[nid]
    scope = m["scope"]
    store = ws.stores[scope]
    by = ws.named_by(nid)
    status = (f"named by {by}" + (f" ({m.get('name_confidence')})" if m.get("ai_name") else "")) if by else "UNNAMED"
    out = [f"{n['label'].split(' @')[0]}  {m.get('address')}  [{status}]  in {ws.scopes[scope]['name']}"]
    if m.get("ai_name") and m.get("original_label"):
        out[0] += f"  (was {m['original_label']})"
    if m.get("signature"):
        out.append("sig: " + _short(substitute_names(ws, scope, nid, m["signature"]), 200))
    out.append(f"size: {m.get('instruction_count', '?')} instrs, {m.get('basic_blocks', '?')} blocks, "
               f"complexity {m.get('cyclomatic_complexity', '?')}; fan-in {m.get('fan_in', 0)}, fan-out {m.get('fan_out', 0)}; "
               + (f"depth {m['depth_from_entry']} from entry" if m.get("reachable_from_entry") else "not reachable from an entry point"))
    if m.get("roles"):
        out.append("roles: " + ", ".join(m["roles"]) + (f"   triage {m.get('triage_score')}: " + "; ".join(m.get("triage_reasons") or [])[:160]))
    if m.get("library_match"):
        out.append("library match: " + _short(m["library_match"], 160))
    caps = [CAPABILITIES[k].label for k in (m.get("capabilities") or []) if k in CAPABILITIES]
    if caps:
        out.append("capabilities (inferred): " + ", ".join(caps))
    if m.get("name_evidence"):
        out.append("name evidence: " + "; ".join(m["name_evidence"][:3]))
    callers = [s for s, _ in ws.calls_in.get(nid, [])]
    callees = [t for t, _ in ws.calls_out.get(nid, [])]
    lim_c = _int(a.get("callers_limit"), 8, 1, 40)
    lim_e = _int(a.get("callees_limit"), 12, 1, 40)
    if callers:
        out.append(f"callers ({len(callers)}): " + ", ".join(ws.display(s) for s in callers[:lim_c]) + (f" +{len(callers) - lim_c}" if len(callers) > lim_c else ""))
    fn_callees = [t for t in callees if ws.meta(t).get("ghidra_kind") in ("function", "thunk")]
    imp_callees = [t for t in callees if ws.meta(t).get("ghidra_kind") == "import"]
    if fn_callees:
        out.append(f"callees ({len(fn_callees)}): " + ", ".join(ws.display(t) for t in fn_callees[:lim_e]) + (f" +{len(fn_callees) - lim_e}" if len(fn_callees) > lim_e else ""))
    if imp_callees:
        out.append(f"imports ({len(imp_callees)}): " + ", ".join(_label(ws, t) for t in imp_callees[:16]))
    strs = [ws.meta(t).get("value") for t, _ in ws.refs_out.get(nid, []) if ws.meta(t).get("ghidra_kind") == "string"]
    if strs:
        out.append(f"strings ({len(strs)}): " + " | ".join(f'"{_short(s, 50)}"' for s in strs[:8]))
    datas = [t for t, _ in ws.refs_out.get(nid, []) if ws.meta(t).get("ghidra_kind") == "data"]
    if datas:
        out.append("globals: " + ", ".join(ws.display(t) for t in datas[:8]))
    types = [t for t, _ in ws.refs_out.get(nid, []) if ws.meta(t).get("ghidra_kind") == "datatype"]
    if types:
        out.append("types: " + ", ".join(_label(ws, t) for t in types[:8]))
    shared = [t for t, _ in ws.shares.get(nid, [])]
    if shared:
        out.append("shares data with: " + ", ".join(ws.display(t) for t in shared[:6]))
    sims = ws.sim.get(nid, [])
    if sims:
        sims = sorted(sims, key=lambda te: -float(te[1].get("confidence_score") or 0))
        out.append("similar code: " + ", ".join(f"{ws.display(t)} {float(e.get('confidence_score') or 0):.2f}" for t, e in sims[:5]))
    beh = [b["label"] for b in store.data["behaviors"].values() if _addr(ws, nid) in b["members"]]
    if beh:
        out.append("behaviours: " + ", ".join(beh))
    ex = store.data["examined"].get(_addr(ws, nid))
    if ex:
        out.append("examined note: " + ex["note"])
    hints = suggestions_for(ws, nid)
    if hints and not ws.is_named(nid):
        out.append("name hints: " + "; ".join(f"{h} [{c}] ({w})" for h, c, w in hints[:3]))
    if a.get("pseudo"):
        side = ws.out / "ghidra" / scope / "pseudo" / (_addr(ws, nid).replace(":", "_") + ".c")
        if side.is_file():
            body = substitute_names(ws, scope, nid, side.read_text(encoding="utf-8"))
            cap = _int(a.get("chars"), 3000, 200, 8000)
            out.append("pseudo-C (cached, names substituted):\n" + body[:cap] + ("\n..." if len(body) > cap else ""))
        else:
            out.append("pseudo-C: not cached; call ghidra_decompile for this address")
    else:
        out.append("(ghidra_decompile gives pseudo-C; ghidra_refs gives call sites)")
    if not ws.is_named(nid):
        out.append("-> ghidra_name this function when you understand it.")
    return _cap("\n".join(out))


# ================================================================== tool: refs

def tool_refs(ws: Workspace, a: dict[str, Any]) -> str:
    """Pull references to/from a function, string, import or global, with a hard cap.

    direction: ``incoming`` = what references this; ``outgoing`` = what this references.
    """
    nid = _resolve_any(ws, str(a.get("target", "")), a.get("binary"))
    limit = _int(a.get("limit"), 40, 1, HARD_LIMIT)
    offset = _int(a.get("offset"), 0, 0, 10_000_000)
    direction = {"in": "incoming", "out": "outgoing", "to": "incoming", "from": "outgoing"}.get(
        str(a.get("direction") or "both"), str(a.get("direction") or "both"))
    if direction not in ("incoming", "outgoing", "both"):
        return "direction must be incoming, outgoing or both"
    kind = a.get("kind") or "all"
    m = ws.meta(nid)
    if a.get("live"):
        return _refs_live(ws, nid, direction, limit, offset)

    rows: list[tuple[str, str, str, str, str]] = []   # (arrow, kind, other, detail, confidence)

    def sites(e: dict) -> str:
        s = e.get("call_site_addresses") or ([e["source_location"]] if e.get("source_location") else [])
        return ("@" + ",".join(str(x) for x in s[:4])) if s else ""

    def add(arrow: str, other: str, e: dict) -> None:
        om = ws.meta(other)
        k = om.get("ghidra_kind", "?")
        rel = e.get("relation")
        if rel in ("calls", "thunks_to"):
            kk = "import" if k == "import" else "call"
        elif rel == "references":
            kk = {"string": "string", "data": "data", "datatype": "type", "variable": "var"}.get(k, "ref")
        elif rel == "shares_data_with":
            kk = "shared"
        else:
            kk = rel or "?"
        if kind != "all" and kind != kk and not (kind == "call" and kk == "import"):
            return
        shown = f'"{_short(om.get("value"), 50)}"' if k == "string" else ws.display(other)
        detail = " ".join(x for x in (sites(e), _short(e.get("context") or "", 50)) if x)
        rows.append((arrow, kk, shown, detail, str(e.get("confidence", ""))[:3]))

    if direction in ("outgoing", "both"):
        for t, e in ws.calls_out.get(nid, []):
            add("->", t, e)
        for t, e in ws.refs_out.get(nid, []):
            add("->", t, e)
        for t, e in ws.shares.get(nid, []):
            add("->", t, e)
    if direction in ("incoming", "both"):
        for s_, e in ws.calls_in.get(nid, []):
            add("<-", s_, e)
        for s_, e in ws.refs_in.get(nid, []):
            add("<-", s_, e)
    rows.sort(key=lambda r: (0 if r[1] in ("call", "import") else 1, r[0] != "<-", r[2]))
    total = len(rows)
    page = rows[offset: offset + limit]
    out = [f"References for {ws.display(nid)} ({m.get('ghidra_kind')}): {total} total, direction={direction}, kind={kind}",
           "legend: '<-' references this node; '->' is referenced by this node"]
    for arrow, k, shown, detail, conf in page:
        out.append(f"  {arrow} {k:<6} {shown}  {detail} [{conf}]".rstrip())
    if offset + limit < total:
        out.append(f"-- showing {offset + 1}-{offset + len(page)} of {total}; next: offset={offset + limit} "
                   f"(cap {limit}; max {HARD_LIMIT})")
    elif not page:
        out.append("  (none in the graph; try live=true for instruction-level references from Ghidra)")
    else:
        out.append(f"-- all {total} shown. live=true adds instruction-level xrefs straight from Ghidra.")
    return _cap("\n".join(out))


def _refs_live(ws: Workspace, nid: str, direction: str, limit: int, offset: int) -> str:
    m = ws.meta(nid)
    scope, addr = m["scope"], m.get("address")
    if not addr:
        return "live references need an address-bearing node (function, data or string)."
    backend = ws.live_backend(scope)
    if not backend.available():
        return "No retained Ghidra project for this binary; run `graphify-ghidra analyze` to enable live=true."
    ghidra_dir = {"incoming": "to", "outgoing": "from", "both": "both"}[direction]
    resp = backend.query("xrefs", [addr], limit=min(offset + limit, HARD_LIMIT * 2), direction=ghidra_dir)
    r = resp["results"][0]
    if r.get("error"):
        return f"Ghidra: {r['error']}"
    out = [f"Live references for {ws.display(nid)} ({addr}):"]
    for key, label in (("to", "incoming (referenced FROM)"), ("from", "outgoing (references TO)")):
        if key not in r:
            continue
        total = r.get(f"{key}_total", len(r[key]))
        out.append(f"{label} ({total} total):")
        for x in r[key][offset: offset + limit]:
            where = x.get("from_function")
            if key == "to":
                other = f"{where} ({x.get('from_function_address')})" if where else "(not inside a function: data table / pointer)"
            else:
                other = x.get("to_symbol") or x["to"]
            flag = "call" if x.get("call") else ("write" if x.get("write") else x.get("type", "").lower())
            out.append(f"  {x['from'] if key == 'to' else addr:<14} {flag:<18} {other}")
        if total > offset + limit:
            out.append(f"  -- {total - offset - limit} more; next: offset={offset + limit}")
    return _cap("\n".join(out))


# ================================================================== tool: name

def _confidence(v: Any) -> str:
    return v if v in CONFIDENCES else "medium"


def _commit(ws: Workspace) -> dict[str, int]:
    for s in ws.stores.values():
        s.save()
    from .graph_io import patch_graph
    counts = patch_graph(ws.out)
    ws.reload()
    return counts


def tool_name(ws: Workspace, a: dict[str, Any]) -> str:
    items = a.get("items")
    if not isinstance(items, list) or not items:
        return "ghidra_name needs items: [{address, name, confidence?, evidence?, rationale?}]. Batch many in one call."
    if len(items) > 80:
        return "Too many items in one call (max 80). Split the batch."
    results: list[str] = []
    changed = 0
    last_scope = None
    for it in items:
        if not isinstance(it, dict):
            results.append("skipped a non-object item")
            continue
        try:
            nid = ws.resolve(it.get("address"), it.get("binary") or a.get("binary"),
                             kinds=("function", "thunk") if not it.get("data") else ("data",))
        except (NotFound, Ambiguous) as exc:
            results.append(f"{it.get('address')}: {exc}")
            continue
        m = ws.meta(nid)
        scope, addr = m["scope"], m["address"]
        last_scope = scope
        store = ws.stores[scope]
        protected = m.get("name_source") == "USER_DEFINED" and not m.get("ai_name")
        if it.get("variable"):
            v = it["variable"]
            if isinstance(v, dict) and v.get("old") and v.get("new"):
                r = store.set_variable(addr, str(v["old"]), v["new"], type_=v.get("type"), note=str(it.get("note") or ""))
                results.append(f"{addr} var {v['old']}: {r.status} -> {r.name or r.message}")
                changed += r.status in ("named", "renamed")
            else:
                results.append(f"{addr}: variable needs {{old, new}}")
        if it.get("name"):
            r = store.set_name(addr, it["name"], confidence=_confidence(it.get("confidence")), evidence=it.get("evidence"),
                               rationale=str(it.get("rationale") or ""), by="ai", force=bool(a.get("force")),
                               protected=protected)
            results.append(r.line())
            changed += r.status in ("named", "renamed")
        elif it.get("note") and not it.get("variable"):
            store.mark_examined(addr, str(it["note"]))
            results.append(f"{addr}: marked examined ({_short(it['note'], 50)})")
            changed += 1
    if changed:
        _commit(ws)
    head = f"{changed} change(s) applied of {len(items)} item(s)." if changed else "No changes applied."
    shown = results[:40]
    text = head + "\n" + "\n".join(shown)
    if len(results) > 40:
        text += f"\n... {len(results) - 40} more results omitted"
    if last_scope:
        text += "\n" + nudge(ws, last_scope)
    return _cap(text)


# =============================================================== tool: suggest

def tool_suggest(ws: Workspace, a: dict[str, Any]) -> str:
    scope = _pick(ws, a)
    limit = _int(a.get("limit"), 25, 1, 100)
    targets: list[str]
    if a.get("addresses"):
        targets = [ws.resolve(x, a.get("binary")) for x in a["addresses"][:100]]
    else:
        targets = [n for n in ws.functions(scope) if (_is_unnamed_fn(ws, n) or ws.meta(n).get("ghidra_kind") == "thunk")
                   and not ws.is_named(n)]
    found = [(nid, suggestions_for(ws, nid)) for nid in targets]
    found = [(n, h) for n, h in found if h]
    found.sort(key=lambda t: (-_RANK_C[t[1][0][1]], _addr(ws, t[0])))
    if a.get("apply_wrappers"):
        store = ws.stores[scope]
        applied = 0
        for nid, hints in found:
            name, conf, why = hints[0]
            if conf in ("medium", "high") and ("wrapper" in why or why.startswith("thunk")):
                r = store.set_name(_addr(ws, nid), name, confidence=conf, evidence=[why], by="heuristic",
                                   protected=ws.meta(nid).get("name_source") == "USER_DEFINED")
                applied += r.status in ("named", "renamed")
        if applied:
            _commit(ws)
        return f"Auto-named {applied} thunk/wrapper functions (by=heuristic; override any with ghidra_name).\n" + nudge(ws, scope)
    out = [f"{len(found)} functions have a name hint (showing {min(limit, len(found))}). Hints are leads, verify before naming:"]
    for nid, hints in found[:limit]:
        h = hints[0]
        out.append(f"  {_addr(ws, nid)}  {h[0]}  [{h[1]}]  {h[2]}")
    out.append("Pass apply_wrappers=true to auto-name the unambiguous thunks/wrappers in bulk.")
    return _cap("\n".join(out))


_RANK_C = {"low": 0, "medium": 1, "high": 2}


# ============================================================== tool: similar

def tool_similar(ws: Workspace, a: dict[str, Any]) -> str:
    nid = ws.resolve(a.get("address"), a.get("binary"))
    limit = _int(a.get("limit"), 8, 1, 40)
    min_score = float(a.get("min_score") or 0.6)
    rows: list[tuple[float, str, str]] = []
    for t, e in ws.sim.get(nid, []):
        s = float(e.get("confidence_score") or 0)
        if s >= min_score:
            rows.append((s, t, _short(e.get("context", "").replace("similar code: ", ""), 70)))
    deep_note = ""
    if a.get("deep") or not rows:
        extra = _deep_similar(ws, nid, min_score, limit)
        known = {t for _, t, _ in rows}
        rows += [r for r in extra if r[1] not in known]
        deep_note = " (deep search over the full feature index)" if extra else ""
    rows.sort(key=lambda r: -r[0])
    if not rows:
        return (f"No functions at least {min_score:.2f} similar to {ws.display(nid)}. Its mnemonic features may be too "
                "short (< 10 instructions) or unique. Lower min_score, or decompile it for expression-level matching.")
    out = [f"Functions similar to {ws.display(nid)}{deep_note}:"]
    for s, t, why in rows[:limit]:
        tm = ws.meta(t)
        tag = f"{ws.scopes.get(tm.get('scope'), {}).get('name', '?')}:" if tm.get("scope") != ws.meta(nid).get("scope") else ""
        named = f" = named by {ws.named_by(t)}" if ws.is_named(t) else " (unnamed)"
        out.append(f"  {s:.2f}  {tag}{ws.display(t)}{named}   {why}")
    out.append("Similar + named -> reuse the name (ghidra_propagate does this in bulk). Similar but different -> ghidra_link kind=variant_of.")
    return _cap("\n".join(out))


def _deep_similar(ws: Workspace, nid: str, min_score: float, limit: int) -> list[tuple[float, str, str]]:
    import json as _json
    from .similarity import Params, describe, expr_hashes, find_similar
    index_dir = ws.out / "ghidra" / "index"
    records, target = [], None
    for p in sorted(index_dir.glob("*.jsonl")) if index_dir.is_dir() else []:
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    r = _json.loads(line)
                    records.append(r)
                    if r["id"] == nid:
                        target = r
    if target is None:
        return []
    side = ws.out / "ghidra" / ws.meta(nid)["scope"] / "pseudo" / (_addr(ws, nid).replace(":", "_") + ".c")
    q = dict(target, id="__query__", scope="__query__")
    if side.is_file():
        q["expr"] = expr_hashes(side.read_text(encoding="utf-8"))
    edges = find_similar(records + [q], params=Params(threshold=min_score, top_k=limit, min_instrs=4),
                         query_scope="__query__")
    out = []
    for e in edges:
        other = e["b"] if e["a"] == "__query__" else e["a"]
        if "__query__" in (e["a"], e["b"]) and other in ws.nodes and other != nid:
            out.append((float(e["score"]), other, describe(e)))
    return out


# ============================================================ tool: propagate

def tool_propagate(ws: Workspace, a: dict[str, Any]) -> str:
    """Carry names from named functions onto their near-copies (same or other binary)."""
    scope = _pick(ws, a)
    thr = float(a.get("threshold") or 0.9)
    limit = _int(a.get("limit"), 40, 1, 200)
    store = ws.stores[scope]
    props: list[tuple[float, str, str, str]] = []
    for nid in ws.functions(scope):
        if not _is_unnamed_fn(ws, nid):
            continue
        best = None
        for t, e in ws.sim.get(nid, []):
            s = float(e.get("confidence_score") or 0)
            src_by = ws.named_by(t)
            if s < thr or src_by is None or src_by == "propagated":
                continue
            tm = ws.meta(t)
            if tm.get("ai_name") and tm.get("name_confidence") == "low":
                continue
            if best is None or s > best[0]:
                best = (s, t)
        if best:
            props.append((best[0], nid, best[1], _label(ws, best[1])))
    props.sort(key=lambda p: (-p[0], _addr(ws, p[1])))
    if not props:
        return (f"No unnamed function is >= {thr:.2f} similar to a named one. Name more functions first (similar copies "
                "then follow), ingest a symbolised build of the same program, or lower threshold.")
    if not a.get("apply"):
        out = [f"{len(props)} propagation proposals at >= {thr:.2f} (showing {min(limit, len(props))}); apply=true commits all:"]
        for s, nid, src, name in props[:limit]:
            out.append(f"  {s:.2f}  {_addr(ws, nid)} <- {ws.display(src)}  => {name}{'' if s >= 0.97 else '_like'}")
        return _cap("\n".join(out))
    applied = 0
    for s, nid, src, name in props:
        final = name if s >= 0.97 else f"{name}_like"
        conf = "high" if s >= 0.97 else "medium" if s >= 0.9 else "low"
        r = store.set_name(_addr(ws, nid), final, confidence=conf, by="propagated",
                           evidence=[f"similar to {ws.display(src)} score {s:.2f}"],
                           protected=ws.meta(nid).get("name_source") == "USER_DEFINED")
        applied += r.status in ("named", "renamed")
    if applied:
        _commit(ws)
    return f"Propagated {applied} names (by=propagated; evidence recorded). Review with ghidra_worklist; override with ghidra_name.\n" + nudge(ws, scope)


# ================================================================== tool: link

def tool_link(ws: Workspace, a: dict[str, Any]) -> str:
    links = a.get("links")
    if not isinstance(links, list) or not links:
        return f"ghidra_link needs links: [{{a, b, kind, confidence?, rationale}}]; kind is one of {sorted(LINK_KINDS)}."
    res, changed = [], 0
    for ln in links[:60]:
        try:
            ia = _resolve_any(ws, str(ln.get("a")), ln.get("binary") or a.get("binary"))
            ib = _resolve_any(ws, str(ln.get("b")), ln.get("binary_b") or ln.get("binary") or a.get("binary"))
        except (NotFound, Ambiguous) as exc:
            res.append(f"{ln.get('a')} -> {ln.get('b')}: {exc}")
            continue
        ma, mb = ws.meta(ia), ws.meta(ib)
        if not ma.get("scope") or not mb.get("scope") or not ma.get("address") or not mb.get("address"):
            res.append(f"{ws.display(ia)} / {ws.display(ib)}: links join functions or globals (address-bearing nodes)")
            continue
        store = ws.stores[ma["scope"]]
        ok, msg = store.add_link(f"{ma['scope']}:{ma['address']}", f"{mb['scope']}:{mb['address']}", str(ln.get("kind", "")),
                                 confidence=_confidence(ln.get("confidence")), rationale=str(ln.get("rationale") or ""))
        res.append(f"{ws.display(ia)} -[{ln.get('kind')}]-> {ws.display(ib)}: {msg}")
        changed += ok
    if changed:
        _commit(ws)
    return _cap(f"{changed} link(s) saved.\n" + "\n".join(res[:40]))


# ============================================================= tool: behavior

def tool_behavior(ws: Workspace, a: dict[str, Any]) -> str:
    scope = _pick(ws, a)
    store = ws.stores[scope]
    action = a.get("action") or "list"
    behaviors = store.data["behaviors"]
    if action == "list":
        if not behaviors:
            return ("No behaviours defined. A behaviour groups the functions that together do one job (e.g. "
                    "'config parsing', 'update check'). Use action=candidates for suggested groups.")
        out = [f"{len(behaviors)} behaviours:"]
        for slug, b in sorted(behaviors.items()):
            par = f" (part of {b['parent']})" if b.get("parent") else ""
            out.append(f"  {slug}: {b['label']} - {len(b['members'])} functions [{b['confidence']}]{par}  {_short(b.get('description'), 70)}")
        return _cap("\n".join(out))
    if action == "show":
        slug = re.sub(r"[^a-z0-9_]+", "_", str(a.get("id", "")).lower()).strip("_")
        b = behaviors.get(slug)
        if not b:
            return f"no behaviour {a.get('id')!r}; known: {', '.join(behaviors) or 'none'}"
        out = [f"{b['label']} [{b['confidence']}]" + (f" part of {b['parent']}" if b.get("parent") else ""), b.get("description") or ""]
        for addr in b["members"][:60]:
            nid = ws.fn_key.get((scope, addr))
            out.append(f"  {ws.display(nid) if nid else addr}")
        subs = [s for s, x in behaviors.items() if x.get("parent") == slug]
        if subs:
            out.append("sub-behaviours: " + ", ".join(subs))
        return _cap("\n".join(x for x in out if x != ""))
    if action == "candidates":
        return _behavior_candidates(ws, scope, _int(a.get("limit"), 6, 1, 15))
    if action == "delete":
        slug = re.sub(r"[^a-z0-9_]+", "_", str(a.get("id", "")).lower()).strip("_")
        if behaviors.pop(slug, None) is None:
            return f"no behaviour {a.get('id')!r}"
        for x in behaviors.values():
            if x.get("parent") == slug:
                x["parent"] = None
        _commit(ws)
        return f"deleted behaviour {slug}"
    if action in ("define", "add", "remove"):
        if not a.get("id"):
            return "behaviour needs id (a short slug, e.g. config_parsing)."
        members = [ws.resolve(x, a.get("binary")) for x in (a.get("members") or [])]
        addrs = [_addr(ws, n) for n in members]
        slug, err = store.set_behavior(
            a["id"], label=a.get("label"), description=a.get("description"),
            members=addrs if action == "define" and a.get("members") is not None else None,
            add_members=addrs if action == "add" else None, remove_members=addrs if action == "remove" else None,
            parent=a.get("parent"), confidence=_confidence(a.get("confidence")), evidence=a.get("evidence"))
        if err and not slug:
            return err
        _commit(ws)
        b = store.data["behaviors"][slug]
        return (f"behaviour {slug!r} now has {len(b['members'])} functions" + (f"  note: {err}" if err else "") +
                "\nGraph links: members --implements--> behaviour node (+ hyperedge). Add sub-behaviours with parent=...")
    return "action must be one of: list, show, candidates, define, add, remove, delete"


def _behavior_candidates(ws: Workspace, scope: str, limit: int) -> str:
    store = ws.stores[scope]
    assigned = {addr for b in store.data["behaviors"].values() for addr in b["members"]}
    groups: dict[Any, list[str]] = defaultdict(list)
    for nid in ws.functions(scope):
        c = ws.nodes[nid].get("community")
        if c is not None and ws.meta(nid).get("ghidra_kind") == "function":
            groups[c].append(nid)
    ranked = []
    for c, members in groups.items():
        if len(members) < 4:
            continue
        free = [m for m in members if _addr(ws, m) not in assigned]
        if len(free) < 3:
            continue
        ranked.append((len(free) * (1 + sum(1 for m in free if not ws.is_named(m)) / len(free)), c, members, free))
    ranked.sort(key=lambda t: -t[0])
    if not ranked:
        return "No unassigned community of >= 4 functions found. Run more naming first, or define behaviours by hand."
    out = ["Candidate groups from graph communities (unassigned functions). Confirm by reading a few, then define:"]
    for _s, c, members, free in ranked[:limit]:
        caps: Counter[str] = Counter()
        apis: Counter[str] = Counter()
        for m in free:
            caps.update(ws.meta(m).get("capabilities") or [])
            apis.update(_label(ws, t) for t, _ in ws.calls_out.get(m, []) if ws.meta(t).get("ghidra_kind") == "import")
        hub = max(free, key=lambda m: len(ws.calls_in.get(m, [])) + len(ws.calls_out.get(m, [])))
        out.append(f"- community {c}: {len(free)} unassigned of {len(members)}; hub {ws.display(hub)}")
        out.append("  members: " + ", ".join(ws.display(m) for m in free[:7]) + (f" +{len(free) - 7}" if len(free) > 7 else ""))
        if caps:
            out.append("  caps: " + ", ".join(k for k, _ in caps.most_common(3)) + "; apis: " + ", ".join(k for k, _ in apis.most_common(4)))
        out.append(f"  -> ghidra_behavior action=define id=<slug> label=<what it does> members=[...]")
    return _cap("\n".join(out))


# ================================================================ tool: search

def tool_search(ws: Workspace, a: dict[str, Any]) -> str:
    q = str(a.get("query", "")).strip()
    if len(q) < 2:
        return "query must be at least 2 characters"
    limit = _int(a.get("limit"), 25, 1, 100)
    kinds = a.get("kinds") or ["name", "string", "api", "constant", "pseudo", "behavior"]
    scope = ws.pick_scope(a["binary"]) if a.get("binary") else None
    low = q.lower()
    out: list[str] = []

    def room() -> bool:
        return len(out) < limit

    for nid, n in ws.nodes.items():
        m = n.get("metadata") or {}
        if scope and m.get("scope") not in (scope, None):
            continue
        k = m.get("ghidra_kind")
        if "name" in kinds and k in ("function", "thunk", "data", "variable") and (
                low in str(n.get("label", "")).lower() or low in str(m.get("original_label", "")).lower()) and room():
            out.append(f"name    {ws.display(nid)}  [{ws.named_by(nid) or 'unnamed'}]")
        elif "string" in kinds and k == "string" and low in str(m.get("value", "")).lower() and room():
            users = [ws.display(s) for s, _ in ws.refs_in.get(nid, [])][:3]
            out.append(f'string  "{_short(m.get("value"), 60)}" @{m.get("address")}  used by: {", ".join(users) or "(no function)"}')
        elif "api" in kinds and k == "import" and low in str(n.get("label", "")).lower() and room():
            users = [ws.display(s) for s, _ in ws.calls_in.get(nid, [])][:3]
            out.append(f"api     {n['label']} ({m.get('library')})  called by: {', '.join(users) or '(unused)'}")
        elif "behavior" in kinds and k == "behavior" and low in (str(n.get("label", "")) + str(m.get("description", ""))).lower() and room():
            out.append(f"behavior {n['label']}  ({m.get('member_count')} functions)")
    if "constant" in kinds and room():
        import json as _json
        needle = canon_addr(q) or q.lower()
        idx = ws.out / "ghidra" / "index"
        for p in sorted(idx.glob("*.jsonl")) if idx.is_dir() else []:
            with p.open(encoding="utf-8") as fh:
                for line in fh:
                    if needle in line and room():
                        r = _json.loads(line)
                        if needle in r.get("consts", []) and r["id"] in ws.nodes and (not scope or r["scope"] == scope):
                            out.append(f"const   {needle} in {ws.display(r['id'])}")
    if "pseudo" in kinds and room():
        for p in sorted((ws.out / "ghidra").glob("*/pseudo/*.c")):
            if scope and p.parts[-3] != scope:
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except OSError:
                continue
            if low in text.lower() and room():
                addr = p.stem
                nid = ws.fn_key.get((p.parts[-3], addr))
                line = next((ln.strip() for ln in text.splitlines() if low in ln.lower()), "")
                out.append(f"pseudo  {ws.display(nid) if nid else addr}: {_short(line, 70)}")
    if not out:
        return f"No matches for {q!r} in {', '.join(kinds)}. (Constants are matched as hex like 0x67452301; pseudo-C only covers decompiled functions.)"
    return _cap(f"{len(out)} match(es){' (capped)' if len(out) >= limit else ''} for {q!r}:\n" + "\n".join(out))


# ================================================================== tool: live

def tool_decompile(ws: Workspace, a: dict[str, Any]) -> str:
    refs = a.get("addresses") or []
    if not refs:
        return "ghidra_decompile needs addresses: [...] (up to 6 functions)."
    per_cap = _int(a.get("chars"), 3500, 300, 12000)
    total_cap = 11000
    nids = [ws.resolve(r, a.get("binary")) for r in refs[:6]]
    by_scope: dict[str, list[str]] = defaultdict(list)
    for nid in nids:
        by_scope[ws.meta(nid)["scope"]].append(nid)
    out: list[str] = []
    used = 0
    for scope, group in by_scope.items():
        backend = ws.live_backend(scope)
        if not backend.available():
            return ("No retained Ghidra project for this binary, so live decompilation is unavailable. Re-run "
                    "`graphify-ghidra analyze` (the project is kept by default).")
        resp = backend.query("decompile", [_addr(ws, n) for n in group], chars=12000, timeout=60)
        for nid, r in zip(group, resp["results"]):
            if r.get("error"):
                out.append(f"{ws.display(nid)}: {r['error']}")
                continue
            raw = r["pseudo_c"]
            side = ws.out / "ghidra" / scope / "pseudo" / (_addr(ws, nid).replace(":", "_") + ".c")
            side.parent.mkdir(parents=True, exist_ok=True)
            side.write_text(raw, encoding="utf-8")                   # raw: names are substituted at read time
            body = substitute_names(ws, scope, nid, raw).replace("\r", "")
            body = "\n".join(ln for ln in body.split("\n") if not ln.lstrip().startswith("/* WARNING"))
            body = re.sub(r"\n{3,}", "\n\n", body).strip()
            head = f"== {ws.display(nid)}  {r.get('pseudo_c_lines')} lines" + (" (truncated by Ghidra cap)" if r.get("pseudo_c_truncated") else "")
            vars_ = [f"{v['name']}:{v['type']}" for v in (r.get("variables") or []) if v.get("param")][:8]
            lines = [head, "params: " + ", ".join(vars_) if vars_ else "params: -"]
            callees = [ws.display(t) for t, _ in ws.calls_out.get(nid, [])][:10]
            if callees:
                lines.append("calls: " + ", ".join(callees))
            budget = max(300, min(per_cap, total_cap - used))
            lines.append(body[:budget] + ("\n... [truncated; pass chars=N up to 12000, or ghidra_function pseudo=true later]" if len(body) > budget else ""))
            used += min(len(body), budget)
            out.append("\n".join(lines))
            _refresh_expr(ws, nid, raw)
    out.append("Rename what you now understand: ghidra_name (use variable={old,new,type} for locals/params; "
               "the next decompile shows your names).")
    return _cap("\n\n".join(out), 14000)


def _refresh_expr(ws: Workspace, nid: str, pseudo: str) -> None:
    """Fold fresh pseudo-C into the similarity index so deep searches use expression features."""
    import json as _json
    from .similarity import expr_hashes
    p = ws.out / "ghidra" / "index" / f"{ws.meta(nid)['scope']}.jsonl"
    if not p.is_file():
        return
    lines, hit = [], False
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = _json.loads(line)
            if r["id"] == nid:
                r["expr"] = expr_hashes(pseudo)
                hit = True
                line = _json.dumps(r, separators=(",", ":"))
        lines.append(line)
    if hit:
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def tool_disasm(ws: Workspace, a: dict[str, Any]) -> str:
    nid = ws.resolve(a.get("address"), a.get("binary"))
    scope = ws.meta(nid)["scope"]
    limit = _int(a.get("limit"), 60, 5, 300)
    backend = ws.live_backend(scope)
    if not backend.available():
        return "No retained Ghidra project for this binary; re-run `graphify-ghidra analyze`."
    r = backend.query("disasm", [_addr(ws, nid)], limit=limit)["results"][0]
    if r.get("error"):
        return f"Ghidra: {r['error']}"
    out = [f"{ws.display(nid)}: {r['instruction_count']} instructions" + (f" (first {limit} shown)" if r.get("truncated") else "")]
    for l in r["lines"]:
        ref = f"   ; {substitute_names(ws, scope, nid, l['refs'])}" if l.get("refs") else ""
        cm = f"   // {l['comment']}" if l.get("comment") else ""
        out.append(f"{l['address']:<12} {l['text']}{ref}{cm}")
    if r.get("truncated"):
        out.append(f"-- more instructions exist; raise limit (max 300)")
    return _cap("\n".join(out), 9000)


# ============================================================== tool: callchain

def tool_callchain(ws: Workspace, a: dict[str, Any]) -> str:
    from .callchain import CallGraph
    cg = CallGraph.__new__(CallGraph)
    import networkx as nx
    g = nx.DiGraph()
    for s, lst in ws.calls_out.items():
        for t, e in lst:
            g.add_edge(s, t, confidence=e.get("confidence"))
    exhibits: dict[str, set[str]] = defaultdict(set)
    for s, caps in ws.caps.items():
        for c in caps:
            exhibits[c].add(s)
    CallGraph.__init__(cg, ws.nodes, g, exhibits)
    src = _resolve_any(ws, str(a.get("source")), a.get("binary"))
    target = str(a.get("target"))
    try:
        chains = cg.chains(src, target, k=_int(a.get("k"), 3, 1, 8))
    except (KeyError, LookupError) as exc:
        return str(exc)
    if not chains:
        return (f"No call chain from {ws.display(src)} to {target!r} over resolved calls. Indirect calls are not followed; "
                "if you know the indirect target, assert it with ghidra_link kind=calls.")
    out = []
    for i, ch in enumerate(chains, 1):
        out.append(f"chain {i} ({len(ch) - 1} calls): " + " -> ".join(ws.display(n) for n in ch))
    return _cap("\n".join(out))


# ============================================================== tool: analyze

def tool_analyze(ws: Workspace, a: dict[str, Any]) -> str:
    """Start a background Ghidra analysis of one binary (never blocks; poll ghidra_status)."""
    from .jobs import start_analysis
    binary = a.get("binary")
    if not isinstance(binary, str) or not binary.strip():
        return "ghidra_analyze needs binary: the absolute path of the DLL/EXE/ELF to analyse."
    ok, msg = start_analysis(ws.out, binary.strip().strip('"'), decompile=_int(a.get("decompile"), 30, 0, 200),
                             language=a.get("language") or None, loader=a.get("loader") or None)
    return msg


# ================================================================== registry

TOOLS: dict[str, Callable[[Workspace, dict[str, Any]], str]] = {
    "ghidra_status": tool_status,
    "ghidra_analyze": tool_analyze,
    "ghidra_worklist": tool_worklist,
    "ghidra_function": tool_function,
    "ghidra_refs": tool_refs,
    "ghidra_name": tool_name,
    "ghidra_suggest": tool_suggest,
    "ghidra_similar": tool_similar,
    "ghidra_propagate": tool_propagate,
    "ghidra_link": tool_link,
    "ghidra_behavior": tool_behavior,
    "ghidra_decompile": tool_decompile,
    "ghidra_disasm": tool_disasm,
    "ghidra_search": tool_search,
    "ghidra_callchain": tool_callchain,
}


def run_tool(ws: Workspace, name: str, args: dict[str, Any] | None) -> tuple[bool, str]:
    """Execute one tool. Never raises: failures come back as ``(False, message)``."""
    fn = TOOLS.get(name)
    if fn is None:
        return False, f"unknown tool {name!r}; available: {', '.join(TOOLS)}"
    args = args if isinstance(args, dict) else {}
    try:
        try:
            ws.ensure()
        except NoGhidraData:
            if name in ("ghidra_status", "ghidra_analyze"):
                return True, fn(ws, args)       # these two explain / fix the missing graph themselves
            return False, _bootstrap_text(ws)
        return True, fn(ws, args)
    except NoGhidraData as exc:
        return False, str(exc)
    except Ambiguous as exc:
        opts = "\n  ".join(exc.options[:10])
        return False, f"{exc.ref!r} matches several; pass scope:address or binary=...\n  {opts}"
    except NotFound as exc:
        return False, f"not found: {exc}"
    except Exception as exc:   # the harness must keep working whatever one tool does
        from .ghidra_runner import ExportFailed
        if isinstance(exc, ExportFailed):
            return False, f"Ghidra: {exc}"
        return False, f"{type(exc).__name__}: {exc}"
