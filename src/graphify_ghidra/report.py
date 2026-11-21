"""Markdown triage report for one analysed binary.

The report follows REA's evidence discipline: every section says whether its
content was *observed* (read from Ghidra), *derived* (computed exactly from
observations) or *inferred* (a heuristic), and a "Blind spots" section lists
what the export could not see, so an empty result is not read as absence.
"""

from __future__ import annotations

from typing import Any

from .capabilities import CAPABILITIES

__all__ = ["render_report"]


def _md(value: Any) -> str:
    """Escape a table cell and neutralise markup: report text derives from an
    untrusted binary (function names, strings), so it is data, not formatting."""
    s = str(value).replace("|", "\\|").replace("\n", " ").replace("`", "'")
    return s if len(s) <= 120 else s[:117] + "..."


def render_report(ghidra: dict[str, Any], *, top: int = 25) -> str:
    prog = ghidra["program"]
    s = ghidra["summary"]
    lines: list[str] = []
    add = lines.append

    add(f"# Ghidra analysis: {_md(prog.get('name'))}")
    add("")
    add("> Everything below comes from a static Ghidra analysis. "
        "**Observed** = read from Ghidra. **Derived** = computed exactly from observations. "
        "**Inferred** = heuristic; treat as a lead, not a finding.")
    add("")
    add("## Program (observed)")
    add("")
    for key, label in (("format", "Format"), ("processor", "Processor"), ("language", "Language"),
                       ("image_base", "Image base"), ("sha256", "SHA-256")):
        if prog.get(key):
            add(f"- **{label}:** `{_md(prog[key])}`")
    add(f"- **Functions:** {s['functions']} ({s['thunks']} thunks, {s['library_functions']} matched as "
        f"statically linked library code, {s['analyst_named']} analyst-named, {s['auto_named']} auto-named)")
    add(f"- **Imports:** {s['imports']}; **strings defined:** {s['strings_total']}")
    add(f"- **Call graph:** {s['call_edges']} function->function edges, {s['external_call_edges']} "
        f"function->import edges from {s['call_sites']} call sites")
    eps = ", ".join(f"`{e}`" for e in s["entry_points"][:8]) or "none found"
    add(f"- **Entry points:** {eps}")
    add(f"- **Reachable from an entry point (derived):** {s['reachable_from_entry']} of {s['functions']}")
    add("")

    add("## Where to start reading (inferred)")
    add("")
    ranked = ghidra.get("ranked", [])[:top]
    if not ranked:
        add("_No function scored above zero._")
    else:
        add("| # | Function | Address | Score | Why |")
        add("|---|----------|---------|-------|-----|")
        for i, r in enumerate(ranked, 1):
            why = "; ".join(r["reasons"][:3]) or "-"
            roles = f" _({', '.join(r['roles'])})_" if r["roles"] else ""
            add(f"| {i} | `{_md(r['name'])}`{roles} | `{r['address']}` | {r['score']} | {_md(why)} |")
    add("")

    add("## Capabilities (inferred)")
    add("")
    counts = s["capability_function_counts"]
    if not counts:
        add("_No capability rules matched. This does not mean the binary has none: "
            "see Blind spots._")
    else:
        add("| Capability | Functions | Risk weight |")
        add("|------------|-----------|-------------|")
        for key, n in counts.items():
            cap = CAPABILITIES.get(key)
            add(f"| {_md(cap.label if cap else key)} | {n} | {cap.risk if cap else 0} |")
    add("")

    libs = ghidra.get("libraries", {})
    if libs:
        add("## Libraries actually called (observed)")
        add("")
        add("| Library | Distinct APIs called |")
        add("|---------|----------------------|")
        for lib, n in list(libs.items())[:20]:
            add(f"| `{_md(lib)}` | {n} |")
        add("")

    add("## Blind spots")
    add("")
    add(f"- **{s['indirect_call_sites']} indirect/computed call sites** of {s['call_sites']}: "
        "targets reached through function pointers, vtables or `jmp` tables may be missing from the call graph.")
    add(f"- **{s['unresolved_call_sites']} call sites Ghidra left unresolved.**")
    add(f"- **{s['unreachable_functions']} functions are not reachable from an entry point** over direct calls: "
        "callbacks, exported-by-pointer targets, or dead code.")
    add(f"- **{round(s['auto_named_ratio'] * 100)}% of functions still carry Ghidra's default names.**")
    if s["decompiled"] == 0:
        add("- No pseudo-code was exported (re-run with `--decompile N` to attach it to the top-ranked functions).")
    else:
        add(f"- Pseudo-code is attached to {s['decompiled']} functions only; it is truncated and not verified.")
    add("- Strings are only those Ghidra *defined*; packed, encrypted or stack-built strings are invisible here.")
    add("- Capability tags come from API/string name rules: they show *access to* a behaviour, not that it executes.")
    add("")
    return "\n".join(lines)
