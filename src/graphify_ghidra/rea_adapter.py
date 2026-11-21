"""Adapt REA (https://github.com/morluto/rea) Ghidra results into a ``graphify-ghidra/1`` export.

REA drives Ghidra through an MCP/CLI surface and returns *Evidence*: provider
facts wrapped in an envelope whose payload lives under
``structuredContent.normalized_result`` (MCP) or the CLI's ``--json`` output.
This adapter turns saved REA results into the same neutral export the packaged
Ghidra script produces, so a REA investigation and a raw headless export land
in one graph with one set of semantics.

What it understands (shapes taken from REA's Ghidra bridge and contracts)
------------------------------------------------------------------------
``list_procedures``        ``[{address, value, procedure:{external, thunk, thunk_target}}]``
``list_strings``           ``[{address, value, string:{encoding, byte_length}}]``
``list_segments``          ``[{name, start, end, readable, writable, executable}]``
``procedure_references``   ``{procedure, direction, references:[{source_address, target_address,
                           source_procedure, target_procedure, kind:{call, data, read, ...}}],
                           unresolved_calls:[...]}``
``procedure_callees`` / ``procedure_callers`` / ``xrefs``
                           bare address arrays carry no subject, so they must be saved in the
                           tool envelope ``{"tool", "arguments", "result"}`` (the adapter also
                           accepts an MCP tool result placed under ``"result"``).

Any payload may be wrapped in ``structuredContent`` / ``normalized_result`` /
``result``; the adapter unwraps those. A file may hold one payload, a list of
payloads/envelopes, or JSON-lines.

Limits, stated honestly
-----------------------
* Written against REA's source and docs, exercised on fixtures shaped from them.
  It has not been validated against live REA output on every provider version;
  unrecognised payloads are reported in ``warnings`` instead of being guessed.
* Evidence-bundle archives (``--evidence_output``) are not unpacked; save the
  individual tool results, or use the packaged Ghidra export for full fidelity.
* REA does not expose per-function instruction counts, complexity or
  pseudo-code in its inventory results, so those fields stay absent; capability
  tagging still works from the names and references REA does return.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable

from .model import canon_addr, empty_export

__all__ = ["load_payloads", "build_export", "unwrap", "classify"]

_UNWRAP_KEYS = ("structuredContent", "normalized_result", "result")


def unwrap(payload: Any) -> Any:
    """Peel REA/MCP envelopes until the provider payload is exposed."""
    seen = 0
    while isinstance(payload, dict) and seen < 6:
        seen += 1
        # A tool envelope is deliberately NOT unwrapped here: classify() needs
        # the tool name and arguments that sit beside "result".
        if "tool" in payload and "result" in payload:
            return payload
        for key in _UNWRAP_KEYS:
            if key in payload and isinstance(payload[key], (dict, list)):
                payload = payload[key]
                break
        else:
            return payload
    return payload


def load_payloads(sources: Iterable[str | Path]) -> list[Any]:
    """Read JSON / JSON-lines files (``-`` = stdin) into a flat payload list."""
    payloads: list[Any] = []
    for src in sources:
        text = sys.stdin.read() if str(src) == "-" else Path(src).read_text(encoding="utf-8")
        text = text.strip()
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
            payloads.extend(data)
            continue
        # A top-level list is ambiguous: it is either many payloads/envelopes, or a
        # single inventory (list_procedures returns a bare list of rows). Treat it as
        # many only when every element is itself an envelope or a payload object.
        if isinstance(data, list) and data and all(
            isinstance(x, dict) and ("tool" in x or "references" in x or "normalized_result" in x
                                      or "structuredContent" in x or "result" in x)
            for x in data
        ):
            payloads.extend(data)
        else:
            payloads.append(data)
    return payloads


def classify(payload: Any) -> tuple[str, Any, dict[str, Any]]:
    """Return ``(kind, data, arguments)`` for one payload; kind ``"unknown"`` if unrecognised."""
    args: dict[str, Any] = {}
    tool = None
    if isinstance(payload, dict) and "tool" in payload and "result" in payload:
        tool = str(payload["tool"])
        args = payload.get("arguments") or payload.get("args") or {}
        payload = unwrap(payload["result"])
    else:
        payload = unwrap(payload)

    if tool:
        norm = tool.replace("-", "_")
        mapping = {
            "list_procedures": "procedures", "search_procedures": "procedures",
            "list_strings": "strings", "search_strings": "strings",
            "list_segments": "segments",
            "procedure_callees": "callees", "procedure_callers": "callers", "xrefs": "xrefs",
            "procedure_references": "references",
        }
        if norm in mapping:
            return mapping[norm], payload, args

    if isinstance(payload, dict):
        if isinstance(payload.get("references"), list) and "procedure" in payload:
            return "references", payload, args
        if "program" in payload and isinstance(payload["program"], dict) and payload.get("schema"):
            return "export", payload, args
        return "unknown", payload, args
    if isinstance(payload, list) and payload:
        first = payload[0]
        if isinstance(first, dict):
            if "start" in first and "end" in first and ("readable" in first or "name" in first):
                return "segments", payload, args
            if "address" in first and isinstance(first.get("string"), dict):
                return "strings", payload, args
            if "address" in first and isinstance(first.get("procedure"), dict):
                return "procedures", payload, args
            if "address" in first and "value" in first and "symbol" in first:
                return "names", payload, args
    return "unknown", payload, args


def _proc_name(identity: dict[str, Any] | None, fallback: str) -> str:
    if not isinstance(identity, dict):
        return fallback
    return str(identity.get("name") or identity.get("value") or fallback)


def build_export(
    payloads: list[Any],
    *,
    program_name: str,
    **program: Any,
) -> tuple[dict[str, Any], list[str]]:
    """Merge classified REA payloads into one export. Returns ``(doc, warnings)``."""
    doc = empty_export(program_name, **program)
    doc["producer"] = {"name": "rea", "adapter": "graphify-ghidra", "source": "https://github.com/morluto/rea"}
    warnings: list[str] = []
    fns: dict[str, dict[str, Any]] = {}
    imports: dict[str, dict[str, Any]] = {}
    strings: dict[str, dict[str, Any]] = {}
    calls: list[dict[str, Any]] = []
    deferred: list[tuple[str, Any, dict[str, Any]]] = []

    def ensure_fn(addr: str, name: str | None = None, **extra: Any) -> dict[str, Any]:
        fn = fns.setdefault(addr, {"address": addr, "name": name or f"FUN_{addr[2:]}"})
        if name and fn["name"].startswith("FUN_"):
            fn["name"] = name
        fn.update({k: v for k, v in extra.items() if v is not None})
        return fn

    for payload in payloads:
        kind, data, args = classify(payload)
        if kind == "procedures":
            for row in data:
                addr = canon_addr(row.get("address"))
                if addr is None:
                    continue
                facts = row.get("procedure") or {}
                name = str(row.get("value") or f"FUN_{addr[2:]}")
                if facts.get("external"):
                    imports.setdefault(addr, {"name": name, "library": facts.get("library"), "address": addr})
                    continue
                sym = row.get("symbol") or {}
                src = (sym.get("facts") or sym).get("source") if isinstance(sym, dict) else None
                ensure_fn(addr, name, is_thunk=bool(facts.get("thunk")),
                          thunk_target=canon_addr(facts.get("thunk_target")),
                          name_source=str(src).upper() if src else None,
                          user_named=True if src in ("user_defined", "USER_DEFINED") else None,
                          auto_named=True if name.startswith(("FUN_", "sub_")) else None)
        elif kind == "strings":
            for row in data:
                addr = canon_addr(row.get("address"))
                value = row.get("value")
                if addr is None or not isinstance(value, str):
                    continue
                facts = row.get("string") or {}
                strings.setdefault(addr, {"address": addr, "value": value, "refs": [],
                                          "length": facts.get("byte_length")})
        elif kind == "segments":
            for row in data:
                doc["segments"].append({
                    "name": row.get("name"), "start": canon_addr(row.get("start")),
                    "end": canon_addr(row.get("end")),
                    "read": bool(row.get("readable")), "write": bool(row.get("writable")),
                    "execute": bool(row.get("executable")), "initialized": row.get("initialized"),
                })
        elif kind in {"references", "callees", "callers", "xrefs"}:
            deferred.append((kind, data, args))
        elif kind == "export":
            warnings.append("payload is already a graphify-ghidra export; ingest it directly instead of via the REA adapter")
        else:
            warnings.append("skipped a payload that is not a recognised REA result "
                            "(expected list_procedures, list_strings, list_segments, procedure_references, "
                            "or a {tool, arguments, result} envelope)")

    # Edges need the function table complete first, so they are processed afterwards.
    for kind, data, args in deferred:
        if kind == "references":
            _apply_references(data, fns, imports, strings, calls, ensure_fn, warnings)
        elif kind in {"callees", "callers"}:
            subject = canon_addr(args.get("procedure") or args.get("address"))
            if subject is None or not isinstance(data, list):
                warnings.append(f"{kind} result skipped: needs the {{tool, arguments, result}} envelope "
                                "with the procedure address in arguments")
                continue
            for item in data:
                other = canon_addr(item if not isinstance(item, dict) else item.get("address"))
                if other is None:
                    continue
                src, dst = (subject, other) if kind == "callees" else (other, subject)
                if dst in imports:
                    calls.append({"from": src, "external_name": imports[dst]["name"],
                                  "external_library": imports[dst].get("library"), "kind": "CALL"})
                else:
                    ensure_fn(src)
                    ensure_fn(dst)
                    calls.append({"from": src, "to": dst, "kind": "CALL"})
        elif kind == "xrefs":
            target = canon_addr(args.get("address"))
            if target is None or not isinstance(data, list):
                warnings.append("xrefs result skipped: needs the envelope with the target address in arguments")
                continue
            for item in data:
                src = canon_addr(item if not isinstance(item, dict) else item.get("address"))
                if src in fns and target in strings:
                    strings[target]["refs"].append(src)
                elif src not in fns:
                    warnings.append(f"xref source {src} is not a function entry; REA xrefs return instruction "
                                    "addresses, so it cannot be attributed to a function without its body ranges")

    for addr, fn in fns.items():
        fn.setdefault("is_external", False)
    doc["functions"] = list(fns.values())
    doc["imports"] = [
        {"name": i["name"], "library": i.get("library") or "unknown", "address": i.get("address")}
        for i in imports.values()
    ]
    doc["calls"] = calls
    doc["strings"] = list(strings.values())
    return doc, warnings


def _apply_references(
    data: dict[str, Any], fns: dict[str, dict[str, Any]], imports: dict[str, dict[str, Any]],
    strings: dict[str, dict[str, Any]], calls: list[dict[str, Any]], ensure_fn, warnings: list[str],
) -> None:
    subject = data.get("procedure") or {}
    s_addr = canon_addr(subject.get("address"))
    if s_addr is None:
        warnings.append("procedure_references payload has no procedure.address; skipped")
        return
    ensure_fn(s_addr, _proc_name(subject, f"FUN_{s_addr[2:]}"))
    direction = data.get("direction")

    for ref in data.get("references") or []:
        kind = ref.get("kind") or {}
        src_p, dst_p = ref.get("source_procedure"), ref.get("target_procedure")
        src_addr = canon_addr((src_p or {}).get("address")) or (s_addr if direction == "outgoing" else None)
        t_addr = canon_addr(ref.get("target_address"))
        if kind.get("call"):
            if src_addr is None:
                continue
            ensure_fn(src_addr, _proc_name(src_p, f"FUN_{src_addr[2:]}"))
            site = canon_addr(ref.get("source_address"))
            if kind.get("external") or (t_addr in imports):
                name = imports.get(t_addr, {}).get("name") or _proc_name(dst_p, t_addr or "unknown")
                calls.append({"from": src_addr, "external_name": name,
                              "external_library": imports.get(t_addr, {}).get("library"),
                              "call_site": site, "kind": _call_kind(kind)})
                continue
            dst_addr = canon_addr((dst_p or {}).get("address")) or t_addr
            if dst_addr is None:
                continue
            ensure_fn(dst_addr, _proc_name(dst_p, f"FUN_{dst_addr[2:]}"))
            calls.append({"from": src_addr, "to": dst_addr, "call_site": site, "kind": _call_kind(kind)})
        elif (kind.get("data") or kind.get("read") or kind.get("write")) and src_addr and t_addr:
            if t_addr in strings:
                strings[t_addr]["refs"].append(src_addr)

    for unresolved in data.get("unresolved_calls") or []:
        calls.append({"from": s_addr, "unresolved": True,
                      "call_site": canon_addr((unresolved or {}).get("address") or (unresolved or {}).get("call_site")),
                      "reason": (unresolved or {}).get("reason")})


def _call_kind(kind: dict[str, Any]) -> str:
    if kind.get("computed") or kind.get("indirect"):
        return "COMPUTED_CALL"
    return "CONDITIONAL_CALL" if kind.get("conditional") else "UNCONDITIONAL_CALL"
