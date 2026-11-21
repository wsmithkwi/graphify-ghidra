"""The ``graphify-ghidra/1`` interchange document.

Every producer (the packaged Ghidra script, the REA adapter, hand-written
tooling) emits one of these; :mod:`graphify_ghidra.ingest` is the only
consumer. Keeping a single neutral document between "where facts come from"
and "how they become graph nodes" is what lets REA output and raw Ghidra
output land in the same graph with the same semantics.

Document shape (all collections optional except where noted)::

    {
      "schema": "graphify-ghidra/1",
      "producer": {"name": ..., ...},
      "program":  {"name", "format", "language", "sha256", "image_base", ...},
      "segments": [{"name", "start", "end", "size", "read", "write", "execute"}],
      "functions": [{"address", "name", "is_thunk", "is_external", "is_entry",
                     "size", "instruction_count", "call_sites",
                     "cyclomatic_complexity", "user_named", "auto_named",
                     "comment", "pseudo_c", "string_refs": [addr],
                     "data_refs": [addr], "api_calls": [name], ...}],
      "calls":    [{"from": addr, "to": addr | "external_name": str,
                    "external_library": str, "call_site": addr,
                    "kind": "UNCONDITIONAL_CALL" | "COMPUTED_CALL" | ...,
                    "via_thunk": addr, "unresolved": bool}],
      "imports":  [{"name", "library", "address"}],
      "exports":  [{"name", "address"}],
      "strings":  [{"address", "value", "refs": [function addr]}],
      "data":     [{"address", "name", "type", "refs": [function addr]}]
    }

Addresses are lowercase ``0x``-hex strings; non-default address spaces are
``<space>:0x<hex>`` (the same convention REA uses), so ids round-trip between
the two tools.
"""

from __future__ import annotations

import re
from typing import Any

SCHEMA = "graphify-ghidra/1"

_ADDR_RE = re.compile(r"^(?:(?P<space>[A-Za-z_][\w.\-]*):)?0x(?P<hex>[0-9a-fA-F]+)$")


class ExportError(ValueError):
    """The document is not a usable graphify-ghidra export."""


def scope_for(name: str, sha256: str | None) -> str:
    """Directory-safe, stable scope for one binary: ``<name>_<sha8>`` (or ``<name>``)."""
    from graphify.ids import make_id
    base = make_id(name) or "program"
    return f"{base}_{sha256[:8]}" if sha256 else base


def canon_addr(value: Any) -> str | None:
    """Canonicalise an address to lowercase ``0x`` hex (REA convention).

    Accepts ints, ``0x401000``, ``0X401000``, ``401000h``, bare hex with an
    ``0x``-less prefix is *not* guessed (ambiguous with decimal), and
    ``space:0x10``. Returns ``None`` for values that are not addresses.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"0x{value:x}" if value >= 0 else None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if s.lower().endswith("h") and re.fullmatch(r"[0-9a-fA-F]+h", s, re.IGNORECASE):
        return f"0x{int(s[:-1], 16):x}"
    m = _ADDR_RE.match(s.replace("0X", "0x"))
    if not m:
        return None
    hex_part = f"{int(m.group('hex'), 16):x}"
    space = m.group("space")
    return f"{space}:0x{hex_part}" if space else f"0x{hex_part}"


def addr_sort_key(addr: str) -> tuple[str, int]:
    m = _ADDR_RE.match(addr)
    if not m:
        return ("~", 0)
    return (m.group("space") or "", int(m.group("hex"), 16))


def validate_export(doc: Any) -> list[str]:
    """Return problems with an export document (empty list = usable)."""
    if not isinstance(doc, dict):
        return ["export must be a JSON object"]
    errors: list[str] = []
    if doc.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA!r}, got {doc.get('schema')!r}")
    program = doc.get("program")
    if not isinstance(program, dict) or not program.get("name"):
        errors.append("program.name is required")
    for key in ("functions", "calls", "imports", "exports", "strings", "data", "segments"):
        value = doc.get(key, [])
        if not isinstance(value, list):
            errors.append(f"{key} must be a list")
            continue
        for i, item in enumerate(value):
            if not isinstance(item, dict):
                errors.append(f"{key}[{i}] must be an object")
                break
    for i, fn in enumerate(doc.get("functions", []) or []):
        if isinstance(fn, dict) and canon_addr(fn.get("address")) is None:
            errors.append(f"functions[{i}] has no usable address: {fn.get('address')!r}")
            break
    return errors


def empty_export(program_name: str, **program: Any) -> dict[str, Any]:
    """A valid, empty export — the starting point for adapters."""
    return {
        "schema": SCHEMA,
        "producer": {"name": "graphify-ghidra"},
        "program": {"name": program_name, **program},
        "segments": [],
        "functions": [],
        "calls": [],
        "imports": [],
        "exports": [],
        "strings": [],
        "data": [],
    }
