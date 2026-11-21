"""An indexed, normalised view of one ``graphify-ghidra/1`` export.

:class:`Program` does the bookkeeping that every later stage needs and none
should repeat: canonical addresses, the call graph as aggregated adjacency,
imports keyed by library+name, string references, and the per-function
capability evidence. It makes no judgement about *importance* (that is
:mod:`graphify_ghidra.analysis`) and emits no graph nodes (that is
:mod:`graphify_ghidra.ingest`).

Provenance matters for reverse engineering, so each fact keeps the strength of
its source. A direct ``CALL`` that Ghidra resolved is an observation; a
computed call whose target came from a pointer slot is weaker, and the call
aggregate remembers which it is so the ingester can pick ``EXTRACTED`` or
``INFERRED`` honestly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .capabilities import classify_api, classify_string
from .model import ExportError, canon_addr, validate_export

__all__ = ["Program", "CallAgg", "ProgramOptions", "import_key", "norm_library"]

_DIRECT_KINDS = {
    "UNCONDITIONAL_CALL", "CONDITIONAL_CALL", "CALL", "DIRECT_CALL", "CALL_OVERRIDE_UNCONDITIONAL",
    "IMPORT_CALL",
}
_JUNK_STRING = re.compile(r"^[\W_]{0,3}$")


def norm_library(name: str | None) -> str:
    """``KERNEL32.DLL`` -> ``kernel32``; ``libc.so.6`` -> ``libc.so.6``."""
    if not name:
        return "unknown"
    n = name.strip().lower()
    for suffix in (".dll", ".exe", ".sys", ".ocx", ".drv"):
        if n.endswith(suffix):
            return n[: -len(suffix)]
    return n


def import_key(library: str | None, name: str) -> str:
    return f"{norm_library(library)}::{name}"


@dataclass
class ProgramOptions:
    """Knobs that decide what the graph will contain.

    ``strings`` is the most consequential: a large binary has tens of thousands
    of strings and most are noise (CRT messages, padding, GUIDs). The default
    keeps strings that code actually references, plus anything matching an IOC
    or capability pattern, so the graph stays navigable.
    """

    strings: str = "referenced"        # none | referenced | interesting | all
    min_string_len: int = 4
    max_strings: int = 4000
    include_segments: bool = True
    include_data: bool = True
    include_thunks: bool = True
    include_capabilities: bool = True
    include_types: bool = True          # datatype nodes + function->type edges (struct-level mapping)
    include_variables: bool = True      # variable nodes for params/locals an analyst already named
    shares_data_edges: bool = True      # writer -> reader `shares_data_with` edges through globals
    similarity: bool = True             # functional-similarity edges (see similarity.py)
    capability_hyperedges: bool = True
    min_capability_members: int = 3
    max_hyperedge_members: int = 60

    def __post_init__(self) -> None:
        if self.strings not in {"none", "referenced", "interesting", "all"}:
            raise ValueError(f"strings must be none|referenced|interesting|all, got {self.strings!r}")


@dataclass
class CallAgg:
    """All call sites from one function to one target, aggregated."""

    count: int = 0
    kinds: set[str] = field(default_factory=set)
    sites: list[str] = field(default_factory=list)
    direct: bool = False
    via_thunks: set[str] = field(default_factory=set)

    def add(self, kind: str | None, site: str | None, via_thunk: str | None) -> None:
        self.count += 1
        if kind:
            self.kinds.add(kind)
            if kind.upper() in _DIRECT_KINDS:
                self.direct = True
        else:
            # Producer gave no kind (e.g. a flat REA edge list): treat as direct,
            # it was resolved by the provider, not by us.
            self.direct = True
        if site and len(self.sites) < 16 and site not in self.sites:
            self.sites.append(site)
        if via_thunk:
            self.via_thunks.add(via_thunk)


class Program:
    def __init__(self, doc: dict[str, Any], options: ProgramOptions | None = None) -> None:
        errors = validate_export(doc)
        if errors:
            raise ExportError("; ".join(errors[:5]))
        self.options = options or ProgramOptions()
        self.doc = doc
        info = doc["program"]
        self.info = info
        self.name: str = str(info["name"])
        self.sha256: str | None = info.get("sha256")
        self.source_file: str = _clean_path(info.get("executable_path") or self.name)
        self.producer = doc.get("producer") or {}

        self.functions: dict[str, dict[str, Any]] = {}
        self.order: list[str] = []
        self.call_edges: dict[tuple[str, str], CallAgg] = {}
        self.external_calls: dict[tuple[str, str], CallAgg] = {}
        self.imports: dict[str, dict[str, Any]] = {}
        self.unresolved_calls: list[dict[str, Any]] = []
        self.strings: dict[str, dict[str, Any]] = {}
        self.fn_strings: dict[str, set[str]] = {}
        self.data: dict[str, dict[str, Any]] = {}
        self.fn_data: dict[str, set[str]] = {}
        self.fn_caps: dict[str, dict[str, set[str]]] = {}
        self.callees: dict[str, set[str]] = {}
        self.callers: dict[str, set[str]] = {}
        self.entry_points: list[str] = []
        self.exports: list[dict[str, Any]] = []
        self.segments: list[dict[str, Any]] = []

        self._load_functions()
        self._load_imports()
        self._load_calls()
        self._load_strings()
        self._load_data()
        self._load_exports_and_entries()
        self._derive_capabilities()
        self.segments = [s for s in doc.get("segments", []) if isinstance(s, dict) and s.get("name")]

    # ------------------------------------------------------------------ load

    def _load_functions(self) -> None:
        for raw in self.doc.get("functions", []):
            addr = canon_addr(raw.get("address"))
            if addr is None or raw.get("is_external"):
                continue  # external functions are modelled as imports
            if addr in self.functions:
                continue
            fn = dict(raw)
            fn["address"] = addr
            fn["name"] = str(raw.get("name") or f"FUN_{addr[2:]}")
            _classify_comment(fn)
            self.functions[addr] = fn
            self.order.append(addr)

    def _load_imports(self) -> None:
        for raw in self.doc.get("imports", []):
            name = raw.get("name") or raw.get("label")
            if not name:
                continue
            self._register_import(str(name), raw.get("library"), raw.get("address"))

    def _register_import(self, name: str, library: str | None, address: Any = None) -> str:
        key = import_key(library, name)
        if key not in self.imports:
            self.imports[key] = {
                "name": name,
                "library": library or "unknown",
                "lib_norm": norm_library(library),
                "address": canon_addr(address),
                "capabilities": classify_api(name),
            }
        return key

    def _load_calls(self) -> None:
        for raw in self.doc.get("calls", []):
            src = canon_addr(raw.get("from"))
            if src is None or src not in self.functions:
                continue
            site = canon_addr(raw.get("call_site"))
            via = canon_addr(raw.get("via_thunk"))
            kind = raw.get("kind")
            if raw.get("unresolved"):
                self.unresolved_calls.append(
                    {"from": src, "call_site": site, "target_address": canon_addr(raw.get("target_address")),
                     "reason": raw.get("reason")}
                )
                continue
            if raw.get("external_name"):
                key = self._register_import(str(raw["external_name"]), raw.get("external_library"),
                                            raw.get("external_address"))
                # A call through an import slot is "computed" in Ghidra's flow types, but the
                # slot is filled by the loader, so the target is fixed: an observation.
                self.external_calls.setdefault((src, key), CallAgg()).add("IMPORT_CALL", site, via)
                continue
            dst = canon_addr(raw.get("to"))
            if dst is None or dst not in self.functions:
                continue
            self.call_edges.setdefault((src, dst), CallAgg()).add(kind, site, via)
        # Flat producers (REA) may list api_calls per function instead of calls.
        for addr, fn in self.functions.items():
            for api in fn.get("api_calls") or []:
                if not isinstance(api, str):
                    continue
                matched = [k for (s, k) in self.external_calls if s == addr and self.imports[k]["name"] == api]
                if matched:
                    continue
                key = self._find_import_by_name(api) or self._register_import(api, None)
                self.external_calls.setdefault((addr, key), CallAgg()).add(None, None, None)
        for (src, dst) in self.call_edges:
            self.callees.setdefault(src, set()).add(dst)
            self.callers.setdefault(dst, set()).add(src)

    def _find_import_by_name(self, name: str) -> str | None:
        for key, imp in self.imports.items():
            if imp["name"] == name:
                return key
        return None

    def _load_strings(self) -> None:
        for raw in self.doc.get("strings", []):
            addr = canon_addr(raw.get("address"))
            value = raw.get("value")
            if addr is None or not isinstance(value, str):
                continue
            refs = {canon_addr(r) for r in raw.get("refs") or []}
            refs.discard(None)
            self.strings[addr] = {
                "address": addr,
                "value": value,
                "refs": {r for r in refs if r in self.functions},
                "length": raw.get("length"),
                "capabilities": classify_string(value),
                "truncated": bool(raw.get("truncated")),
            }
        # Function-side string_refs are authoritative when the string table
        # omits refs (flat producers).
        for addr, fn in self.functions.items():
            for sref in fn.get("string_refs") or []:
                s = canon_addr(sref)
                if s and s in self.strings:
                    self.strings[s]["refs"].add(addr)
        for s_addr, s in self.strings.items():
            for f_addr in s["refs"]:
                self.fn_strings.setdefault(f_addr, set()).add(s_addr)

    def _load_data(self) -> None:
        for raw in self.doc.get("data", []):
            addr = canon_addr(raw.get("address"))
            if addr is None or not raw.get("name"):
                continue
            refs = {canon_addr(r) for r in raw.get("refs") or []}
            self.data[addr] = {
                "address": addr, "name": str(raw["name"]), "type": raw.get("type"),
                "size": raw.get("size"), "user_named": bool(raw.get("user_named")),
                "refs": {r for r in refs if r in self.functions}, "writers": set(),
            }
        for addr, fn in self.functions.items():
            for dref in fn.get("data_refs") or []:
                d = canon_addr(dref)
                if d and d in self.data:
                    self.data[d]["refs"].add(addr)
            for dref in fn.get("data_writes") or []:
                d = canon_addr(dref)
                if d and d in self.data:
                    self.data[d]["refs"].add(addr)
                    self.data[d]["writers"].add(addr)
        for d_addr, d in self.data.items():
            for f_addr in d["refs"]:
                self.fn_data.setdefault(f_addr, set()).add(d_addr)

    def _load_exports_and_entries(self) -> None:
        for raw in self.doc.get("exports", []):
            addr = canon_addr(raw.get("address"))
            if addr is None:
                continue
            self.exports.append({"address": addr, "name": raw.get("name") or addr,
                                 "is_function": addr in self.functions})
        seen: set[str] = set()
        for addr in self.order:
            if self.functions[addr].get("is_entry") and addr not in seen:
                self.entry_points.append(addr)
                seen.add(addr)
        for exp in self.exports:
            if exp["address"] in self.functions and exp["address"] not in seen:
                self.entry_points.append(exp["address"])
                seen.add(exp["address"])

    def _derive_capabilities(self) -> None:
        for (src, key), _agg in self.external_calls.items():
            name = self.imports[key]["name"]
            for cap in self.imports[key]["capabilities"]:
                self.fn_caps.setdefault(src, {}).setdefault(cap, set()).add(name)
        for f_addr, s_addrs in self.fn_strings.items():
            for s_addr in s_addrs:
                for cap in self.strings[s_addr]["capabilities"]:
                    self.fn_caps.setdefault(f_addr, {}).setdefault(cap, set()).add(f"string:{s_addr}")

    # --------------------------------------------------------------- queries

    def keep_string(self, s: dict[str, Any]) -> bool:
        """Apply the ``strings`` option to one string record."""
        mode = self.options.strings
        value = s["value"]
        if mode == "none":
            return False
        if len(value) < self.options.min_string_len or _JUNK_STRING.match(value):
            return False
        if mode == "all":
            return True
        if mode == "referenced":
            return bool(s["refs"]) or bool(s["capabilities"])
        # interesting: only strings that look like indicators or hit a capability rule
        return bool(s["capabilities"])

    def function_label(self, addr: str) -> str:
        """A unique, human-readable label (name, disambiguated by address)."""
        fn = self.functions[addr]
        name = fn["name"]
        dup = self._label_counts().get(name, 0) > 1
        return f"{name} @{addr}" if dup else name

    def _label_counts(self) -> dict[str, int]:
        if not hasattr(self, "_label_cache"):
            counts: dict[str, int] = {}
            for fn in self.functions.values():
                counts[fn["name"]] = counts.get(fn["name"], 0) + 1
            self._label_cache = counts
        return self._label_cache


def _classify_comment(fn: dict[str, Any]) -> None:
    """Separate tool-generated comments from analyst notes.

    Ghidra's Function ID analyzer stamps matched statically-linked library code
    with a plate comment starting ``Library Function - ...``. That is a
    *machine* annotation: it tells a reverse engineer which functions to skip
    (CRT, STL, compiler runtime), the opposite of "an analyst cared about this".
    We surface it as ``library_match`` and leave ``comment`` for human notes.
    """
    for key in ("comment", "repeatable_comment"):
        text = fn.get(key)
        if isinstance(text, str) and text.lstrip().startswith("Library Function"):
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            libs = ""
            for ln in lines:
                if ln.lower().startswith(("library:", "libraries:")):
                    libs = ln.split(":", 1)[1].strip()
            fn["is_library"] = True
            fn["library_match"] = (lines[0] + (f" ({libs})" if libs else ""))[:300]
            fn.pop(key, None)
    if not fn.get("is_library") and fn.get("name_source") == "ANALYSIS" and fn.get("name", "").startswith("FID_conflict"):
        fn["is_library"] = True


def _clean_path(path: str) -> str:
    """Ghidra reports ``/C:/Windows/x.exe``; normalise to ``C:/Windows/x.exe``."""
    p = str(path).replace("\\", "/")
    if re.match(r"^/[A-Za-z]:/", p):
        p = p[1:]
    return p
