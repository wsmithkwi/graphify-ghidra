"""In-memory view of a Ghidra-bearing ``graphify-out`` for the tool layer.

Loads ``graph.json`` once (reloading when the file changes), indexes it for the
questions tools ask - callers/callees, references, similar neighbours, who is
named, what lives at an address - and resolves the loose references an agent
produces (``0x1400..``, ``scope:0x1400..``, a node id, a function name).
"""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .annotations import AnnotationStore, load_stores
from .model import canon_addr

__all__ = ["Workspace", "NotFound", "Ambiguous", "NoGhidraData", "resolve_out", "has_ghidra_data", "DEFAULT_OUT_NAME"]

FN_KINDS = ("function", "thunk")

#: Where Ghidra graphs live unless told otherwise. Deliberately NOT ``graphify-out``: in a project that already
#: has a graphify graph (of source code, say) that folder is the user's, and a binary analysis must not be merged
#: into it unless they ask.
DEFAULT_OUT_NAME = "graphify-out-ghidra"


def has_ghidra_data(out: str | Path) -> bool:
    """True when ``out`` holds a graph built by graphify-ghidra (it writes ``ghidra/<scope>.summary.json``)."""
    d = Path(out) / "ghidra"
    try:
        return d.is_dir() and any(d.glob("*.summary.json"))
    except OSError:
        return False


def resolve_out(base: str | Path | None = None, explicit: str | Path | None = None) -> Path:
    """The folder graphify-ghidra reads and writes.

    ``explicit`` > ``$GRAPHIFY_GHIDRA_OUT`` > an existing ``<base>/graphify-out`` that already has Ghidra data
    (older installs) > ``<base>/graphify-out-ghidra``.
    """
    if explicit:
        return Path(explicit)
    env = os.environ.get("GRAPHIFY_GHIDRA_OUT")
    if env:
        return Path(env)
    root = Path(base) if base else Path.cwd()
    for name in ("graphify-out", DEFAULT_OUT_NAME):
        if has_ghidra_data(root / name):
            return root / name
    return root / DEFAULT_OUT_NAME
_GHIDRA_NAMED_SOURCES = {"USER_DEFINED", "IMPORTED", "ANALYSIS"}


class NotFound(LookupError):
    pass


class Ambiguous(LookupError):
    def __init__(self, ref: str, options: list[str]) -> None:
        super().__init__(f"{ref!r} is ambiguous")
        self.ref, self.options = ref, options


class NoGhidraData(RuntimeError):
    pass


class Workspace:
    def __init__(self, out_dir: str | Path) -> None:
        self.out = Path(out_dir)
        self.graph_path = self.out / "graph.json"
        self._mtime: float | None = None
        self.graph: dict[str, Any] = {}
        self.nodes: dict[str, dict[str, Any]] = {}
        self.fn_key: dict[tuple[str, str], str] = {}
        self.data_key: dict[tuple[str, str], str] = {}
        self.scopes: dict[str, dict[str, Any]] = {}
        self.calls_out: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        self.calls_in: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        self.refs_out: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        self.refs_in: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        self.sim: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        self.shares: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        self.caps: dict[str, list[str]] = defaultdict(list)
        self.stores: dict[str, AnnotationStore] = {}
        self._live: dict[str, Any] = {}
        self._ranges: dict[str, list[tuple[int, str]]] = {}

    # ---------------------------------------------------------------- loading
    def ensure(self) -> "Workspace":
        if not self.graph_path.is_file():
            raise NoGhidraData(f"No Ghidra analysis found in {self.out}.")
        mtime = self.graph_path.stat().st_mtime
        if self._mtime != mtime:
            self._load()
            self._mtime = mtime
        self.stores = {s: AnnotationStore.open(self.out, s) for s in self.scopes}
        return self

    def reload(self) -> None:
        self._mtime = None
        self.ensure()

    def _load(self) -> None:
        self.graph = json.loads(self.graph_path.read_text(encoding="utf-8"))
        self.nodes = {n["id"]: n for n in self.graph.get("nodes", [])}
        for d in (self.fn_key, self.data_key, self.scopes, self.calls_out, self.calls_in, self.refs_out,
                  self.refs_in, self.sim, self.shares, self.caps, self._ranges):
            d.clear()
        for nid, n in self.nodes.items():
            m = n.get("metadata") or {}
            kind, scope, addr = m.get("ghidra_kind"), m.get("scope"), m.get("address")
            if kind in FN_KINDS and scope and addr:
                self.fn_key[(scope, addr)] = nid
            elif kind == "data" and scope and addr:
                self.data_key[(scope, addr)] = nid
            elif kind == "binary" and scope:
                self.scopes[scope] = {"name": n.get("label"), "sha256": m.get("sha256"), "binary_id": nid,
                                      "source_file": n.get("source_file"), "language": m.get("language")}
        if not self.scopes:
            raise NoGhidraData(f"{self.graph_path} is a graph without any analysed binary in it (an ordinary "
                               "graphify graph, left untouched).")
        for e in self.graph.get("links", self.graph.get("edges", [])):
            s, t = e.get("_src", e.get("source")), e.get("_tgt", e.get("target"))
            rel = e.get("relation")
            if rel in ("calls", "thunks_to"):
                self.calls_out[s].append((t, e))
                self.calls_in[t].append((s, e))
            elif rel == "references":
                self.refs_out[s].append((t, e))
                self.refs_in[t].append((s, e))
            elif rel == "semantically_similar_to":
                self.sim[s].append((t, e))
                self.sim[t].append((s, e))
            elif rel == "shares_data_with":
                self.shares[s].append((t, e))
                self.shares[t].append((s, e))
            elif rel == "exhibits":
                self.caps[s].append(t)

    # ---------------------------------------------------------------- scopes
    def pick_scope(self, binary: str | None = None) -> str:
        if binary:
            b = binary.lower()
            hits = [s for s, i in self.scopes.items() if s.lower() == b or str(i["name"]).lower() == b]
            hits = hits or [s for s, i in self.scopes.items() if b in s.lower() or b in str(i["name"]).lower()]
            if len(hits) == 1:
                return hits[0]
            raise NotFound(f"binary {binary!r} matches {len(hits)} of: {', '.join(self.scopes)}")
        if len(self.scopes) == 1:
            return next(iter(self.scopes))
        raise Ambiguous("binary", list(self.scopes))

    # -------------------------------------------------------------- resolving
    def meta(self, nid: str) -> dict[str, Any]:
        return self.nodes[nid].get("metadata") or {}

    def resolve(self, ref: Any, binary: str | None = None, kinds: tuple[str, ...] = FN_KINDS) -> str:
        if not isinstance(ref, str) or not ref.strip():
            raise NotFound("empty reference")
        ref = ref.strip()
        if ref in self.nodes and self.meta(ref).get("ghidra_kind") in kinds:
            return ref
        scopes = list(self.scopes)
        if binary:
            scopes = [self.pick_scope(binary)]
        table = self.fn_key if "function" in kinds else self.data_key
        if ":0x" in ref and not ref.startswith("0x"):
            scope, _, a = ref.rpartition(":")
            c = canon_addr(a)
            if (scope, c) in table:
                return table[(scope, c)]
        addr = canon_addr(ref)
        if addr:
            hits = [table[(s, addr)] for s in scopes if (s, addr) in table]
            if "function" in kinds and not hits:
                hits = [fid for s in scopes if (fid := self._containing(s, addr))]
            if len(hits) == 1:
                return hits[0]
            if len(hits) > 1:
                raise Ambiguous(ref, [f"{self.meta(h)['scope']}:{addr}" for h in hits])
            raise NotFound(f"no {'function' if 'function' in kinds else 'data'} at {addr}")
        # by name
        low = ref.lower().split(" @")[0]
        exact, loose = [], []
        for nid, n in self.nodes.items():
            m = n.get("metadata") or {}
            if m.get("ghidra_kind") not in kinds or (binary and m.get("scope") not in scopes):
                continue
            names = {str(n.get("label", "")).split(" @")[0].lower(), str(m.get("original_label", "")).lower()}
            if low in names:
                exact.append(nid)
            elif low in str(n.get("label", "")).lower():
                loose.append(nid)
        hits = exact or loose
        if len(hits) == 1:
            return hits[0]
        if not hits:
            raise NotFound(f"nothing named {ref!r}")
        raise Ambiguous(ref, [f"{self.meta(h)['scope']}:{self.meta(h)['address']} {self.nodes[h]['label']}" for h in hits[:10]])

    def _containing(self, scope: str, addr: str) -> str | None:
        """The function whose body contains ``addr`` (entry addresses are handled by the table)."""
        import bisect
        ranges = self._ranges.get(scope)
        if ranges is None:
            ranges = sorted((int(a[2:], 16), nid) for (s, a), nid in self.fn_key.items()
                            if s == scope and re.fullmatch(r"0x[0-9a-f]+", a))
            self._ranges[scope] = ranges
        if not re.fullmatch(r"0x[0-9a-f]+", addr or ""):
            return None
        v = int(addr[2:], 16)
        i = bisect.bisect_right(ranges, (v, "￿")) - 1
        if i < 0:
            return None
        start, nid = ranges[i]
        size = int(self.meta(nid).get("size_bytes") or 0)
        return nid if start <= v < start + max(size, 1) else None

    # ------------------------------------------------------------- predicates
    def is_named(self, nid: str) -> bool:
        m = self.meta(nid)
        return bool(m.get("ai_name") or m.get("name_source") in _GHIDRA_NAMED_SOURCES
                    or "library" in (m.get("roles") or []))

    def named_by(self, nid: str) -> str | None:
        m = self.meta(nid)
        if m.get("ai_name"):
            return m.get("named_by") or "ai"
        if m.get("name_source") == "USER_DEFINED":
            return "analyst"
        if "library" in (m.get("roles") or []):
            return "library"
        if m.get("name_source") in _GHIDRA_NAMED_SOURCES:
            return "ghidra"
        return None

    def display(self, nid: str) -> str:
        n = self.nodes[nid]
        m = n.get("metadata") or {}
        label = str(n.get("label", nid)).split(" @")[0]
        addr = m.get("address")
        return label if addr and addr[2:] in label else f"{label} ({addr})" if addr else label

    def functions(self, scope: str | None = None) -> list[str]:
        return [nid for (s, _a), nid in self.fn_key.items() if scope is None or s == scope]

    def auto_label(self, nid: str) -> str:
        m = self.meta(nid)
        return str(m.get("original_label") or self.nodes[nid].get("label"))

    # ------------------------------------------------------------------ live
    def live_backend(self, scope: str):
        from .ghidra_server import LiveBackend
        if scope not in self._live:
            self._live[scope] = LiveBackend(self.out / "ghidra" / scope / "project")
        return self._live[scope]

    def close(self) -> None:
        for lb in self._live.values():
            try:
                lb.stop()
            except Exception:
                pass
        self._live.clear()
