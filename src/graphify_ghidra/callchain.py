"""Call-chain queries over a graphify graph built from Ghidra data.

Why this exists: in the full graph every function, import and string hangs off
the binary node, so a plain shortest-path query between two functions finds the
useless two-hop route ``fn <- binary -> import`` instead of the real chain of
calls. These queries walk **only call edges** (``calls`` and ``thunks_to``), so
the answer to "how does ``entry`` reach ``CryptEncrypt``?" is a call chain.

Direction comes from graphify's ``_src``/``_tgt`` edge attributes when present,
so the queries are correct even if the graph was saved undirected.
"""

from __future__ import annotations

import json
from collections import deque
from itertools import islice
from pathlib import Path
from typing import Any

import networkx as nx

__all__ = ["CallGraph", "load_call_graph", "AmbiguousNode"]

CALL_RELATIONS = {"calls", "thunks_to"}


class AmbiguousNode(LookupError):
    def __init__(self, query: str, candidates: list[str]) -> None:
        super().__init__(f"{query!r} matches {len(candidates)} nodes")
        self.query = query
        self.candidates = candidates


class CallGraph:
    def __init__(self, nodes: dict[str, dict[str, Any]], calls: nx.DiGraph, exhibits: dict[str, set[str]]):
        self.nodes = nodes
        self.calls = calls
        self.exhibits = exhibits      # capability node id -> {function/import node ids}

    # ------------------------------------------------------------ resolution
    def label(self, nid: str) -> str:
        n = self.nodes.get(nid, {})
        meta = n.get("metadata") or {}
        addr = meta.get("address") or n.get("source_location")
        label = n.get("label") or nid
        return f"{label} [{addr}]" if addr and meta.get("ghidra_kind") in {"function", "thunk"} else str(label)

    def resolve(self, query: str) -> list[str]:
        """Resolve a user query to node ids: id, address, exact label, then substring."""
        q = query.strip()
        if q in self.nodes:
            return [q]
        ql = q.lower()
        by_addr = [i for i, n in self.nodes.items()
                   if str((n.get("metadata") or {}).get("address", "")).lower() == ql]
        if by_addr:
            return by_addr
        exact = [i for i, n in self.nodes.items() if str(n.get("label", "")).lower() == ql
                 or str(n.get("label", "")).lower().split(" @")[0] == ql]
        if exact:
            return exact
        return [i for i, n in self.nodes.items() if ql in str(n.get("label", "")).lower()]

    def resolve_one(self, query: str) -> str:
        found = self.resolve(query)
        if not found:
            raise KeyError(f"no node matches {query!r}")
        if len(found) > 1:
            # Prefer functions over imports/strings when a name is shared.
            funcs = [i for i in found if (self.nodes[i].get("metadata") or {}).get("ghidra_kind") in {"function", "thunk"}]
            if len(funcs) == 1:
                return funcs[0]
            raise AmbiguousNode(query, found)
        return found[0]

    def targets_for(self, query: str) -> list[str]:
        """Targets a chain may end at. A capability expands to everything that exhibits it."""
        nid = self.resolve_one(query)
        if (self.nodes[nid].get("metadata") or {}).get("ghidra_kind") == "capability":
            return sorted(self.exhibits.get(nid, ()))
        return [nid]

    # --------------------------------------------------------------- queries
    def chains(self, source: str, target: str, k: int = 3, max_len: int = 40) -> list[list[str]]:
        src = self.resolve_one(source)
        targets = [t for t in self.targets_for(target) if t in self.calls and t != src]
        if src not in self.calls or not targets:
            return []
        # One virtual sink lets shortest_simple_paths rank chains to *any* target.
        g = self.calls.copy()
        sink = "\0sink"
        for t in targets:
            g.add_edge(t, sink)
        out: list[list[str]] = []
        try:
            for path in islice(nx.shortest_simple_paths(g, src, sink), k):
                chain = path[:-1]
                if len(chain) <= max_len:
                    out.append(chain)
        except nx.NetworkXNoPath:
            return []
        return out

    def callers_tree(self, query: str, depth: int = 4, limit: int = 60) -> list[tuple[int, str]]:
        """Breadth-first callers of a function/import, as ``(depth, node_id)`` rows."""
        start = self.resolve_one(query)
        rows: list[tuple[int, str]] = []
        seen = {start}
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        while queue and len(rows) < limit:
            cur, d = queue.popleft()
            if d >= depth:
                continue
            for caller in sorted(self.calls.predecessors(cur)) if cur in self.calls else []:
                if caller in seen:
                    continue
                seen.add(caller)
                rows.append((d + 1, caller))
                queue.append((caller, d + 1))
        return rows

    def is_entry(self, nid: str) -> bool:
        meta = (self.nodes.get(nid) or {}).get("metadata") or {}
        return "entry" in (meta.get("roles") or [])


def load_call_graph(graph_path: str | Path) -> CallGraph:
    data = json.loads(Path(graph_path).read_text(encoding="utf-8"))
    nodes = {n["id"]: n for n in data.get("nodes", [])}
    calls = nx.DiGraph()
    exhibits: dict[str, set[str]] = {}
    for e in data.get("links", data.get("edges", [])):
        src = e.get("_src", e.get("source"))
        dst = e.get("_tgt", e.get("target"))
        rel = e.get("relation")
        if src not in nodes or dst not in nodes:
            continue
        if rel in CALL_RELATIONS:
            calls.add_edge(src, dst, **{k: e.get(k) for k in ("confidence", "context", "weight")})
        elif rel == "exhibits":
            exhibits.setdefault(dst, set()).add(src)
    return CallGraph(nodes, calls, exhibits)
