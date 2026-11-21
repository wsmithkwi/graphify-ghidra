"""Persist a Ghidra extraction into a graphify graph.

Uses graphify's own ``build_merge`` / ``cluster`` / ``to_json`` so the result
is an ordinary ``graphify-out/graph.json``: every graphify consumer (the MCP
server, ``graphify query``, the HTML view, wiki export) works on it unchanged,
and a binary's graph can live in the same file as the source-code graph of the
project that built (or is being compared against) it.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .report import render_report

__all__ = ["WriteResult", "write_extraction", "ForeignGraphError"]


class ForeignGraphError(RuntimeError):
    """The target graph.json exists but holds no analysed binary (it is someone else's graph)."""


@dataclass
class WriteResult:
    graph_path: Path
    report_path: Path
    nodes: int
    edges: int
    communities: int
    written: bool
    message: str = ""
    similarity: dict | None = None


def write_extraction(
    extraction: dict[str, Any],
    out_dir: str | Path = "graphify-out",
    *,
    force: bool = False,
    directed: bool | None = None,
    root: str | Path | None = None,
    engine: str = "auto",
    allow_foreign_merge: bool = False,
) -> WriteResult:
    """Merge ``extraction`` into ``<out_dir>/graph.json`` and write sidecars.

    ``directed`` defaults to ``True`` for a brand-new graph (caller vs callee
    matters a great deal in a call graph) and otherwise follows the graph
    already on disk, so merging never silently flips an existing graph.
    """
    from graphify.build import build_merge
    from graphify.cluster import cluster, label_communities_by_hub
    from graphify.export import to_json

    out = Path(out_dir)
    graph_path = out / "graph.json"
    ghidra = extraction.get("ghidra") or {}
    if graph_path.is_file() and not allow_foreign_merge and not _graph_has_binary(graph_path):
        # e.g. a project's own graphify graph of its source code. Merging rewrites that file (and a
        # re-ingest can replace content), so never do it by accident.
        raise ForeignGraphError(
            f"{graph_path} already holds a graph with no analysed binary in it, so it was not touched. "
            "Ghidra graphs default to their own folder (graphify-out-ghidra); pass --out to choose another, or "
            "--merge-into-existing if you really want the binary merged into that graph.")
    out.mkdir(parents=True, exist_ok=True)

    if directed is None and not graph_path.exists():
        directed = True

    # The ghidra block is ours; graphify must not see unknown top-level keys
    # leak into node-link data.
    chunk = {k: v for k, v in extraction.items() if k != "ghidra"}
    sim_summary = _add_similarity(chunk, ghidra, out, engine=engine)
    _carry_shared_nodes(chunk, graph_path)
    G = build_merge([chunk], graph_path, directed=directed, root=root)
    # The binary, its libraries and the capability concepts touch everything; left in,
    # they glue unrelated subsystems into one community. graphify can set such hubs
    # aside during partitioning and reattach them by neighbour vote afterwards.
    if G.number_of_nodes() > 100:
        communities = cluster(G, exclude_hubs_percentile=99)
    else:
        communities = cluster(G)
    labels = label_communities_by_hub(G, communities)

    written = to_json(G, communities, str(graph_path), force=force, community_labels=labels)
    message = ""
    if not written:
        message = ("graphify refused to overwrite graph.json because the merged graph is smaller "
                   "than the existing one. Re-run with --force if the shrink is expected "
                   "(for example, after re-ingesting with fewer strings).")

    # Sidecars: full pseudo-code (graph metadata is length-capped by graphify).
    for rel, text in (ghidra.get("sidecars") or {}).items():
        target = (out / rel).resolve()
        if out.resolve() not in target.parents:
            continue  # never write outside the output dir, whatever the producer sent
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    if written:
        patch_graph(out)   # re-apply names / behaviours / links: a re-ingest resets labels

    scope = ghidra.get("scope") or "program"
    report_path = out / f"GHIDRA_REPORT_{scope}.md"
    if ghidra:
        report_path.write_text(render_report(ghidra), encoding="utf-8")
        (out / "ghidra").mkdir(exist_ok=True)
        (out / "ghidra" / f"{scope}.summary.json").write_text(
            json.dumps({"program": ghidra.get("program"), "summary": ghidra.get("summary"),
                        "ranked": ghidra.get("ranked"), "libraries": ghidra.get("libraries")},
                       indent=2),
            encoding="utf-8",
        )

    return WriteResult(graph_path, report_path, G.number_of_nodes(), G.number_of_edges(),
                       len(communities), bool(written), message, sim_summary)


def _graph_has_binary(graph_path: Path) -> bool:
    try:
        data = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return True      # unreadable: let graphify's own handling report it rather than guess
    return any((n.get("metadata") or {}).get("ghidra_kind") == "binary" for n in data.get("nodes", []))


def patch_graph(out_dir: str | Path) -> dict[str, int]:
    """Re-apply every annotation store to ``<out_dir>/graph.json`` in place (atomic).

    Only graphify's own file format is touched, via plain JSON, so a graph that
    other tools (``graphify-mcp``, the HTML view) are reading stays valid.
    """
    from .annotations import load_stores, reapply
    graph_path = Path(out_dir) / "graph.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    counts = reapply(graph, load_stores(out_dir))
    fd, tmp = tempfile.mkstemp(dir=graph_path.parent, prefix=".graph-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(graph, fh, ensure_ascii=False)
        os.replace(tmp, graph_path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return counts


def _add_similarity(chunk: dict[str, Any], ghidra: dict[str, Any], out: Path, *, engine: str) -> dict[str, Any]:
    """Index this binary's features and add similarity edges within and across binaries."""
    from .similarity import Params, describe, find_similar

    features = ghidra.get("features") or []
    scope = ghidra.get("scope")
    if not features or not scope:
        return {}
    index_dir = out / "ghidra" / "index"
    index_dir.mkdir(parents=True, exist_ok=True)
    with (index_dir / f"{scope}.jsonl").open("w", encoding="utf-8") as fh:
        for rec in features:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")

    records = list(features)
    other_scopes = []
    for p in sorted(index_dir.glob("*.jsonl")):
        if p.stem == scope:
            continue
        other_scopes.append(p.stem)
        with p.open(encoding="utf-8") as fh:
            records.extend(json.loads(line) for line in fh if line.strip())
    edges = find_similar(records, params=Params(), query_scope=scope, engine=engine)
    src_file = next((n["source_file"] for n in chunk["nodes"] if n.get("source_file")), "")
    for e in edges:
        chunk["edges"].append({
            "source": e["a"], "target": e["b"], "relation": "semantically_similar_to", "confidence": "INFERRED",
            "confidence_score": e["score"], "source_file": src_file, "source_location": None, "weight": e["score"],
            "context": "similar code: " + describe(e),
        })
    return {"similar_edges": len(edges), "compared_scopes": other_scopes, "engine": _engine_name(engine)}


_SHARED_KINDS = {"import", "library", "capability", "datatype"}


def _carry_shared_nodes(chunk: dict[str, Any], graph_path: Path) -> int:
    """Keep shared nodes that other binaries still point at.

    Imports, libraries, capabilities and datatypes have global ids so that binaries
    share them. graphify, however, attributes a node to one source file and *replaces*
    a file's whole contribution on re-ingest. If binary A "owns" the shared node
    ``capability_privilege`` and is re-ingested without it (different options, or a new
    build that no longer needs it), graphify would drop the node and then silently delete
    binary B's edges to it. So any shared node this binary owns, is about to lose, and
    that another binary's edges still reference is carried into the new chunk.
    """
    if not graph_path.is_file():
        return 0
    src_file = next((n["source_file"] for n in chunk["nodes"] if n.get("source_file")), None)
    if not src_file:
        return 0
    try:
        existing = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    have = {n["id"] for n in chunk["nodes"]}
    owned = {n["id"]: n for n in existing.get("nodes", [])
             if n.get("source_file") == src_file and (n.get("metadata") or {}).get("ghidra_kind") in _SHARED_KINDS
             and n["id"] not in have}
    if not owned:
        return 0
    needed: set[str] = set()
    for e in existing.get("links", existing.get("edges", [])):
        if e.get("source_file") == src_file:
            continue                         # this binary's own edges are being replaced anyway
        for end in (e.get("source"), e.get("target")):
            if end in owned:
                needed.add(end)
    for nid in sorted(needed):
        chunk["nodes"].append(owned[nid])
    return len(needed)


def _engine_name(engine: str) -> str:
    from .similarity import engine_path
    return "rust" if engine == "rust" or (engine == "auto" and engine_path()) else "python"
