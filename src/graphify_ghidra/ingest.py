"""Turn a ``graphify-ghidra/1`` export into a graphify extraction.

Entry points
------------
``ingest_export(doc, options=None) -> dict``
    Returns ``{"nodes", "edges", "hyperedges"}`` in graphify's extraction
    format, ready for ``graphify.build.build_from_json`` / ``build_merge``.
    The result also carries ``"ghidra"``: the :class:`ProgramAnalysis` summary,
    for report generation. graphify ignores unknown top-level keys.

Graph model
-----------
Nodes (``metadata.ghidra_kind`` says which)::

    binary      the analysed program
    segment     a memory block (.text, .rdata, ...)
    function    a local function; ``source_location`` is its address
    thunk       a thunk function (kept distinct so wrappers are visible)
    import      an imported API, global across binaries (``lib::name``)
    library     an imported shared library, global across binaries
    string      a defined string literal that code references / matches a rule
    data        a named global variable or table
    capability  a behaviour concept, global (network, crypto, anti-analysis, ...)
    comment     an analyst's comment on a function (file_type ``rationale``)

Edges::

    contains         binary -> segment / function / data / string
    calls            function -> function | import   (direct = EXTRACTED,
                     computed/indirect = INFERRED)
    thunks_to        thunk -> its resolved target
    imports          binary -> import
    links_against    binary -> library
    member_of        import -> library
    references       function -> string | data
    exhibits         function -> capability          (always INFERRED)
    rationale_for    comment -> function

Import, library and capability nodes carry *global* ids, so two binaries that
import ``CreateRemoteThread`` end up sharing that node: cross-binary queries
("which samples inject code?") fall out of ordinary graph traversal.
"""

from __future__ import annotations

import re
from typing import Any

from graphify.ids import make_id
from graphify.security import sanitize_label, sanitize_metadata

from .analysis import ProgramAnalysis, analyze
from .capabilities import CAPABILITIES
from .program import Program, ProgramOptions

__all__ = ["ingest_export", "node_id_for"]

_MAX_PSEUDO = 1500
_MAX_COMMENT = 600


def node_id_for(program: Program, kind: str, key: str) -> str:
    """Stable node id; per-binary kinds are scoped by name + hash prefix."""
    scope = program.name
    if program.sha256:
        scope = f"{program.name}_{program.sha256[:8]}"
    key = key.replace(":", "_")
    if kind in {"import", "library", "capability"}:
        return make_id("ghidra", kind, key)
    return make_id("ghidra", scope, kind, key)


def _scope(program: Program) -> str:
    """Directory-safe scope for sidecar files: ``name`` or ``name_<sha8>``."""
    from .model import scope_for
    return scope_for(program.name, program.sha256)


def ingest_export(doc: dict[str, Any], options: ProgramOptions | None = None) -> dict[str, Any]:
    program = Program(doc, options)
    analysis = analyze(program)
    return _emit(program, analysis)


# --------------------------------------------------------------------- emit

_GLOBAL_KINDS = {"import", "library", "capability", "datatype"}
_PRIMITIVE_TYPES = {
    "void", "char", "uchar", "byte", "short", "ushort", "int", "uint", "long", "ulong", "longlong", "ulonglong",
    "float", "double", "bool", "wchar_t", "wchar16", "size_t", "dword", "word", "qword", "handle", "lpvoid", "pvoid",
    "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t", "undefined", "pointer",
    "code", "lpcwstr", "lpwstr", "lpcstr", "lpstr", "lpcvoid", "pcwstr", "pwstr", "pcstr", "pstr", "hresult", "ntstatus",
    "boolean", "uint_ptr", "int_ptr", "ulong_ptr", "long_ptr", "dword_ptr", "wchar", "tchar", "lptstr", "lpctstr",
    "float10", "string", "unicode", "pointer32", "pointer64", "imagebaseoffset32", "longdouble",
}


def interesting_type(t: str | None) -> str | None:
    """The base name of a non-primitive type (struct/class/enum/typedef), else None.

    Mapping *struct-typed* parameters is what links functions that operate on the
    same object, which is how a program's data model becomes visible in the graph.
    """
    if not t:
        return None
    base = re.sub(r"\[[^\]]*\]", "", t)
    base = re.sub(r"\b(const|volatile|struct|union|enum|class)\b", "", base)
    base = base.replace("*", " ").strip().split()
    if not base:
        return None
    b = base[-1]
    low = b.lower()
    if low in _PRIMITIVE_TYPES or low.startswith(("undefined", "pointer")) or not re.match(r"^[A-Za-z_]\w*$", b):
        return None
    return b


class _Out:
    def __init__(self, source_file: str, scope: str = "") -> None:
        self.source_file = source_file
        self.scope = scope
        self.nodes: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []
        self.node_ids: set[str] = set()
        self._edge_keys: set[tuple[str, str, str]] = set()

    def node(self, nid: str, label: str, *, kind: str, file_type: str = "code",
             location: str | None = None, **meta: Any) -> str:
        if nid in self.node_ids:
            return nid
        self.node_ids.add(nid)
        clean = {k: v for k, v in meta.items() if v is not None}
        clean["ghidra_kind"] = kind
        if self.scope and kind not in _GLOBAL_KINDS:
            clean.setdefault("scope", self.scope)   # lets annotations find this node later
        self.nodes.append({
            "id": nid,
            "label": sanitize_label(label),
            "file_type": file_type,
            "source_file": self.source_file,
            "source_location": location,
            "metadata": sanitize_metadata(clean),
        })
        return nid

    def edge(self, source: str, target: str, relation: str, *, confidence: str = "EXTRACTED",
             score: float = 1.0, weight: float = 1.0, location: str | None = None,
             context: str | None = None, **extra: Any) -> None:
        if source == target or source not in self.node_ids or target not in self.node_ids:
            return  # endpoint-safe: never emit a dangling edge
        key = (source, target, relation)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        e: dict[str, Any] = {
            "source": source, "target": target, "relation": relation,
            "confidence": confidence, "confidence_score": score,
            "source_file": self.source_file, "source_location": location, "weight": weight,
        }
        if context:
            e["context"] = sanitize_label(context)
        e.update({k: v for k, v in sanitize_metadata(extra).items()})
        self.edges.append(e)


def _emit(program: Program, analysis: ProgramAnalysis) -> dict[str, Any]:
    opts = program.options
    out = _Out(program.source_file, _scope(program))
    info = program.info

    binary = out.node(
        node_id_for(program, "binary", program.name), program.name, kind="binary",
        location=info.get("image_base"),
        format=info.get("format"), language=info.get("language"), processor=info.get("processor"),
        endian=info.get("endian"), compiler=info.get("compiler"), pointer_size=info.get("pointer_size"),
        image_base=info.get("image_base"), sha256=program.sha256, md5=info.get("md5"),
        producer=program.producer.get("name"), ghidra_version=program.producer.get("ghidra_version"),
    )

    # ------------------------------------------------------------- segments
    if opts.include_segments:
        for seg in program.segments:
            perms = "".join(c if seg.get(k) else "-" for c, k in (("r", "read"), ("w", "write"), ("x", "execute")))
            sid = out.node(node_id_for(program, "segment", f"{seg['name']}_{seg.get('start', '')}"),
                           f"{seg['name']} ({perms})", kind="segment", location=seg.get("start"),
                           start=seg.get("start"), end=seg.get("end"), size=seg.get("size"),
                           permissions=perms, initialized=seg.get("initialized"))
            out.edge(binary, sid, "contains")

    # ------------------------------------------------------------ functions
    fn_ids: dict[str, str] = {}
    pseudo_sidecar: dict[str, str] = {}
    for addr in program.order:
        fn = program.functions[addr]
        is_thunk = bool(fn.get("is_thunk"))
        if is_thunk and not opts.include_thunks:
            continue
        m = analysis.metrics[addr]
        meta: dict[str, Any] = {
            "address": addr,
            "signature": fn.get("signature"),
            "calling_convention": fn.get("calling_convention"),
            "size_bytes": fn.get("size"),
            "instruction_count": fn.get("instruction_count"),
            "basic_blocks": fn.get("block_count"),
            "cyclomatic_complexity": fn.get("cyclomatic_complexity"),
            "call_sites": fn.get("call_sites"),
            "indirect_calls": fn.get("indirect_calls"),
            "fan_in": m.fan_in,
            "fan_out": m.fan_out,
            "depth_from_entry": m.depth,
            "reachable_from_entry": m.reachable,
            "name_source": fn.get("name_source"),
            "namespace": fn.get("namespace"),
            "roles": m.roles or None,
            "triage_score": m.score,
            "triage_reasons": m.reasons or None,
            "capabilities": sorted(m.capabilities) or None,
            "api_calls": sorted({program.imports[k]["name"] for (s, k) in program.external_calls if s == addr})[:40] or None,
            "no_return": fn.get("no_return") or None,
            "library_match": fn.get("library_match"),
        }
        if fn.get("pseudo_c"):
            # graphify caps (and HTML-escapes) metadata strings at 512 chars, which
            # would mangle pseudo-C. Keep a short preview on the node and the full
            # text in a sidecar file that graph_io writes next to graph.json.
            text = str(fn["pseudo_c"])[:_MAX_PSEUDO]
            rel = f"ghidra/{_scope(program)}/pseudo/{addr.replace(':', '_')}.c"
            pseudo_sidecar[rel] = text
            meta["pseudo_c_path"] = rel
            meta["pseudo_c_preview"] = text[:300]
            meta["pseudo_c_truncated"] = bool(fn.get("pseudo_c_truncated"))
            meta["untrusted_content"] = True
        fid = out.node(
            node_id_for(program, "fn", addr), program.function_label(addr),
            kind="thunk" if is_thunk else "function", location=addr, **meta,
        )
        fn_ids[addr] = fid
        out.edge(binary, fid, "contains", location=addr)

        comment = fn.get("comment") or fn.get("repeatable_comment")
        if comment and str(comment).strip():
            text = str(comment).strip()
            cid = out.node(node_id_for(program, "comment", addr), f"Note on {fn['name']}",
                           kind="comment", file_type="rationale", location=addr,
                           text=text[:_MAX_COMMENT], author="analyst")
            out.edge(cid, fid, "rationale_for", location=addr)

    # thunk -> target
    for addr, fid in fn_ids.items():
        fn = program.functions[addr]
        tgt = fn.get("thunk_target")
        if not fn.get("is_thunk") or not tgt:
            continue
        from .model import canon_addr
        t_addr = canon_addr(tgt)
        if t_addr in fn_ids:
            out.edge(fid, fn_ids[t_addr], "thunks_to", location=addr, context="thunk")

    # ---------------------------------------------------------------- calls
    for (src, dst), agg in program.call_edges.items():
        if src not in fn_ids or dst not in fn_ids or src == dst:
            continue
        ctx = f"{agg.count} call site{'s' if agg.count != 1 else ''}"
        if agg.via_thunks:
            ctx += f"; via thunk {', '.join(sorted(agg.via_thunks)[:2])}"
        if not agg.direct:
            ctx += "; computed/indirect"
        out.edge(fn_ids[src], fn_ids[dst], "calls",
                 confidence="EXTRACTED" if agg.direct else "INFERRED",
                 score=1.0 if agg.direct else 0.8, weight=float(agg.count),
                 location=agg.sites[0] if agg.sites else None, context=ctx,
                 call_site_addresses=agg.sites[:8] or None)

    # -------------------------------------------------------------- imports
    used_imports = {key for (_s, key) in program.external_calls}
    lib_ids: dict[str, str] = {}
    imp_ids: dict[str, str] = {}
    for key, imp in program.imports.items():
        # Keep unused imports too: an import that is never called is itself a
        # finding (dead code, or resolved dynamically via a pointer table).
        lib = imp["lib_norm"]
        if lib not in lib_ids:
            lib_ids[lib] = out.node(node_id_for(program, "library", lib), imp["library"] or lib,
                                    kind="library", library=imp["library"])
            out.edge(binary, lib_ids[lib], "links_against")
        iid = out.node(
            node_id_for(program, "import", f"{lib}_{imp['name']}"),
            imp["name"], kind="import", library=imp["library"],
            capabilities=imp["capabilities"] or None,
            called_by_code=key in used_imports,
        )
        imp_ids[key] = iid
        out.edge(binary, iid, "imports")
        out.edge(iid, lib_ids[lib], "member_of")

    for (src, key), agg in program.external_calls.items():
        if src not in fn_ids or key not in imp_ids:
            continue
        out.edge(fn_ids[src], imp_ids[key], "calls", weight=float(agg.count),
                 location=agg.sites[0] if agg.sites else None,
                 confidence="EXTRACTED" if agg.direct else "INFERRED",
                 score=1.0 if agg.direct else 0.8,
                 context=f"{agg.count} call site{'s' if agg.count != 1 else ''}"
                         + ("" if agg.direct else "; computed/indirect"))

    # -------------------------------------------------------------- strings
    kept = 0
    str_ids: dict[str, str] = {}
    for s_addr, s in sorted(program.strings.items(), key=lambda kv: (-len(kv[1]["refs"]), kv[0])):
        if kept >= opts.max_strings:
            break
        if not program.keep_string(s):
            continue
        label = s["value"] if len(s["value"]) <= 80 else s["value"][:77] + "..."
        sid = out.node(node_id_for(program, "str", s_addr), repr(label)[1:-1] or "(empty)",
                       kind="string", file_type="document", location=s_addr,
                       address=s_addr, value=s["value"][:512], length=s.get("length"),
                       capabilities=s["capabilities"] or None, referenced_by=len(s["refs"]),
                       untrusted_content=True)
        str_ids[s_addr] = sid
        kept += 1
        out.edge(binary, sid, "contains", location=s_addr)
    for f_addr, s_addrs in program.fn_strings.items():
        if f_addr not in fn_ids:
            continue
        for s_addr in sorted(s_addrs):
            if s_addr in str_ids:
                out.edge(fn_ids[f_addr], str_ids[s_addr], "references", location=s_addr)

    # ----------------------------------------------------------------- data
    data_ids: dict[str, str] = {}
    if opts.include_data:
        for d_addr, d in program.data.items():
            if not d["refs"] and not d["user_named"]:
                continue  # unreferenced, compiler-named tables are noise
            data_ids[d_addr] = out.node(node_id_for(program, "data", d_addr), d["name"],
                                        kind="data", location=d_addr, address=d_addr,
                                        data_type=d.get("type"), size_bytes=d.get("size"))
            out.edge(binary, data_ids[d_addr], "contains", location=d_addr)
        for f_addr, d_addrs in program.fn_data.items():
            if f_addr not in fn_ids:
                continue
            for d_addr in sorted(d_addrs):
                if d_addr in data_ids:
                    out.edge(fn_ids[f_addr], data_ids[d_addr], "references", location=d_addr)

    # ---------------------------------------------- shared state through globals
    # writer -> reader `shares_data_with`: graphify's native relation for "these two
    # functions communicate through the same variable". Bounded per global so a
    # widely used one (a logger, an allocator) cannot create a quadratic clique;
    # the data node itself still links every user.
    if opts.shares_data_edges:
        for d_addr, d in program.data.items():
            if d_addr not in data_ids or not d["writers"]:
                continue
            writers = sorted(w for w in d["writers"] if w in fn_ids)[:4]
            readers = sorted(r for r in d["refs"] - d["writers"] if r in fn_ids)[:25]
            for w in writers:
                for r in readers:
                    out.edge(fn_ids[w], fn_ids[r], "shares_data_with", score=0.9, location=d_addr,
                             confidence="EXTRACTED", context=f"writes {d['name']}, read by target")

    # ------------------------------------------------- types and variables
    if opts.include_types or opts.include_variables:
        type_ids: dict[str, str] = {}

        def type_node(base: str) -> str:
            if base not in type_ids:
                type_ids[base] = out.node(make_id("ghidra", "type", base), base, kind="datatype", file_type="concept")
            return type_ids[base]

        for addr, fid in fn_ids.items():
            fn = program.functions[addr]
            if opts.include_types:
                uses: dict[str, str] = {}
                for p in fn.get("params") or []:
                    b = interesting_type(p.get("type"))
                    if b:
                        uses.setdefault(b, "param")
                b = interesting_type(fn.get("return_type"))
                if b:
                    uses.setdefault(b, "return")
                for lv in (fn.get("locals") or [])[:30]:
                    b = interesting_type(lv.get("type"))
                    if b:
                        uses.setdefault(b, "local")
                for b, role in list(uses.items())[:12]:
                    out.edge(fid, type_node(b), "references", context=f"{role} of type {b}", location=addr)
            if opts.include_variables:
                for role, key in (("param", "params"), ("local", "locals")):
                    for v in fn.get(key) or []:
                        if v.get("auto", True):
                            continue          # only variables someone has already named
                        vid = out.node(node_id_for(program, "var", f"{addr}_{v['name']}"),
                                       f"{fn['name']}::{v['name']}", kind="variable", location=addr,
                                       address=addr, data_type=v.get("type"), role=role)
                        out.edge(fid, vid, "contains", location=addr)
                        b = interesting_type(v.get("type"))
                        if b:
                            out.edge(vid, type_node(b), "references", context="variable type")

    # --------------------------------------------------------- capabilities
    hyperedges: list[dict[str, Any]] = []
    if opts.include_capabilities:
        cap_ids: dict[str, str] = {}

        def cap_node(key: str) -> str:
            if key not in cap_ids:
                cap = CAPABILITIES[key]
                cap_ids[key] = out.node(node_id_for(program, "capability", key), cap.label,
                                        kind="capability", file_type="concept",
                                        description=cap.description, risk=cap.risk)
            return cap_ids[key]

        for addr, m in analysis.metrics.items():
            if addr not in fn_ids:
                continue
            for cap, evidence in m.capabilities.items():
                api_ev = [e for e in evidence if not e.startswith("string:")]
                str_ev = [e for e in evidence if e.startswith("string:")]
                # Imported API evidence is stronger than a matched string literal.
                score = 0.75 if api_ev else 0.5
                ctx_bits = []
                if api_ev:
                    ctx_bits.append("APIs: " + ", ".join(api_ev[:6]))
                if str_ev:
                    ctx_bits.append(f"{len(str_ev)} matching string(s)")
                out.edge(fn_ids[addr], cap_node(cap), "exhibits", confidence="INFERRED",
                         score=score, location=addr, context="; ".join(ctx_bits))
        for key, imp_id in imp_ids.items():
            for cap in program.imports[key]["capabilities"]:
                out.edge(imp_id, cap_node(cap), "exhibits", confidence="INFERRED", score=0.75,
                         context="API name matches capability rule")
        for s_addr, sid in str_ids.items():
            for cap in program.strings[s_addr]["capabilities"]:
                out.edge(sid, cap_node(cap), "exhibits", confidence="INFERRED", score=0.5,
                         context="string matches capability rule")

        if opts.capability_hyperedges:
            for cap, members in analysis.capability_members.items():
                member_ids = [fn_ids[a] for a in members if a in fn_ids]
                if len(member_ids) < opts.min_capability_members:
                    continue
                hyperedges.append({
                    "id": node_id_for(program, "cap_group", cap),
                    "label": f"{CAPABILITIES[cap].label} functions",
                    "nodes": member_ids[: opts.max_hyperedge_members],
                    "relation": "participate_in",
                    "confidence": "INFERRED",
                    "confidence_score": 0.7,
                    "source_file": program.source_file,
                })

    features: list[dict[str, Any]] = []
    if opts.similarity:
        from .similarity import make_record
        api_by_fn: dict[str, set[str]] = {}
        for (src, key) in program.external_calls:
            api_by_fn.setdefault(src, set()).add(program.imports[key]["name"])
        for addr, fid in fn_ids.items():
            fn = program.functions[addr]
            if fn.get("is_thunk") or not fn.get("mnemonics"):
                continue
            features.append(make_record(
                fid, _scope(program), mnemonics=fn["mnemonics"], consts=fn.get("constants") or [],
                apis=api_by_fn.get(addr, ()),
                strings=[program.strings[s]["value"] for s in sorted(program.fn_strings.get(addr, ()))][:40],
                instrs=fn.get("instruction_count") or 0, blocks=fn.get("block_count") or 0,
                pseudo_c=fn.get("pseudo_c")))

    return {
        "nodes": out.nodes,
        "edges": out.edges,
        "hyperedges": hyperedges,
        "input_tokens": 0,
        "output_tokens": 0,
        "ghidra": {
            "features": features,
            "scope": _scope(program),
            "sidecars": pseudo_sidecar,
            "program": {k: info.get(k) for k in ("name", "format", "language", "sha256", "image_base", "processor")},
            "summary": analysis.summary,
            "ranked": [
                {"address": a, "name": program.functions[a]["name"], "score": analysis.metrics[a].score,
                 "reasons": analysis.metrics[a].reasons, "roles": analysis.metrics[a].roles,
                 "node_id": fn_ids.get(a)}
                for a in analysis.ranked[:50] if analysis.metrics[a].score > 0
            ],
            "libraries": analysis.external_library_usage,
        },
    }
