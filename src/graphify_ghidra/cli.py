"""``graphify-ghidra`` command line.

    graphify-ghidra doctor
    graphify-ghidra export   app.exe -o app.ghidra.json [--decompile 40]
    graphify-ghidra ingest   app.ghidra.json            [--out graphify-out]
    graphify-ghidra analyze  app.exe                    [--decompile 40]   # export + ingest
    graphify-ghidra ingest   rea-*.json --name app.exe                    # REA results
    graphify-ghidra report   app.ghidra.json                              # no graph, just triage
    graphify-ghidra install-skill [--apply]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .model import SCHEMA, validate_export
from .program import ProgramOptions


def _add_ingest_options(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("what goes into the graph")
    g.add_argument("--strings", choices=["none", "referenced", "interesting", "all"], default="referenced",
                   help="which defined strings become nodes (default: referenced = used by code or matching a rule)")
    g.add_argument("--min-string-len", type=int, default=4)
    g.add_argument("--max-strings", type=int, default=4000)
    g.add_argument("--no-segments", action="store_true", help="omit memory-segment nodes")
    g.add_argument("--no-data", action="store_true", help="omit named-global/data nodes")
    g.add_argument("--no-thunks", action="store_true", help="omit thunk function nodes")
    g.add_argument("--no-capabilities", action="store_true", help="omit capability concept nodes and edges")
    o = p.add_argument_group("output")
    o.add_argument("--out", default=None,
                   help="output dir (default: $GRAPHIFY_GHIDRA_OUT, an existing ./graphify-out that already holds "
                        "Ghidra data, else ./graphify-out-ghidra; an existing graphify graph is never used by default)")
    o.add_argument("--merge-into-existing", action="store_true",
                   help="allow merging into a graph.json that holds no analysed binary (e.g. your source-code graph)")
    o.add_argument("--force", action="store_true", help="let the merge shrink an existing graph.json")
    o.add_argument("--undirected", action="store_true", help="build an undirected graph (default: directed)")


def _options(args: argparse.Namespace) -> ProgramOptions:
    return ProgramOptions(
        strings=args.strings, min_string_len=args.min_string_len, max_strings=args.max_strings,
        include_segments=not args.no_segments, include_data=not args.no_data,
        include_thunks=not args.no_thunks, include_capabilities=not args.no_capabilities,
        capability_hyperedges=not args.no_capabilities,
    )


def _add_export_options(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("Ghidra")
    g.add_argument("--ghidra-home", help="Ghidra install dir (default: $GHIDRA_INSTALL_DIR, PATH, common locations)")
    g.add_argument("--decompile", type=int, default=30, metavar="N",
                   help="attach pseudo-C to the N highest-priority functions up front (default 30; more via the "
                        "ghidra_decompile tool on demand)")
    g.add_argument("--no-keep-project", action="store_true",
                   help="delete the Ghidra project after analysis (disables live decompile/disasm/xrefs)")
    g.add_argument("--decompile-timeout", type=int, default=20, metavar="SEC")
    g.add_argument("--max-strings-export", type=int, default=50000)
    g.add_argument("--language", help="Ghidra language id for raw/unknown formats (default: $REA_GHIDRA_LANGUAGE_ID)")
    g.add_argument("--cspec", help="compiler spec id (default: $REA_GHIDRA_COMPILER_SPEC_ID)")
    g.add_argument("--loader", help="Ghidra loader name, e.g. BinaryLoader")
    g.add_argument("--timeout", type=int, default=1800, help="seconds before giving up on Ghidra")


def _run_export(args: argparse.Namespace, out_json: Path, project_dir: Path | None = None) -> Path:
    from .ghidra_runner import default_log_path, export_binary
    mode = f"project kept at {project_dir}" if project_dir else "read-only, ephemeral project"
    print(f"[graphify-ghidra] analysing {args.binary} with Ghidra ({mode})...", file=sys.stderr)
    res = export_binary(
        args.binary, out_json, ghidra_home=args.ghidra_home, decompile=args.decompile,
        decompile_timeout=args.decompile_timeout, max_strings=args.max_strings_export,
        language=args.language, compiler_spec=args.cspec, loader=args.loader, timeout=args.timeout,
        log_to=default_log_path(out_json), project_dir=project_dir,
    )
    print(f"[graphify-ghidra] Ghidra {res.ghidra_root.name}: wrote {res.out_path}", file=sys.stderr)
    return res.out_path


def cmd_export(args: argparse.Namespace) -> int:
    out = Path(args.output) if args.output else Path(f"{Path(args.binary).name}.ghidra.json")
    _run_export(args, out)
    return 0


def _load_doc_from_inputs(args: argparse.Namespace) -> dict[str, Any]:
    """One native export, or REA result files adapted into one."""
    from .rea_adapter import build_export, load_payloads
    payloads = load_payloads(args.inputs)
    if not payloads:
        raise SystemExit("error: no JSON found in the input file(s)")
    if len(payloads) == 1 and isinstance(payloads[0], dict) and payloads[0].get("schema") == SCHEMA:
        doc = payloads[0]
    else:
        if not args.name:
            raise SystemExit("error: REA input needs --name <program name> (the analysed binary's file name)")
        doc, warnings = build_export(payloads, program_name=args.name,
                                     **({"sha256": args.sha256} if args.sha256 else {}))
        for w in warnings:
            print(f"[graphify-ghidra] warning: {w}", file=sys.stderr)
        if not doc["functions"]:
            # An empty analysis is indistinguishable from "a binary with no functions".
            # Refuse rather than emit a confident-looking, wrong report.
            raise SystemExit("error: no functions could be read from the input; nothing was ingested. "
                             "Expected REA list_procedures / procedure_references results "
                             "(see `graphify-ghidra --help` and the skill for accepted shapes).")
    errs = validate_export(doc)
    if errs:
        raise SystemExit("error: not a usable export:\n  " + "\n  ".join(errs[:8]))
    return doc


def _ingest_and_write(doc: dict[str, Any], args: argparse.Namespace) -> int:
    from .graph_io import ForeignGraphError, write_extraction
    from .ingest import ingest_export
    from .workspace import resolve_out
    extraction = ingest_export(doc, _options(args))
    out = resolve_out(explicit=args.out)
    try:
        res = write_extraction(extraction, out, force=args.force, directed=False if args.undirected else None,
                               allow_foreign_merge=args.merge_into_existing)
    except ForeignGraphError as exc:
        print(f"[graphify-ghidra] {exc}", file=sys.stderr)
        return 4
    s = extraction["ghidra"]["summary"]
    print(f"[graphify-ghidra] {s['functions']} functions, {s['imports']} imports -> "
          f"{res.nodes} nodes / {res.edges} edges / {res.communities} communities in the merged graph",
          file=sys.stderr)
    if not res.written:
        print(f"[graphify-ghidra] NOT written: {res.message}", file=sys.stderr)
        return 3
    print(f"[graphify-ghidra] graph:  {res.graph_path}")
    print(f"[graphify-ghidra] report: {res.report_path}")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    return _ingest_and_write(_load_doc_from_inputs(args), args)


def cmd_analyze(args: argparse.Namespace) -> int:
    from .ghidra_runner import file_sha256
    from .model import scope_for
    from .graph_io import _graph_has_binary
    from .workspace import resolve_out
    out_dir = resolve_out(explicit=args.out)
    args.out = str(out_dir)
    binary = Path(args.binary)
    if not binary.is_file():
        raise SystemExit(f"error: {binary} is not a file")
    gp = out_dir / "graph.json"
    if gp.is_file() and not args.merge_into_existing and not _graph_has_binary(gp):
        # Fail now, not after a multi-minute Ghidra run.
        raise SystemExit(f"error: {gp} is an existing graph with no analysed binary in it; not touching it. "
                         "Omit --out to use ./graphify-out-ghidra, or pass --merge-into-existing to merge into it.")
    scope = scope_for(binary.name, file_sha256(binary))
    export_path = out_dir / "ghidra" / f"{binary.name}.ghidra.json"
    project = None if args.no_keep_project else out_dir / "ghidra" / scope / "project"
    _run_export(args, export_path, project)
    doc = json.loads(export_path.read_text(encoding="utf-8"))
    code = _ingest_and_write(doc, args)
    if code == 0:
        print("[graphify-ghidra] next: let your agent run ghidra_status / ghidra_worklist, or "
              "`graphify-ghidra tool worklist`", file=sys.stderr)
    return code


def cmd_report(args: argparse.Namespace) -> int:
    from .ingest import ingest_export
    from .report import render_report
    doc = _load_doc_from_inputs(args)
    ex = ingest_export(doc, ProgramOptions(strings="none"))
    print(render_report(ex["ghidra"], top=args.top))
    return 0


def _load_cg(args: argparse.Namespace):
    from .callchain import load_call_graph
    from .workspace import resolve_out
    path = Path(args.graph) if args.graph else resolve_out() / "graph.json"
    if not path.is_file():
        raise SystemExit(f"error: {path} not found (run `graphify-ghidra analyze` first, or pass --graph)")
    return load_call_graph(path)


def _resolve_or_exit(cg, query: str) -> str:
    from .callchain import AmbiguousNode
    try:
        return cg.resolve_one(query)
    except KeyError as exc:
        raise SystemExit(f"error: {exc.args[0]}")
    except AmbiguousNode as exc:
        shown = "\n  ".join(cg.label(c) for c in exc.candidates[:12])
        raise SystemExit(f"error: {query!r} is ambiguous; use a node id or address. Candidates:\n  {shown}")


def cmd_callchain(args: argparse.Namespace) -> int:
    cg = _load_cg(args)
    _resolve_or_exit(cg, args.source)
    _resolve_or_exit(cg, args.target)
    chains = cg.chains(args.source, args.target, k=args.k)
    if not chains:
        print(f"No call chain from {args.source!r} to {args.target!r} over direct/resolved calls.")
        print("This is not proof none exists: indirect calls (function pointers, vtables) are not "
              "followed. Check the report's blind spots.")
        return 1
    for i, chain in enumerate(chains, 1):
        print(f"Chain {i} ({len(chain) - 1} call{'s' if len(chain) != 2 else ''}):")
        for depth, nid in enumerate(chain):
            conf = ""
            if depth:
                edge = cg.calls.get_edge_data(chain[depth - 1], nid) or {}
                conf = f"  [{edge.get('confidence', '?')}]"
            print(f"  {'-> ' if depth else '   '}{cg.label(nid)}{conf}")
    return 0


def cmd_callers(args: argparse.Namespace) -> int:
    cg = _load_cg(args)
    start = _resolve_or_exit(cg, args.node)
    rows = cg.callers_tree(args.node, depth=args.depth, limit=args.limit)
    print(f"Callers of {cg.label(start)} (up to depth {args.depth}):")
    if not rows:
        print("  (none found over resolved calls; it may be reached indirectly or be an entry point)")
    for depth, nid in rows:
        mark = "  <- ENTRY POINT" if cg.is_entry(nid) else ""
        print(f"  {'  ' * (depth - 1)}{cg.label(nid)}{mark}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    ok = True

    def line(good: bool, label: str, detail: str) -> None:
        nonlocal ok
        ok = ok and good
        print(f"[{'ok' if good else '!!'}] {label}: {detail}")

    line(True, "graphify-ghidra", __version__)
    try:
        import graphify  # noqa: F401
        from importlib.metadata import version
        line(True, "graphify", version("graphifyy"))
    except Exception as exc:  # pragma: no cover
        line(False, "graphify", f"not importable ({exc}); pip install graphifyy")
    try:
        from .ghidra_runner import find_ghidra
        root = find_ghidra(args.ghidra_home)
        line(True, "Ghidra", str(root))
    except Exception as exc:
        line(False, "Ghidra", str(exc))
    java = shutil.which("java")
    line(bool(java), "java", java or "not on PATH (Ghidra may still find one via JAVA_HOME)")
    for var in ("GHIDRA_INSTALL_DIR", "REA_GHIDRA_LANGUAGE_ID", "REA_GHIDRA_COMPILER_SPEC_ID"):
        print(f"      {var} = {os.environ.get(var, '(unset)')}")
    return 0 if ok else 1


def cmd_install_skill(args: argparse.Namespace) -> int:
    src = Path(__file__).parent / "skill" / "SKILL.md"
    dest_root = Path(args.dest).expanduser() if args.dest else Path.home() / ".claude" / "skills"
    dest = dest_root / "graphify-ghidra" / "SKILL.md"
    print(f"Plan: copy {src.name} -> {dest}")
    if dest.exists():
        print(f"      existing file will be backed up to {dest.with_suffix('.md.bak')}")
    if not args.apply:
        print("Dry run. Re-run with --apply to write it.")
        return 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.read_bytes() != src.read_bytes():
        shutil.copy2(dest, dest.with_suffix(".md.bak"))
    shutil.copy2(src, dest)
    print(f"Installed {dest}")
    return 0


def _out_dir(arg: str | None) -> str:
    from .workspace import resolve_out
    return str(resolve_out(explicit=arg))


def cmd_job(args: argparse.Namespace) -> int:
    """Internal: the detached process behind ghidra_analyze (records its outcome in job.json)."""
    from .jobs import run_job
    rest = args.rest[1:] if args.rest[:1] == ["--"] else args.rest
    return run_job(args.jobfile, rest)


def cmd_tool(args: argparse.Namespace) -> int:
    from .tools import TOOLS, run_tool
    from .workspace import Workspace
    name = args.name if args.name.startswith("ghidra_") else f"ghidra_{args.name}"
    if name not in TOOLS:
        raise SystemExit(f"error: unknown tool {args.name!r}; tools: {', '.join(t[7:] for t in TOOLS)}")
    payload = json.loads(args.args) if args.args else {}
    ws = Workspace(_out_dir(args.out))
    try:
        ok, text = run_tool(ws, name, payload)
    finally:
        ws.close()
    print(text)
    return 0 if ok else 1


def cmd_tool_server(args: argparse.Namespace) -> int:
    """JSON-lines tool server on stdin/stdout, keeping the graph (and Ghidra) warm between calls.

    Request:  {"id": 1, "tool": "ghidra_worklist", "args": {...}, "out": "graphify-out"}
    Response: {"id": 1, "ok": true, "text": "..."}
    """
    from .tools import run_tool
    from .workspace import Workspace
    proto = sys.stdout
    sys.stdout = sys.stderr          # library prints must never corrupt the protocol stream
    workspaces: dict[str, Workspace] = {}
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError as exc:
                proto.write(json.dumps({"id": None, "ok": False, "text": f"bad request: {exc}"}) + "\n")
                proto.flush()
                continue
            if req.get("tool") == "__ping__":
                resp = {"id": req.get("id"), "ok": True, "text": "pong"}
            else:
                out = str(Path(req.get("out") or _out_dir(None)).resolve())
                ws = workspaces.setdefault(out, Workspace(out))
                ok, text = run_tool(ws, str(req.get("tool")), req.get("args"))
                resp = {"id": req.get("id"), "ok": ok, "text": text}
            proto.write(json.dumps(resp) + "\n")
            proto.flush()
    finally:
        for ws in workspaces.values():
            ws.close()
    return 0


def cmd_build_engine(args: argparse.Namespace) -> int:
    """Build the multithreaded Rust similarity engine and install it next to the package."""
    import subprocess
    engine_dir = Path(__file__).resolve().parents[2] / "engine"
    if not (engine_dir / "Cargo.toml").is_file():
        raise SystemExit(f"error: engine sources not found at {engine_dir} (source checkout required)")
    if not shutil.which("cargo"):
        raise SystemExit("error: cargo not found. Install Rust (https://rustup.rs). The Python fallback keeps working without it.")
    cmd = ["cargo", "build", "--release"] + (["--offline"] if args.offline else [])
    print("[graphify-ghidra] " + " ".join(cmd), file=sys.stderr)
    code = subprocess.run(cmd, cwd=engine_dir).returncode
    if code != 0:
        print("[graphify-ghidra] build failed. If crates.io is unreachable, retry with --offline when the crates are "
              "already in your cargo cache.", file=sys.stderr)
        return code
    exe = "gg-engine.exe" if os.name == "nt" else "gg-engine"
    built = engine_dir / "target" / "release" / exe
    dest = Path(__file__).parent / "bin"
    dest.mkdir(exist_ok=True)
    shutil.copy2(built, dest / exe)
    print(f"[graphify-ghidra] engine installed: {dest / exe}")
    return 0


def _pi_package_dir() -> Path:
    return Path(__file__).parent / "pi_package"


def cmd_install_pi(args: argparse.Namespace) -> int:
    """Install the Pi extension + skill. Dry run unless --apply; settings.json is backed up first."""
    import subprocess
    pi_home = Path(args.pi_home).expanduser() if args.pi_home else Path.home() / ".pi" / "agent"
    pkg = _pi_package_dir()
    exe = shutil.which("graphify-ghidra") or sys.argv[0]
    cfg = pi_home / "graphify-ghidra.json"
    settings = pi_home / "settings.json"
    pi_cmd = shutil.which("pi")
    print("Plan:")
    print(f"  1. back up {settings} -> {settings.with_name('settings.json.bak-graphify-ghidra')} (if not already backed up)")
    print(f"  2. `pi install {pkg}`  (adds this package to {settings}; loaded in place, nothing copied)")
    print(f"  3. write {cfg} with the graphify-ghidra command path: {exe}")
    print("  Adds 14 ghidra_* tools, native graphify_* and rea_* tools (they reuse the graphify and rea entries from your "
          "MCP config; nothing there is changed), and the graphify-ghidra skill to Pi.")
    if not pkg.is_dir():
        raise SystemExit(f"error: Pi package files not found at {pkg}")
    if not pi_cmd:
        raise SystemExit("error: `pi` is not on PATH")
    if not args.apply:
        print("Dry run. Re-run with --apply to perform these steps.")
        return 0
    if settings.is_file():
        bak = settings.with_name("settings.json.bak-graphify-ghidra")
        if not bak.exists():
            shutil.copy2(settings, bak)
    res = subprocess.run([pi_cmd, "install", str(pkg)], capture_output=True, text=True, encoding="utf-8", errors="replace")
    print((res.stdout or "").strip())
    if res.returncode != 0:
        print((res.stderr or "").strip(), file=sys.stderr)
        raise SystemExit(f"error: `pi install` failed ({res.returncode}); nothing else was changed")
    cfg.write_text(json.dumps({"command": str(exe)}, indent=1), encoding="utf-8")
    print(f"Installed. Restart Pi (or /reload). Config: {cfg}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="graphify-ghidra", description="Ghidra and REA support for graphify")
    p.add_argument("--version", action="version", version=f"graphify-ghidra {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("doctor", help="check Ghidra, Java and graphify")
    s.add_argument("--ghidra-home")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("export", help="run Ghidra headless and write a graphify-ghidra/1 JSON export")
    s.add_argument("binary")
    s.add_argument("-o", "--output")
    _add_export_options(s)
    s.set_defaults(func=cmd_export)

    def inputs(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("inputs", nargs="+", help="a graphify-ghidra/1 export, or saved REA result file(s) ('-' = stdin)")
        sp.add_argument("--name", help="binary file name (required for REA input)")
        sp.add_argument("--sha256", help="binary SHA-256 (optional; scopes node ids for REA input)")

    s = sub.add_parser("ingest", help="merge an export (or REA results) into graphify-out/graph.json")
    inputs(s)
    _add_ingest_options(s)
    s.set_defaults(func=cmd_ingest)

    s = sub.add_parser("analyze", help="export a binary with Ghidra, then ingest it")
    s.add_argument("binary")
    _add_export_options(s)
    _add_ingest_options(s)
    s.set_defaults(func=cmd_analyze)

    s = sub.add_parser("report", help="print the triage report without touching any graph")
    inputs(s)
    s.add_argument("--top", type=int, default=25)
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("callchain", help="shortest call chain(s) between two functions/imports/capabilities")
    s.add_argument("source")
    s.add_argument("target", help="function, import, address, or capability (e.g. 'Networking')")
    s.add_argument("--graph", default=None, help="graph.json (default: the resolved Ghidra output dir)")
    s.add_argument("-k", type=int, default=3, help="number of chains to show")
    s.set_defaults(func=cmd_callchain)

    s = sub.add_parser("callers", help="who calls this function/import (breadth-first, with entry points marked)")
    s.add_argument("node")
    s.add_argument("--graph", default=None, help="graph.json (default: the resolved Ghidra output dir)")
    s.add_argument("--depth", type=int, default=4)
    s.add_argument("--limit", type=int, default=60)
    s.set_defaults(func=cmd_callers)

    s = sub.add_parser("tool", help="run one agent tool from the shell (e.g. `tool worklist --args '{\"limit\":5}'`)")
    s.add_argument("name")
    s.add_argument("--args", help="JSON arguments")
    s.add_argument("--out", help="graphify-out directory (default: $GRAPHIFY_GHIDRA_OUT or ./graphify-out)")
    s.set_defaults(func=cmd_tool)

    s = sub.add_parser("_job", help=argparse.SUPPRESS)
    s.add_argument("jobfile")
    s.add_argument("rest", nargs=argparse.REMAINDER)
    s.set_defaults(func=cmd_job)

    s = sub.add_parser("tool-server", help="JSON-lines tool server for agent harnesses (keeps the graph warm)")
    s.set_defaults(func=cmd_tool_server)

    s = sub.add_parser("build-engine", help="build the multithreaded Rust similarity engine")
    s.add_argument("--offline", action="store_true", help="build from the local cargo cache only")
    s.set_defaults(func=cmd_build_engine)

    s = sub.add_parser("install-pi", help="install the Pi harness extension and skill (dry run unless --apply)")
    s.add_argument("--pi-home", help="Pi agent directory (default: ~/.pi/agent)")
    s.add_argument("--apply", action="store_true")
    s.set_defaults(func=cmd_install_pi)

    s = sub.add_parser("install-skill", help="install the Claude Code skill (dry run unless --apply)")
    s.add_argument("--dest", help="skills directory (default: ~/.claude/skills)")
    s.add_argument("--apply", action="store_true")
    s.set_defaults(func=cmd_install_skill)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # surface Ghidra/Export errors without a traceback
        from .ghidra_runner import ExportFailed, GhidraNotFound
        if isinstance(exc, (ExportFailed, GhidraNotFound)):
            print(f"error: {exc}", file=sys.stderr)
            log = getattr(exc, "log", "")
            if log:
                print("--- ghidra log tail ---\n" + log, file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
