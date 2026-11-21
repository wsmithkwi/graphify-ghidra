import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from graphify_ghidra import ProgramOptions, ingest_export, write_extraction
from graphify_ghidra.callchain import AmbiguousNode, load_call_graph
from graphify_ghidra.cli import main
from graphify_ghidra.ghidra_runner import GhidraNotFound, _diagnose, find_ghidra


# ------------------------------------------------------------------- graph_io

def test_write_produces_standard_graphify_graph(graph_dir):
    g = json.loads((graph_dir / "graph.json").read_text(encoding="utf-8"))
    assert g["directed"] is True, "a new call graph must keep caller->callee direction"
    kinds = {n["metadata"]["ghidra_kind"] for n in g["nodes"]}
    assert {"function", "import", "capability", "binary"} <= kinds
    assert any(n.get("community") is not None for n in g["nodes"])
    assert list(graph_dir.glob("GHIDRA_REPORT_*.md"))


def test_reingest_is_idempotent(graph_dir, synthetic):
    before = json.loads((graph_dir / "graph.json").read_text(encoding="utf-8"))
    res = write_extraction(ingest_export(synthetic), graph_dir)
    assert res.written
    after = json.loads((graph_dir / "graph.json").read_text(encoding="utf-8"))
    assert len(after["nodes"]) == len(before["nodes"])
    assert len(after.get("links", after.get("edges"))) == len(before.get("links", before.get("edges")))


def test_second_binary_merges_and_shares_import_nodes(graph_dir, synthetic):
    other = json.loads(json.dumps(synthetic))
    other["program"].update(name="other.exe", sha256="cd" * 32, executable_path="/C:/samples/other.exe")
    write_extraction(ingest_export(other), graph_dir)
    g = json.loads((graph_dir / "graph.json").read_text(encoding="utf-8"))
    binaries = [n for n in g["nodes"] if n["metadata"].get("ghidra_kind") == "binary"]
    assert {b["label"] for b in binaries} == {"sample.exe", "other.exe"}
    imports = [n for n in g["nodes"] if n["metadata"].get("ghidra_kind") == "import" and n["label"] == "connect"]
    assert len(imports) == 1, "the same API is one node shared across binaries"


def test_shrinking_rewrite_is_refused_without_force(graph_dir, synthetic):
    shrunk = ingest_export(synthetic, ProgramOptions(strings="none", include_data=False, include_segments=False,
                                                     include_capabilities=False, capability_hyperedges=False))
    res = write_extraction(shrunk, graph_dir)
    # Same source file => graphify treats it as a replacement; either outcome is legal, but
    # a refusal must be reported, never silent.
    assert res.written or "--force" in res.message
    forced = write_extraction(shrunk, graph_dir, force=True)
    assert forced.written


def test_sidecar_cannot_escape_output_dir(tmp_path, synthetic):
    ex = ingest_export(synthetic)
    ex["ghidra"]["sidecars"] = {"../../evil.c": "boom", "ghidra/ok/pseudo/0x1.c": "fine"}
    out = tmp_path / "out"
    write_extraction(ex, out)
    assert not (tmp_path / "evil.c").exists() and not (tmp_path.parent / "evil.c").exists()
    assert (out / "ghidra/ok/pseudo/0x1.c").read_text() == "fine"


def test_report_text_from_untrusted_names_cannot_inject_markup(tmp_path, synthetic):
    synthetic["functions"][2]["name"] = "evil|`name`\n# injected heading"
    write_extraction(ingest_export(synthetic), tmp_path / "o")
    text = next((tmp_path / "o").glob("GHIDRA_REPORT_*.md")).read_text(encoding="utf-8")
    assert "\n# injected heading" not in text


# ------------------------------------------------------------------- callchain

def test_callchain_follows_calls_not_the_binary_hub(graph_dir):
    cg = load_call_graph(graph_dir / "graph.json")
    chains = cg.chains("entry", "connect")
    assert chains, "entry reaches connect"
    labels = [[cg.nodes[n]["label"] for n in c] for c in chains]
    assert labels[0] == ["entry", "main", "FUN_net", "connect"], "no shortcut through the binary node"
    assert "sample.exe" not in labels[0]


def test_callchain_to_capability_expands_members(graph_dir):
    cg = load_call_graph(graph_dir / "graph.json")
    chain = cg.chains("entry", "Code injection")[0]
    assert cg.nodes[chain[-1]]["label"] in {"FUN_inject", "WriteProcessMemory"}


def test_callchain_unreachable_returns_empty(graph_dir):
    cg = load_call_graph(graph_dir / "graph.json")
    assert cg.chains("entry", "CreateRemoteThread") == [], "only an unreferenced callback calls it"
    assert cg.chains("FUN_net", "entry") == [], "calls are directed"


def test_callers_tree_marks_entry(graph_dir):
    cg = load_call_graph(graph_dir / "graph.json")
    rows = cg.callers_tree("connect", depth=5)
    labels = [(d, cg.nodes[n]["label"]) for d, n in rows]
    assert labels[0] == (1, "FUN_net") and (3, "entry") in labels
    assert cg.is_entry(next(n for d, n in rows if cg.nodes[n]["label"] == "entry"))


def test_resolution_by_address_label_and_ambiguity(graph_dir):
    cg = load_call_graph(graph_dir / "graph.json")
    assert cg.nodes[cg.resolve_one("0x401100")]["label"] == "main"
    assert cg.nodes[cg.resolve_one("MAIN")]["label"] == "main"
    with pytest.raises(KeyError):
        cg.resolve_one("definitely_not_here")
    with pytest.raises(AmbiguousNode):
        cg.resolve_one("FUN_")


def test_direction_survives_undirected_storage(tmp_path, synthetic):
    write_extraction(ingest_export(synthetic), tmp_path / "u", directed=False)
    cg = load_call_graph(tmp_path / "u" / "graph.json")
    assert cg.chains("entry", "connect"), "_src/_tgt keep direction even when the graph is undirected"
    assert cg.chains("connect", "entry") == []


# ------------------------------------------------------------------------ CLI

def run_cli(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_ingest_report_and_queries(tmp_path, capsys, synthetic):
    export = tmp_path / "s.ghidra.json"
    export.write_text(json.dumps(synthetic), encoding="utf-8")
    out = tmp_path / "go"

    code, stdout, stderr = run_cli(capsys, "ingest", str(export), "--out", str(out))
    assert code == 0 and "graph.json" in stdout and "functions" in stderr

    code, stdout, _ = run_cli(capsys, "report", str(export))
    assert code == 0 and "Where to start reading" in stdout and "Blind spots" in stdout

    code, stdout, _ = run_cli(capsys, "callchain", "entry", "connect", "--graph", str(out / "graph.json"), "-k", "1")
    assert code == 0 and "entry [0x401000]" in stdout and "-> connect" in stdout

    code, stdout, _ = run_cli(capsys, "callchain", "entry", "CreateRemoteThread", "--graph", str(out / "graph.json"))
    assert code == 1 and "not proof" in stdout

    code, stdout, _ = run_cli(capsys, "callers", "WriteProcessMemory", "--graph", str(out / "graph.json"))
    assert code == 0 and "FUN_inject" in stdout and "ENTRY POINT" in stdout


def test_cli_ingest_rea_requires_name(tmp_path, capsys):
    f = tmp_path / "rea.json"
    f.write_text(json.dumps([{"address": "0x1", "value": "f", "procedure": {"external": False}}]))
    with pytest.raises(SystemExit) as exc:
        main(["ingest", str(f), "--out", str(tmp_path / "o")])
    assert "--name" in str(exc.value)


def test_cli_ingest_rea_with_name(tmp_path, capsys):
    f = tmp_path / "rea.json"
    f.write_text(json.dumps([{"address": "0x1000", "value": "main", "procedure": {"external": False}}]))
    code, _, _ = run_cli(capsys, "ingest", str(f), "--name", "app.exe", "--out", str(tmp_path / "o"))
    assert code == 0 and (tmp_path / "o" / "graph.json").is_file()


def test_cli_rejects_garbage_input(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{}")
    with pytest.raises(SystemExit):
        main(["report", str(f), "--name", "x"])


def test_cli_missing_graph_is_a_clear_error(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["callers", "x", "--graph", str(tmp_path / "nope.json")])
    assert "not found" in str(exc.value)


def test_install_skill_dry_run_then_apply_with_backup(tmp_path, capsys):
    dest = tmp_path / "skills"
    code, stdout, _ = run_cli(capsys, "install-skill", "--dest", str(dest))
    assert code == 0 and "Dry run" in stdout and not dest.exists(), "dry run must write nothing"
    run_cli(capsys, "install-skill", "--dest", str(dest), "--apply")
    target = dest / "graphify-ghidra" / "SKILL.md"
    assert target.is_file() and target.read_text(encoding="utf-8").startswith("---")
    target.write_text("local edits", encoding="utf-8")
    run_cli(capsys, "install-skill", "--dest", str(dest), "--apply")
    assert (dest / "graphify-ghidra" / "SKILL.md.bak").read_text() == "local edits", "existing file is backed up"


# ---------------------------------------------------------------------- runner

def test_find_ghidra_honours_env_and_parent_dir(tmp_path, monkeypatch):
    root = tmp_path / "ghidra_99_PUBLIC"
    (root / "support").mkdir(parents=True)
    (root / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")).write_text("")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(root))
    assert find_ghidra() == root
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))      # parent of the release
    assert find_ghidra() == root
    assert find_ghidra(root) == root                              # explicit wins


def test_find_ghidra_failure_names_the_fix(tmp_path, monkeypatch):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setattr("graphify_ghidra.ghidra_runner._candidates", lambda: [])
    monkeypatch.setattr("shutil.which", lambda *_: None)
    with pytest.raises(GhidraNotFound) as exc:
        find_ghidra(tmp_path / "missing")
    assert "GHIDRA_INSTALL_DIR" in str(exc.value) and "never installs" in str(exc.value)


@pytest.mark.parametrize("rc,log,needle", [
    (1, "UnsupportedClassVersionError", "Java version"),
    (1, "Unable to find a loader for file", "--language"),
    (1, "nothing special", "without writing an export"),
])
def test_failure_diagnosis(rc, log, needle):
    assert needle in _diagnose(rc, log)


def test_export_binary_rejects_missing_file(tmp_path):
    from graphify_ghidra.ghidra_runner import ExportFailed, export_binary
    with pytest.raises(ExportFailed):
        export_binary(tmp_path / "nope.bin", tmp_path / "o.json")


# ------------------------------------------------------- real Ghidra (opt-in)

@pytest.mark.skipif(os.environ.get("GRAPHIFY_GHIDRA_INTEGRATION") != "1",
                    reason="set GRAPHIFY_GHIDRA_INTEGRATION=1 to run against a real Ghidra install")
def test_real_ghidra_export_of_a_system_binary(tmp_path):
    from graphify_ghidra.ghidra_runner import export_binary
    candidates = [Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "whoami.exe", Path("/bin/ls")]
    binary = next((c for c in candidates if c.is_file()), None)
    if binary is None:
        pytest.skip("no stock binary available")
    res = export_binary(binary, tmp_path / "x.json", decompile=3)
    doc = json.loads(res.out_path.read_text(encoding="utf-8"))
    ex = ingest_export(doc)
    assert ex["ghidra"]["summary"]["functions"] > 20
    assert ex["ghidra"]["summary"]["decompiled"] >= 1
    assert any(n["metadata"]["ghidra_kind"] == "import" for n in ex["nodes"])


def test_reingesting_the_owner_of_a_shared_node_does_not_orphan_the_other_binary(tmp_path, synthetic):
    """graphify attributes a node to one file and replaces a file's contribution wholesale; shared
    capability/import nodes must survive the owner being re-ingested without them."""
    from graphify_ghidra import ProgramOptions
    out = tmp_path / "go"
    a = json.loads(json.dumps(synthetic))
    b = json.loads(json.dumps(synthetic))
    b["program"].update(name="owner.exe", sha256="cd" * 32, executable_path="/C:/samples/owner.exe")
    write_extraction(ingest_export(a), out)
    write_extraction(ingest_export(b), out)            # b ingested last: graphify keeps its copy of shared nodes

    def exhibits(path_name):
        g = json.loads((out / "graph.json").read_text(encoding="utf-8"))
        return sum(1 for e in g["links"] if e["relation"] == "exhibits" and e["source_file"].endswith(path_name))

    before_a = exhibits("sample.exe")
    assert before_a > 0
    write_extraction(ingest_export(b, ProgramOptions(include_capabilities=False)), out, force=True)
    g = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    ids = {n["id"] for n in g["nodes"]}
    assert exhibits("sample.exe") == before_a, "binary A keeps every capability edge"
    assert exhibits("owner.exe") == 0, "binary B's own were removed, as requested"
    assert all(e["source"] in ids and e["target"] in ids for e in g["links"]), "no dangling edges"
    assert sum(1 for n in g["nodes"] if (n.get("metadata") or {}).get("ghidra_kind") == "capability") >= 3
