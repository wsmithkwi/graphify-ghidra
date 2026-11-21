"""The way in: where Ghidra data lives, never touching someone else's graph, and starting an analysis from
inside the agent loop (the gap that made the whole naming loop unusable in a fresh project)."""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from graphify_ghidra import ingest_export, jobs, write_extraction
from graphify_ghidra.cli import main
from graphify_ghidra.graph_io import ForeignGraphError
from graphify_ghidra.tools import run_tool
from graphify_ghidra.workspace import DEFAULT_OUT_NAME, Workspace, has_ghidra_data, resolve_out


def plain_graph(dir_: Path) -> Path:
    """A graphify graph of *source code*: nodes, no binary."""
    dir_.mkdir(parents=True, exist_ok=True)
    g = {"directed": False, "nodes": [{"id": "a_py", "label": "a.py", "file_type": "code", "source_file": "a.py"}],
         "links": [], "hyperedges": []}
    (dir_ / "graph.json").write_text(json.dumps(g), encoding="utf-8")
    return dir_ / "graph.json"


# ------------------------------------------------------------------ out-dir rule

def test_resolve_out_precedence(tmp_path, monkeypatch):
    monkeypatch.delenv("GRAPHIFY_GHIDRA_OUT", raising=False)
    assert resolve_out(tmp_path) == tmp_path / DEFAULT_OUT_NAME, "default is its own folder"
    plain_graph(tmp_path / "graphify-out")
    assert resolve_out(tmp_path) == tmp_path / DEFAULT_OUT_NAME, "a plain graphify graph is never adopted"
    ghidra = tmp_path / "graphify-out" / "ghidra"
    ghidra.mkdir()
    (ghidra / "x.summary.json").write_text("{}")
    assert resolve_out(tmp_path) == tmp_path / "graphify-out", "older installs that already hold Ghidra data keep working"
    monkeypatch.setenv("GRAPHIFY_GHIDRA_OUT", str(tmp_path / "elsewhere"))
    assert resolve_out(tmp_path) == tmp_path / "elsewhere"
    assert resolve_out(tmp_path, explicit=tmp_path / "chosen") == tmp_path / "chosen"
    assert has_ghidra_data(tmp_path / "graphify-out") and not has_ghidra_data(tmp_path / "nope")


# --------------------------------------------------------------------- the guard

def test_write_refuses_a_foreign_graph_and_leaves_it_byte_identical(tmp_path, synthetic):
    gp = plain_graph(tmp_path / "graphify-out")
    before = gp.read_bytes()
    with pytest.raises(ForeignGraphError, match="not touched"):
        write_extraction(ingest_export(synthetic), tmp_path / "graphify-out")
    assert gp.read_bytes() == before
    assert not (tmp_path / "graphify-out" / "ghidra").exists(), "nothing else was written either"


def test_write_allows_explicit_merge_new_dirs_and_reingest(tmp_path, synthetic):
    plain_graph(tmp_path / "mine")
    write_extraction(ingest_export(synthetic), tmp_path / "mine", allow_foreign_merge=True)
    g = json.loads((tmp_path / "mine" / "graph.json").read_text(encoding="utf-8"))
    assert "a_py" in {n["id"] for n in g["nodes"]}, "the user's own nodes survive an explicit merge"
    assert any((n.get("metadata") or {}).get("ghidra_kind") == "binary" for n in g["nodes"])
    write_extraction(ingest_export(synthetic), tmp_path / "mine")        # now it holds a binary: a normal re-ingest
    write_extraction(ingest_export(synthetic), tmp_path / "fresh")       # brand-new folder


def test_cli_analyze_fails_fast_before_starting_ghidra(tmp_path, monkeypatch):
    plain_graph(tmp_path / "out")
    binary = tmp_path / "x.dll"
    binary.write_bytes(b"MZ")
    import graphify_ghidra.ghidra_runner as gr
    monkeypatch.setattr(gr, "export_binary", lambda *a, **k: pytest.fail("Ghidra must not start"))
    with pytest.raises(SystemExit, match="not touching it"):
        main(["analyze", str(binary), "--out", str(tmp_path / "out")])


def test_cli_ingest_returns_4_for_a_foreign_graph(tmp_path, synthetic, capsys):
    plain_graph(tmp_path / "out")
    export = tmp_path / "e.json"
    export.write_text(json.dumps(synthetic), encoding="utf-8")
    assert main(["ingest", str(export), "--out", str(tmp_path / "out")]) == 4
    assert "--merge-into-existing" in capsys.readouterr().err


# ------------------------------------------------------------- status / analyze tools

def test_status_before_any_analysis_is_a_way_in(tmp_path):
    ok, text = run_tool(Workspace(tmp_path / "graphify-out-ghidra"), "ghidra_status", {})
    assert ok and 'ghidra_analyze {binary: "<absolute path' in text and "does not touch any existing graph" in text


def test_status_notes_an_existing_foreign_graph_is_left_alone(tmp_path):
    plain_graph(tmp_path / "o")
    ok, text = run_tool(Workspace(tmp_path / "o"), "ghidra_status", {})
    assert ok and "ordinary graphify graph" in text and "untouched" in text


def test_other_tools_point_at_the_way_in(tmp_path):
    ws = Workspace(tmp_path / "none")
    for name, args in (("ghidra_worklist", {}), ("ghidra_name", {"items": []}), ("ghidra_search", {"query": "abc"}),
                       ("ghidra_function", {"address": "0x1"})):
        ok, text = run_tool(ws, name, args)
        assert not ok and "ghidra_analyze" in text, name
        assert "ghidra_kind" not in text, "no internals leaked into the message"


def test_analyze_tool_validates_input(tmp_path):
    ws = Workspace(tmp_path / "o")
    ok, text = run_tool(ws, "ghidra_analyze", {})
    assert ok and "needs binary" in text
    ok, text = run_tool(ws, "ghidra_analyze", {"binary": str(tmp_path / "missing.dll")})
    assert ok and "is not a file" in text
    assert not (tmp_path / "o").exists(), "a rejected request creates nothing"


class FakePopen:
    calls: list = []

    def __init__(self, cmd, **kw):
        FakePopen.calls.append((cmd, kw))
        self.pid = os.getpid()      # a live pid, so the job counts as running


def test_analyze_starts_a_detached_job_and_refuses_a_second(tmp_path, monkeypatch):
    FakePopen.calls.clear()
    monkeypatch.setattr(jobs.subprocess, "Popen", FakePopen)
    binary = tmp_path / "ccl_x.dll"
    binary.write_bytes(b"MZ")
    ws = Workspace(tmp_path / "out")
    ok, text = run_tool(ws, "ghidra_analyze", {"binary": str(binary), "decompile": 10, "language": "x86:LE:64:default"})
    assert ok and "Started analysis of ccl_x.dll in the background" in text
    cmd, kw = FakePopen.calls[0]
    assert cmd[1:4] == ["-m", "graphify_ghidra.cli", "_job"] and cmd[5] == "--" and cmd[6] == "analyze"
    assert str(binary.resolve()) in cmd and "--decompile" in cmd and "10" in cmd and "x86:LE:64:default" in cmd
    assert str((tmp_path / "out").resolve()) in cmd, "output goes where the tools will look"
    assert kw["stdin"] is subprocess.DEVNULL and "shell" not in kw, "no shell, no stdin"
    assert kw["env"]["GRAPHIFY_NO_AUTO_REFRESH"] == "1"
    if os.name == "nt":
        assert kw["creationflags"] & subprocess.DETACHED_PROCESS
    else:
        assert kw["start_new_session"] is True
    job = jobs.read_job(tmp_path / "out")
    assert job["state"] == "running" and job["pid"] == os.getpid()
    ok, again = run_tool(ws, "ghidra_analyze", {"binary": str(binary)})
    assert "already running" in again and len(FakePopen.calls) == 1
    ok, status = run_tool(ws, "ghidra_status", {})
    assert "RUNNING" in status and "ccl_x.dll" in status, "status reports progress while there is still no graph"


def test_job_that_vanished_is_reported_died_not_running_forever(tmp_path):
    jp = jobs.job_path(tmp_path)
    jp.parent.mkdir(parents=True)
    jp.write_text(json.dumps({"state": "running", "pid": 2_000_000_000, "binary": "C:/x/a.dll", "started": time.time(),
                              "log": str(tmp_path / "nolog")}))
    job = jobs.read_job(tmp_path)
    assert job["state"] == "died" and "gone" in job["error"]
    assert "DIED" in jobs.job_summary(job)


def test_pid_alive():
    assert jobs.pid_alive(os.getpid())
    assert not jobs.pid_alive(0) and not jobs.pid_alive(2_000_000_000)


def _job_file(tmp_path):
    jp = jobs.job_path(tmp_path)
    jp.parent.mkdir(parents=True)
    jp.write_text(json.dumps({"state": "starting", "binary": "x", "started": time.time(), "pid": 0, "log": ""}))
    return jp


def test_run_job_records_success_and_failure(tmp_path):
    jp = _job_file(tmp_path)
    assert jobs.run_job(jp, ["--version"]) == 0            # argparse exits through SystemExit(0)
    assert json.loads(jp.read_text())["state"] == "done"
    assert jobs.run_job(jp, ["analyze", str(tmp_path / "not-a-file.dll")]) != 0
    j = json.loads(jp.read_text())
    assert j["state"] == "failed" and "not a file" in j["error"] and j["exit_code"] != 0


def test_job_subcommand_is_wired_through_the_cli(tmp_path):
    jp = _job_file(tmp_path)
    assert main(["_job", str(jp), "--", "--version"]) == 0
    assert json.loads(jp.read_text())["state"] == "done"
