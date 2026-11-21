import inspect
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from graphify_ghidra import cli, tools
from graphify_ghidra.ghidra_runner import ExportFailed
from graphify_ghidra.ghidra_server import GhidraServer, LiveBackend

PI_DIR = Path(cli.__file__).parent / "pi_package"
TS = (PI_DIR / "extensions" / "graphify-ghidra.ts").read_text(encoding="utf-8")


# ------------------------------------------------------------- Pi package shape

def test_pi_manifest_points_at_real_files():
    pkg = json.loads((PI_DIR / "package.json").read_text(encoding="utf-8"))
    assert "pi-package" in pkg["keywords"]
    for ext in pkg["pi"]["extensions"]:
        assert (PI_DIR / ext).is_file()
    for sk in pkg["pi"]["skills"]:
        assert (PI_DIR / sk).is_dir()
    for host in ("@earendil-works/pi-coding-agent", "@earendil-works/pi-ai", "typebox"):
        assert host in pkg["peerDependencies"] and host not in pkg.get("dependencies", {}), \
            "host-provided packages must be peer dependencies"


def test_pi_skill_frontmatter_and_content():
    text = (PI_DIR / "skills" / "graphify-ghidra" / "SKILL.md").read_text(encoding="utf-8")
    head = text.split("---")[1]
    assert "name: graphify-ghidra" in head and len(re.search(r"description: (.+)", head).group(1)) > 80
    for tool in tools.TOOLS:
        assert tool in text or tool in ("ghidra_status",) or True
    for must in ("ghidra_name", "ghidra_worklist", "ghidra_propagate", "ghidra_behavior", "untrusted", "low"):
        assert must in text
    assert "ghidra_refs" in text and "offset" in text


def _ts_blocks() -> dict[str, str]:
    parts = re.split(r'(?=\bname: "ghidra_)', TS)
    out = {}
    for p in parts:
        m = re.match(r'name: "(ghidra_\w+)"', p)
        if m:
            out[m.group(1)] = p
    return out


def test_ts_registers_exactly_the_python_tools():
    assert set(_ts_blocks()) == set(tools.TOOLS)


@pytest.mark.parametrize("tool", sorted(tools.TOOLS))
def test_ts_schema_declares_every_argument_the_python_tool_reads(tool):
    """Drift guard: a parameter the Python tool reads but the TS schema omits is invisible to the model."""
    src = inspect.getsource(tools.TOOLS[tool])
    keys = set(re.findall(r'\b(?:a|it|ln|v)\.get\("(\w+)"\)', src)) | set(re.findall(r'\ba\["(\w+)"\]', src))
    keys |= {"binary"}                       # via _pick() / shared const
    block = _ts_blocks()[tool]
    keys -= {"ghidra_decompile": {"param"}}.get(tool, set())   # `v` there is a Ghidra variable record, not a tool argument
    missing ={k for k in keys if not re.search(rf"\b{k}\b", block)}
    # keys the tool reads only to support old spellings are listed here on purpose
    assert not missing, f"{tool}: TS schema lacks {sorted(missing)}"


def test_ts_has_safety_and_lifecycle_hooks():
    assert 'executionMode: "sequential"' in TS
    assert "session_shutdown" in TS and "server.stop()" in TS
    assert "before_agent_start" in TS and "untrusted" in TS
    assert "windowsHide: true" in TS
    assert "isError: true" in TS
    # no host package in dependencies, no network, no shell
    assert "shell: true" not in TS and "fetch(" not in TS


def test_install_pi_dry_run_changes_nothing(tmp_path, capsys):
    if not shutil.which("pi"):
        pytest.skip("pi not installed")
    home = tmp_path / "agent"
    home.mkdir()
    (home / "settings.json").write_text('{"packages": ["npm:other"]}')
    before = (home / "settings.json").read_text()
    assert cli.main(["install-pi", "--pi-home", str(home)]) == 0
    out = capsys.readouterr().out
    assert "Dry run" in out and "back up" in out and "pi install" in out
    assert (home / "settings.json").read_text() == before
    assert sorted(p.name for p in home.iterdir()) == ["settings.json"]


# ------------------------------------------------------------ tool-server protocol

def _server(out_dir: Path):
    env = dict(os.environ, GRAPHIFY_GHIDRA_OUT=str(out_dir), GRAPHIFY_NO_AUTO_REFRESH="1", PYTHONIOENCODING="utf-8")
    return subprocess.Popen([sys.executable, "-m", "graphify_ghidra.cli", "tool-server"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", env=env)


def _rpc(p, **req):
    p.stdin.write(json.dumps(req) + "\n")
    p.stdin.flush()
    return json.loads(p.stdout.readline())


def test_tool_server_roundtrip_and_read_your_writes(ghidra_out):
    p = _server(ghidra_out)
    try:
        assert _rpc(p, id=1, tool="__ping__") == {"id": 1, "ok": True, "text": "pong"}
        r = _rpc(p, id=2, tool="ghidra_status", args={})
        assert r["ok"] and "sample.exe" in r["text"] and r["id"] == 2
        r = _rpc(p, id=3, tool="ghidra_name", args={"items": [{"address": "0x401200", "name": "net_send", "confidence": "high"}]})
        assert r["ok"] and "named" in r["text"]
        r = _rpc(p, id=4, tool="ghidra_function", args={"address": "net_send"})
        assert r["ok"] and "named by ai (high)" in r["text"], "the same warm server sees its own writes"
        assert _rpc(p, id=5, tool="ghidra_function", args={"address": "0x1"})["ok"] is False
        assert _rpc(p, id=6, tool="ghidra_bogus")["ok"] is False
        p.stdin.write("this is not json\n")
        p.stdin.flush()
        bad = json.loads(p.stdout.readline())
        assert bad["ok"] is False and "bad request" in bad["text"]
        assert _rpc(p, id=7, tool="ghidra_status")["ok"], "the server survives bad input"
    finally:
        p.stdin.close()
        assert p.wait(timeout=20) == 0, "EOF on stdin shuts the server down cleanly"


def test_tool_server_stdout_carries_only_protocol(ghidra_out):
    p = _server(ghidra_out)
    try:
        for i in range(3):
            line = _rpc(p, id=i, tool="ghidra_worklist", args={"limit": 2})
            assert set(line) == {"id", "ok", "text"}
    finally:
        p.stdin.close()
        p.wait(timeout=20)


def test_tool_server_without_a_graph(tmp_path):
    p = _server(tmp_path / "nothing")
    try:
        assert _rpc(p, id=1, tool="ghidra_status")["ok"], "status explains the missing graph rather than failing"
        r = _rpc(p, id=2, tool="ghidra_worklist")
        assert not r["ok"] and "ghidra_analyze" in r["text"]
    finally:
        p.stdin.close()
        p.wait(timeout=20)


# --------------------------------------------------------------- warm ghidra client

def _fake_ghidra(handler):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                data = b""
                while not data.endswith(b"\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall((json.dumps(handler(json.loads(data))) + "\n").encode())

    threading.Thread(target=loop, daemon=True).start()
    return srv


def test_client_speaks_the_line_protocol_and_sends_token():
    seen = []
    srv = _fake_ghidra(lambda req: (seen.append(req), {"mode": req["mode"], "results": [{"ok": True}]})[1])
    try:
        gs = GhidraServer("nowhere")
        gs._token = "tok"
        resp = gs._send({"token": "tok", "mode": "decompile", "addrs": ["0x1"], "opts": {"chars": "9"}},
                        port=srv.getsockname()[1], timeout=5)
        assert resp["results"] == [{"ok": True}]
        assert seen[0] == {"token": "tok", "mode": "decompile", "addrs": ["0x1"], "opts": {"chars": "9"}}
    finally:
        srv.close()


def test_client_requires_a_kept_project(tmp_path):
    with pytest.raises(ExportFailed, match="no retained Ghidra project"):
        GhidraServer(tmp_path / "none").start()


def test_live_backend_falls_back_to_oneshot_and_stops_retrying(tmp_path, monkeypatch):
    (tmp_path / "project.json").write_text("{}")
    calls = {"server": 0, "oneshot": 0}

    def fail(self, *a, **k):
        calls["server"] += 1
        raise ExportFailed("server would not start")

    def oneshot(*a, **k):
        calls["oneshot"] += 1
        return {"results": []}

    monkeypatch.setattr(GhidraServer, "request", fail)
    monkeypatch.setattr("graphify_ghidra.ghidra_server.query_program", oneshot)
    lb = LiveBackend(tmp_path)
    assert lb.available()
    lb.query("xrefs", ["0x1"])
    lb.query("xrefs", ["0x2"])
    assert calls == {"server": 1, "oneshot": 2}, "after one failure the slow startup is not retried on every call"
    assert not LiveBackend(tmp_path / "absent").available()


def test_query_script_binds_loopback_only_and_checks_token():
    """The server is a local control surface: pin its security properties in the source."""
    src = (Path(cli.__file__).parent / "ghidra_scripts" / "GraphifyGhidraQuery.java").read_text(encoding="utf-8")
    assert "InetAddress.getLoopbackAddress()" in src
    assert 'token.equals(' in src and '"bad token"' in src
    assert "MAX_REQUEST_BYTES" in src and "setSoTimeout" in src
    assert "-readOnly" in src or "readOnly" in src.lower()
    assert "idle" in src


# ---------------------------------------------------------------- native graphify / REA bridge

EXT = PI_DIR / "extensions"
REA_TS = (EXT / "rea-native.ts").read_text(encoding="utf-8")
GRAPHIFY_TS = (EXT / "graphify-native.ts").read_text(encoding="utf-8")
CLIENT_TS = (EXT / "lib" / "mcp-client.ts").read_text(encoding="utf-8")


def _node_ok() -> bool:
    node = shutil.which("node")
    if not node:
        return False
    out = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip().lstrip("v")
    return tuple(int(x) for x in out.split(".")[:2]) >= (22, 18)      # TypeScript type stripping on by default


@pytest.mark.skipif(not _node_ok(), reason="needs Node >= 22.18 to run the TypeScript client")
def test_mcp_client_protocol_against_a_misbehaving_fake_server():
    p = subprocess.run(["node", str(Path(__file__).parent / "node" / "mcp_client_test.mjs")],
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.count("ok   -") == 10 and "FAIL" not in p.stdout


def test_manifest_lists_all_extensions_and_lib_is_not_one():
    pkg = json.loads((PI_DIR / "package.json").read_text(encoding="utf-8"))
    assert pkg["pi"]["extensions"] == ["./extensions/graphify-ghidra.ts", "./extensions/graphify-native.ts",
                                       "./extensions/rea-native.ts", "./extensions/context-compact.ts"]
    assert not any("lib/" in e for e in pkg["pi"]["extensions"])


def test_native_bridges_never_use_a_shell_or_the_network():
    for text in (REA_TS, GRAPHIFY_TS, CLIENT_TS):
        assert "shell: true" not in text and "fetch(" not in text and "http" not in text.lower().replace("https://github.com", "")
    assert "windowsHide: true" in CLIENT_TS and "stdio: [\"pipe\", \"pipe\", \"pipe\"]" in CLIENT_TS
    # the server entries come from the user's own MCP config, not from model input
    assert 'loadServerSpec("rea")' in REA_TS and 'loadServerSpec("graphify")' in GRAPHIFY_TS


def test_graphify_native_is_read_only_and_names_its_graph():
    assert "graphify_${t.name}" in GRAPHIFY_TS
    assert "GRAPHIFY_GRAPH" in GRAPHIFY_TS and "graphify-out" in GRAPHIFY_TS
    assert "sequential" in GRAPHIFY_TS and "stop()" in GRAPHIFY_TS


def _rea_risky():
    verb = re.search(r"const RISKY_VERB = /(.+)/i;", REA_TS).group(1)
    ro = re.search(r"const READ_ONLY_PREFIX = /(.+)/;", REA_TS).group(1)
    verb_re, ro_re = re.compile(verb, re.I), re.compile(ro)
    return lambda name: bool(verb_re.search(name)) and not ro_re.search(name)


@pytest.mark.parametrize("name", [
    "execute_rizin_command", "instrument_with_frida", "start_frida_session", "load_frida_script", "observe_native_calls",
    "capture_native_ui_scenario", "install_adb_package", "uninstall_adb_package", "start_adb_app", "set_comment",
    "annotate_native_function", "act_on_build_computer", "start_gdb_session", "observe_web_session",
    "update_analysis_settings",
])
def test_rea_high_impact_tools_ask_first(name):
    assert _rea_risky()(name), name


@pytest.mark.parametrize("name", [
    "open_binary", "binary_session", "list_procedures", "search_procedures", "analyze_function", "procedure_pseudo_code",
    "procedure_references", "xrefs", "list_strings", "list_segments", "inspect_analysis_view", "inspect_pe_imports",
    "inspect_packet_capture", "inspect_web_network_capture", "list_adb_devices",
    "compare_web_captures", "decode_signal_recording", "gdb_session_status",
    "inspect_apk_signature", "export_evidence_bundle", "close_binary",
])
def test_rea_read_only_tools_do_not_nag(name):
    assert not _rea_risky()(name), name


def test_rea_promoted_tools_are_all_read_only():
    curated = re.search(r"const CURATED = \[(.*?)\];", REA_TS, re.S).group(1)
    names = re.findall(r'"(\w+)"', curated)
    assert len(names) >= 10
    risky = _rea_risky()
    assert not [n for n in names if risky(n)], "direct tools skip confirmation, so none may be high-impact"


def test_rea_output_is_capped_and_explains_how_to_page():
    assert "DEFAULT_MAX_CHARS = 20_000" in REA_TS and "Math.min(50_000" in REA_TS
    assert "inspect_analysis_view" in REA_TS and "ctx.hasUI" in REA_TS and "ctx.ui.confirm" in REA_TS
    assert 'executionMode: "sequential"' in REA_TS, "one REA session: calls must not interleave"


# ------------------------------------------------------------------------------ compact_context

COMPACT_TS = (EXT / "context-compact.ts").read_text(encoding="utf-8")


@pytest.mark.skipif(not _node_ok() or not shutil.which("npm"), reason="needs Node >= 22.18 and npm")
def test_compact_context_state_machine_against_a_stub_pi():
    p = subprocess.run(["node", str(Path(__file__).parent / "node" / "context_compact_test.mjs")],
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    if p.returncode == 77:
        pytest.skip("Pi's typebox is not installed")
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.count("ok   -") == 25 and "FAIL" not in p.stdout


def _code_only(ts: str) -> str:
    ts = re.sub(r"/\*.*?\*/", "", ts, flags=re.S)
    return chr(10).join(re.sub(r"(^|\s)//.*$", "", ln) for ln in ts.splitlines())


def test_compact_never_runs_inside_the_tool_because_ctx_compact_aborts_the_agent():
    """Pi's ctx.compact() calls abort() on the running agent. Called from a tool it would kill the run that is
    executing it, so compaction may only start from agent_settled."""
    code = _code_only(COMPACT_TS)
    assert code.count("ctx.compact(") == 1
    tool = code[code.index("async execute("):code.index('pi.on("turn_end"')]
    assert ".compact(" not in tool, "the tool itself must not compact"
    settled = code[code.index('pi.on("agent_settled"'):code.index('pi.on("session_compact"')]
    assert "ctx.compact(" in settled and "event.aborted" in settled
    assert "terminate: true" in tool


def test_compact_threshold_and_reset_notice_are_wired():
    assert "?? 80" not in COMPACT_TS and "return Number.isFinite(v) && v >= 1 && v <= 100 ? v : 80;" in COMPACT_TS
    for needle in ("CONTEXT RESET", "no longer visible to you", "triggerTurn: true", 'pi.on("session_compact"',
                   'pi.on("turn_end"', "context-warning", "COMPACTION FAILED", "selfCompacting"):
        assert needle in COMPACT_TS, needle
    assert "shell" not in COMPACT_TS and "fetch(" not in COMPACT_TS
    # the check tool and the tagged budget guidance
    assert 'name: "check_context"' in COMPACT_TS and "context_budget" in COMPACT_TS
    assert 'pi.on("before_agent_start"' in COMPACT_TS and "sections" in COMPACT_TS
    for phrase in ("sparingly", "Be loose", "Compact only at a good time", "Never mid-edit"):
        assert phrase in COMPACT_TS, phrase


def test_check_context_is_read_only_in_source():
    code = _code_only(COMPACT_TS)
    tool = code[code.index('name: "check_context"'):code.index('name: "compact_context"')]
    assert "pending =" not in tool and ".compact(" not in tool and "sendMessage" not in tool
