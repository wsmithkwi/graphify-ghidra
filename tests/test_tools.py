import json
import re

import pytest

from graphify_ghidra.tools import TOOLS, run_tool, substitute_names, suggestions_for, MAX_TEXT
from graphify_ghidra.workspace import Workspace

SCOPE = "sample_exe_abababab"


def call(ws, name, **args):
    return run_tool(ws, name, args)


def ok(ws, name, **args):
    good, text = run_tool(ws, name, args)
    assert good, text
    return text


def by_label(ws, label):
    return next(n for n, d in ws.nodes.items() if d["label"] == label)


# ------------------------------------------------------------------ resolution

def test_resolve_by_address_name_scope_and_body(ws):
    main = ws.resolve("0x401100")
    assert ws.nodes[main]["label"] == "main"
    assert ws.resolve("main") == main and ws.resolve("MAIN") == main
    assert ws.resolve(f"{SCOPE}:0x401100") == main and ws.resolve(main) == main
    assert ws.resolve("0x401150") == main, "an address inside a function body resolves to it"
    with pytest.raises(Exception):
        ws.resolve("0x500000")      # nothing there


def test_unknown_and_ambiguous_references_are_clean_errors(ws):
    good, text = call(ws, "ghidra_function", address="0x1")
    assert not good and "not found" in text
    good, text = call(ws, "ghidra_function", address="FUN_")
    assert not good and "several" in text and "0x" in text
    good, text = call(ws, "ghidra_nope")
    assert not good and "unknown tool" in text


def test_no_graph_gives_actionable_error(tmp_path):
    w = Workspace(tmp_path / "missing")
    good, text = run_tool(w, "ghidra_status", {})
    assert good and "ghidra_analyze" in text and "background" in text, "status explains how to start"
    good, text = run_tool(w, "ghidra_worklist", {})
    assert not good and "ghidra_analyze" in text, "every other tool points at the way in, not at internals"
    assert "ghidra_kind" not in text


# -------------------------------------------------------------------- status / worklist

def test_status_reports_coverage_and_nudges(ws):
    text = ok(ws, "ghidra_status")
    assert "sample.exe" in text and "unnamed" in text and "Name every function you understand" in text
    assert "live decompile/disasm/xrefs: NOT available" in text


def test_worklist_skips_named_library_and_examined(ws):
    text = ok(ws, "ghidra_worklist", limit=20)
    addrs = re.findall(r"^\d+\. (0x[0-9a-f]+)", text, re.M)
    assert "0x401100" not in addrs, "main is named by the analyst in Ghidra"
    lib = ws.resolve("_Init_thread_footer")
    assert ws.meta(lib)["address"] not in addrs, "FID library matches are skipped"
    assert {"0x401200", "0x401300"} <= set(addrs)
    ok(ws, "ghidra_name", items=[{"address": "0x401600", "note": "indirect-only; unclear"}])
    assert "0x401600" not in re.findall(r"^\d+\. (0x[0-9a-f]+)", ok(ws, "ghidra_worklist", limit=20), re.M)


def test_worklist_bottom_up_gets_easier_as_callees_are_named(ws):
    before = ok(ws, "ghidra_worklist", limit=20)
    ok(ws, "ghidra_name", items=[{"address": "0x401200", "name": "net_send", "confidence": "high"}])
    after = ok(ws, "ghidra_worklist", limit=20)
    wrapper_block = lambda t: re.search(r"(0x401400.*?)(?=\n\d+\. 0x|\nUse ghidra)", t, re.S).group(1)
    assert "net_send" not in wrapper_block(before)
    assert "net_send" in wrapper_block(after), "the wrapper now shows its named callee as context"


def test_worklist_modes(ws):
    assert "mode=unreached" in ok(ws, "ghidra_worklist", mode="unreached")
    caps = ok(ws, "ghidra_worklist", mode="capable", limit=20)
    assert "0x401400" not in re.findall(r"^\d+\. (0x[0-9a-f]+)", caps, re.M), "wrapper has no capability"
    assert call(ws, "ghidra_worklist", limit=999)[0], "oversized limit is clamped, not an error"


# -------------------------------------------------------------------- function / refs

def test_function_dossier_contents(ws):
    text = ok(ws, "ghidra_function", address="0x401200")
    for needle in ("UNNAMED", "callers (", "imports (", "connect", "capabilities (inferred): Networking",
                   "strings (1)", "beacon"):
        assert needle in text, needle
    assert "ghidra_name this function" in text


def test_refs_paging_and_cap(ws):
    full = ok(ws, "ghidra_refs", target="0x401100", direction="outgoing", limit=200)
    total = int(re.search(r"(\d+) total", full).group(1))
    assert total >= 8
    p1 = ok(ws, "ghidra_refs", target="0x401100", direction="outgoing", limit=3)
    assert "showing 1-3" in p1 and "next: offset=3" in p1
    rows1 = [ln for ln in p1.splitlines() if ln.startswith("  ->")]
    p2 = ok(ws, "ghidra_refs", target="0x401100", direction="outgoing", limit=3, offset=3)
    rows2 = [ln for ln in p2.splitlines() if ln.startswith("  ->")]
    assert len(rows1) == 3 and len(rows2) == 3 and not set(rows1) & set(rows2), "pages are disjoint"
    huge = ok(ws, "ghidra_refs", target="0x401100", limit=100000)
    assert len([ln for ln in huge.splitlines() if ln.startswith("  ")]) <= 200 + 2, "hard cap"


def test_refs_directions_kinds_and_targets(ws):
    inc = ok(ws, "ghidra_refs", target="connect", direction="incoming")
    assert "FUN_net" in inc and "<-" in inc and "->" not in inc.split("legend")[1].split("\n", 1)[1]
    out = ok(ws, "ghidra_refs", target="FUN_net", direction="outgoing", kind="import")
    assert "connect" in out and "send" in out and "string" not in out
    s = ok(ws, "ghidra_refs", target="beacon", direction="incoming")
    assert "FUN_net" in s, "a string (found by substring) lists the functions that use it"
    d = ok(ws, "ghidra_refs", target="g_config", direction="incoming")
    assert "main" in d
    assert "direction must be" in call(ws, "ghidra_refs", target="main", direction="sideways")[1]


def test_refs_live_without_project_explains(ws):
    assert "No retained Ghidra project" in ok(ws, "ghidra_refs", target="main", live=True)


# --------------------------------------------------------------------------- name

def test_name_batch_applies_and_persists_to_graph(ws, ghidra_out):
    text = ok(ws, "ghidra_name", items=[
        {"address": "0x401200", "name": "net_send_beacon", "confidence": "high", "evidence": ["connect", "send"]},
        {"address": "0x401300", "name": "inject_payload", "confidence": "medium"},
        {"address": "0x401400", "name": "FUN_999"},               # invalid: auto-style name
        {"address": "0x999999", "name": "x_y"},                    # unknown
    ])
    assert "2 change(s) applied of 4" in text and "invalid" in text and "no function at" in text
    assert "Coverage:" in text
    g = json.loads((ghidra_out / "graph.json").read_text(encoding="utf-8"))
    assert {"net_send_beacon", "inject_payload"} <= {n["label"] for n in g["nodes"]}
    assert ws.nodes[ws.resolve("net_send_beacon")]["metadata"]["name_confidence"] == "high"
    assert "UNNAMED" not in ok(ws, "ghidra_function", address="net_send_beacon")


def test_name_protects_analyst_names_unless_forced(ws):
    t = ok(ws, "ghidra_name", items=[{"address": "0x401100", "name": "my_main"}])
    assert "protected" in t and "No changes" in t
    t = ok(ws, "ghidra_name", items=[{"address": "0x401100", "name": "my_main"}], force=True)
    assert "1 change" in t


def test_name_requires_items_and_bounds_batch(ws):
    assert "needs items" in ok(ws, "ghidra_name")
    assert "Too many" in ok(ws, "ghidra_name", items=[{"address": "0x1", "name": "a_b"}] * 81)
    assert "skipped a non-object" in ok(ws, "ghidra_name", items=["nope"])


def test_variable_rename_shows_in_cached_pseudo(ws, ghidra_out):
    ok(ws, "ghidra_name", items=[{"address": "0x401200", "name": "net_send_beacon",
                                  "variable": {"old": "param_1", "new": "host", "type": "HostInfo *"}}])
    side = ghidra_out / "ghidra" / SCOPE / "pseudo"
    side.mkdir(parents=True, exist_ok=True)
    (side / "0x401200.c").write_text("void FUN_00401200(HostInfo *param_1) {\n  FUN_cb(param_1->name);\n  FUN_00401300(0);\n}\n")
    text = ok(ws, "ghidra_function", address="net_send_beacon", pseudo=True)
    assert "void net_send_beacon(HostInfo *host)" in text and "host->name" in text
    assert "FUN_cb" in text, "unnamed neighbours keep their names"


def test_substitute_names_uses_current_names(ws):
    ok(ws, "ghidra_name", items=[{"address": "0x401700", "name": "dispatch_callback"}])
    assert substitute_names(ws, SCOPE, None, "call FUN_00401700(x); call FUN_00401300(y);") == \
           "call dispatch_callback(x); call FUN_00401300(y);"


# ----------------------------------------------------------------------- suggest

def test_suggest_wrappers_thunks_and_apply(ws):
    text = ok(ws, "ghidra_suggest")
    assert "FUN_wrapper" not in text    # shown by address, not name
    hints = suggestions_for(ws, ws.resolve("0x401400"))
    assert hints == [] or hints[0][1] in ("low", "medium")      # wrapper of an *unnamed* function: no confident hint
    ok(ws, "ghidra_name", items=[{"address": "0x401200", "name": "net_send_beacon"}])
    hints = suggestions_for(ws, ws.resolve("0x401400"))
    assert hints and hints[0][0] == "net_send_beacon_wrapper"
    applied = ok(ws, "ghidra_suggest", apply_wrappers=True)
    assert "Auto-named" in applied
    # heuristic names are provenance-tagged
    assert ws.meta(ws.resolve("net_send_beacon_wrapper"))["named_by"] == "heuristic"


# ------------------------------------------------------------- similar / propagate

def test_similar_finds_planted_copies_and_deep_search(ws):
    text = ok(ws, "ghidra_similar", address="0x402000")
    assert "0x402100" in text or "FUN_copy_b" in text
    deep = ok(ws, "ghidra_similar", address="0x402000", deep=True, min_score=0.5)
    assert "FUN_copy_b" in deep and "unnamed" in deep


def test_propagate_dry_run_then_apply(ws):
    assert "No unnamed function" in ok(ws, "ghidra_propagate"), "nothing to carry before anything is named"
    ok(ws, "ghidra_name", items=[{"address": "0x402000", "name": "recv_framed_message", "confidence": "high"}])
    dry = ok(ws, "ghidra_propagate", threshold=0.8)
    assert "proposal" in dry and "recv_framed_message" in dry and "apply=true" in dry
    assert "FUN_copy_b" not in ok(ws, "ghidra_function", address="0x402100").split("\n")[0].replace("FUN_copy_b  0x", "")  # dry run changed nothing
    assert ws.named_by(ws.resolve("0x402100")) is None
    done = ok(ws, "ghidra_propagate", threshold=0.8, apply=True)
    assert "Propagated 1 names" in done
    n = ws.resolve("0x402100")
    assert ws.named_by(n) == "propagated" and ws.nodes[n]["label"].startswith("recv_framed_message")
    assert "similar to" in ws.meta(n)["name_evidence"][0]
    # propagated names are never themselves a source (no runaway chains)
    ok(ws, "ghidra_name", items=[{"address": "0x402000", "name": "x_renamed", "confidence": "high"}], force=True)
    assert ws.named_by(ws.resolve("0x402100")) == "propagated"


# ------------------------------------------------------------------ link / behaviour

def test_link_tool(ws):
    t = ok(ws, "ghidra_link", links=[{"a": "0x401000", "b": "0x401700", "kind": "calls", "rationale": "callback table"},
                                      {"a": "0x401200", "b": "nope", "kind": "similar"},
                                      {"a": "0x401200", "b": "0x401300", "kind": "teleports"}])
    assert "1 link(s) saved" in t and "callback table" not in t.split("\n")[0]
    assert "kind must be one of" in t
    cc = ok(ws, "ghidra_callchain", source="entry", target="FUN_cb")
    assert "entry" in cc and "FUN_cb" in cc, "an asserted call closes a gap in the call graph"
    assert "needs links" in ok(ws, "ghidra_link")


def test_behavior_lifecycle(ws):
    assert "No behaviours defined" in ok(ws, "ghidra_behavior")
    ok(ws, "ghidra_behavior", action="define", id="net_io", label="Network I/O", members=["0x401200", "0x401100", "0x401300"])
    ok(ws, "ghidra_behavior", action="add", id="net_io", members=["0x401400"])
    shown = ok(ws, "ghidra_behavior", action="show", id="net_io")
    assert "Network I/O" in shown and shown.count("(0x401") == 4
    ok(ws, "ghidra_behavior", action="define", id="startup", label="Startup", members=["0x401000"])
    ok(ws, "ghidra_behavior", action="define", id="net_io", parent="startup")
    assert "sub-behaviours: net_io" in ok(ws, "ghidra_behavior", action="show", id="startup")
    assert "part of startup" in ok(ws, "ghidra_behavior", action="list")
    assert "cycle" in ok(ws, "ghidra_behavior", action="define", id="startup", parent="net_io")
    assert "deleted" in ok(ws, "ghidra_behavior", action="delete", id="net_io")
    assert "no behaviour" in ok(ws, "ghidra_behavior", action="show", id="net_io")
    assert "action must be" in ok(ws, "ghidra_behavior", action="explode")
    assert "needs id" in ok(ws, "ghidra_behavior", action="define")


def test_behavior_candidates_from_communities(ws):
    text = ok(ws, "ghidra_behavior", action="candidates")
    assert "community" in text or "No unassigned community" in text


# ----------------------------------------------------------------------- search

def test_search_kinds_and_caps(ws):
    assert "name" in ok(ws, "ghidra_search", query="FUN_net", kinds=["name"])
    s = ok(ws, "ghidra_search", query="203.0.113", kinds=["string"])
    assert "beacon" in s and "FUN_net" in s
    assert "WriteProcessMemory" in ok(ws, "ghidra_search", query="process", kinds=["api"])
    assert "0xdeadbeef" in ok(ws, "ghidra_search", query="0xDEADBEEF", kinds=["constant"])
    assert "No matches" in ok(ws, "ghidra_search", query="zzzzqqq")
    assert "at least 2" in ok(ws, "ghidra_search", query="a")
    capped = ok(ws, "ghidra_search", query="FUN_", limit=2)
    assert "(capped)" in capped and len([x for x in capped.splitlines() if x.startswith("name")]) == 2


def test_callchain_by_names_and_capability(ws):
    assert "entry" in ok(ws, "ghidra_callchain", source="entry", target="connect")
    assert "chain" in ok(ws, "ghidra_callchain", source="entry", target="Networking")
    assert "No call chain" in ok(ws, "ghidra_callchain", source="entry", target="CreateRemoteThread")


# ------------------------------------------------------------------------- live

def test_decompile_and_disasm_without_project_are_explicit(ws):
    assert "No retained Ghidra project" in ok(ws, "ghidra_decompile", addresses=["0x401200"])
    assert "needs addresses" in ok(ws, "ghidra_decompile")
    assert "No retained Ghidra project" in ok(ws, "ghidra_disasm", address="0x401200")


def test_all_outputs_respect_the_cap(ws):
    for name, args in (("ghidra_status", {}), ("ghidra_worklist", {"limit": 20}), ("ghidra_refs", {"target": "main", "limit": 200}),
                       ("ghidra_search", {"query": "0x", "limit": 100})):
        assert len(ok(ws, name, **args)) <= MAX_TEXT + 200


def test_registry_is_complete():
    assert set(TOOLS) == {"ghidra_status", "ghidra_worklist", "ghidra_function", "ghidra_refs", "ghidra_name",
                          "ghidra_suggest", "ghidra_similar", "ghidra_propagate", "ghidra_link", "ghidra_behavior",
                          "ghidra_decompile", "ghidra_disasm", "ghidra_search", "ghidra_callchain", "ghidra_analyze"}
