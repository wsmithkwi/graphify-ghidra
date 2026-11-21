"""REA adapter tests.

The payloads below are shaped from REA's Ghidra bridge source
(bridge/ghidra/ReaGhidraBridge.java: ``resultItem``, ``procedureIdentity``,
``referenceEdge``, ``referenceKind``) and its documented
``structuredContent.normalized_result`` envelope. They are *not* captured from a
live REA run; the adapter's docstring says so too.
"""

import json

import pytest
from graphify.validate import validate_extraction

from graphify_ghidra import ingest_export, validate_export
from graphify_ghidra.rea_adapter import build_export, classify, load_payloads, unwrap


def proc(addr, name, **facts):
    return {"address": addr, "name": name, "symbol": None, "classification": {}, "body": {}, **facts}


def kind(**flags):
    base = {"available": True, "provenance": "ghidra-reference-manager", "type": "UNCONDITIONAL_CALL",
            "call": False, "data": False, "read": False, "write": False, "indirect": False,
            "computed": False, "conditional": False, "external": False}
    base.update(flags)
    return base


PROCEDURES = [
    {"address": "0x401000", "value": "entry", "procedure": {"external": False, "thunk": False}},
    {"address": "0x401100", "value": "FUN_00401100", "procedure": {"external": False, "thunk": False}},
    {"address": "0x401200", "value": "thunk_x", "procedure": {"external": False, "thunk": True,
                                                             "thunk_target": "0x500000"}},
    {"address": "EXTERNAL:0x1", "value": "connect", "procedure": {"external": True, "thunk": False}},
]
STRINGS = [
    {"address": "0x403010", "value": "http://203.0.113.9/x", "string": {"encoding": "US-ASCII", "byte_length": 21}},
]
SEGMENTS = [{"name": ".text", "start": "0x401000", "end": "0x402000", "readable": True, "writable": False,
             "executable": True}]
REFS_OUT = {
    "procedure": proc("0x401000", "entry"),
    "direction": "outgoing",
    "references": [
        {"source_address": "0x401005", "target_address": "0x401100",
         "source_procedure": proc("0x401000", "entry"), "target_procedure": proc("0x401100", "FUN_00401100"),
         "kind": kind(call=True)},
        {"source_address": "0x401010", "target_address": "EXTERNAL:0x1",
         "source_procedure": proc("0x401000", "entry"), "target_procedure": None,
         "kind": kind(call=True, computed=True, external=True, type="COMPUTED_CALL")},
        {"source_address": "0x401020", "target_address": "0x403010",
         "source_procedure": proc("0x401000", "entry"), "target_procedure": None, "kind": kind(data=True, read=True)},
    ],
    "unresolved_calls": [{"address": "0x401030", "reason": "register-indirect"}],
}


def mcp(payload):
    """What an MCP client hands back."""
    return {"content": [], "structuredContent": {"normalized_result": payload, "evidence_id": "e1"}}


def test_unwrap_peels_envelopes():
    assert unwrap(mcp([1])) == [1]
    assert unwrap({"normalized_result": {"a": 1}}) == {"a": 1}
    assert unwrap({"result": [2]}) == [2]
    assert unwrap([3]) == [3]
    env = {"tool": "xrefs", "arguments": {}, "result": [4]}
    assert unwrap(env) is env, "tool envelopes are kept: the tool name and arguments matter"


@pytest.mark.parametrize("payload,expected", [
    (PROCEDURES, "procedures"), (STRINGS, "strings"), (SEGMENTS, "segments"), (REFS_OUT, "references"),
    (mcp(PROCEDURES), "procedures"), ({"nope": 1}, "unknown"), ([], "unknown"), (["0x1", "0x2"], "unknown"),
])
def test_classify_by_shape(payload, expected):
    assert classify(payload)[0] == expected


def test_classify_tool_envelope_wins_for_bare_address_lists():
    kind_, data, args = classify({"tool": "procedure_callees", "arguments": {"procedure": "0x401000"},
                                  "result": ["0x401100"]})
    assert kind_ == "callees" and data == ["0x401100"] and args["procedure"] == "0x401000"


def build(*payloads):
    return build_export(list(payloads), program_name="app.exe", sha256="ef" * 32)


def test_full_adapter_roundtrip_produces_valid_export_and_graph():
    doc, warnings = build(mcp(PROCEDURES), mcp(STRINGS), mcp(SEGMENTS), mcp(REFS_OUT))
    assert validate_export(doc) == [] and warnings == []
    fns = {f["address"]: f for f in doc["functions"]}
    assert set(fns) == {"0x401000", "0x401100", "0x401200"}, "external procedures become imports, not functions"
    assert fns["0x401200"]["is_thunk"] and fns["0x401200"]["thunk_target"] == "0x500000"
    assert [i["name"] for i in doc["imports"]] == ["connect"]

    ex = ingest_export(doc)
    assert validate_extraction(ex) == []
    labels = {n["label"] for n in ex["nodes"]}
    assert {"entry", "FUN_00401100", "connect", "http://203.0.113.9/x"} <= labels
    rel = {(e["relation"]) for e in ex["edges"]}
    assert {"calls", "references", "exhibits"} <= rel
    assert ex["ghidra"]["summary"]["unresolved_call_sites"] == 1


def test_adapter_edge_kinds():
    doc, _ = build(mcp(PROCEDURES), mcp(STRINGS), mcp(REFS_OUT))
    by = {(c.get("to") or c.get("external_name") or "?"): c for c in doc["calls"] if not c.get("unresolved")}
    assert by["0x401100"]["kind"] == "UNCONDITIONAL_CALL"
    assert by["connect"]["kind"] == "COMPUTED_CALL"
    s = {s["address"]: s for s in doc["strings"]}["0x403010"]
    assert s["refs"] == ["0x401000"]


def test_callees_envelope_adds_edges():
    env = {"tool": "procedure_callees", "arguments": {"procedure": "0x401000"}, "result": ["0x401100"]}
    doc, w = build(mcp(PROCEDURES), env)
    assert w == [] and {"from": "0x401000", "to": "0x401100", "kind": "CALL"} in doc["calls"]


def test_callers_direction_is_reversed():
    env = {"tool": "procedure_callers", "arguments": {"procedure": "0x401100"}, "result": ["0x401000"]}
    doc, _ = build(mcp(PROCEDURES), env)
    assert {"from": "0x401000", "to": "0x401100", "kind": "CALL"} in doc["calls"]


def test_bare_address_list_is_reported_not_guessed():
    doc, warnings = build(mcp(PROCEDURES), ["0x401100", "0x401200"])
    assert doc["calls"] == []
    assert any("not a recognised REA result" in w for w in warnings)


def test_xref_from_instruction_address_is_warned_not_misattributed():
    env = {"tool": "xrefs", "arguments": {"address": "0x403010"}, "result": ["0x401020"]}
    doc, warnings = build(mcp(PROCEDURES), mcp(STRINGS), env)
    assert any("not a function entry" in w for w in warnings)
    assert doc["strings"][0]["refs"] == []


def test_xref_from_function_entry_attaches_to_string():
    env = {"tool": "xrefs", "arguments": {"address": "0x403010"}, "result": ["0x401100"]}
    doc, warnings = build(mcp(PROCEDURES), mcp(STRINGS), env)
    assert warnings == [] and doc["strings"][0]["refs"] == ["0x401100"]


def test_native_export_is_flagged_not_silently_reimported(synthetic):
    _, warnings = build(synthetic)
    assert any("already a graphify-ghidra export" in w for w in warnings)


def test_load_payloads_file_shapes(tmp_path):
    one = tmp_path / "one.json"
    one.write_text(json.dumps(mcp(PROCEDURES)))
    many = tmp_path / "many.json"
    many.write_text(json.dumps([mcp(STRINGS), mcp(SEGMENTS)]))
    lines = tmp_path / "lines.jsonl"
    lines.write_text(json.dumps(mcp(STRINGS)) + "\n" + json.dumps(mcp(SEGMENTS)) + "\n")
    bare_list = tmp_path / "bare.json"
    bare_list.write_text(json.dumps(PROCEDURES))
    empty = tmp_path / "empty.json"
    empty.write_text("")
    assert len(load_payloads([one])) == 1
    assert len(load_payloads([many])) == 2
    assert len(load_payloads([lines])) == 2
    # A bare inventory list is ONE payload (rows), not many payloads.
    assert len(load_payloads([bare_list])) == 1 and classify(load_payloads([bare_list])[0])[0] == "procedures"
    assert load_payloads([empty]) == []
