from collections import Counter

import pytest
from graphify.validate import validate_extraction

from graphify_ghidra import ProgramOptions, ingest_export
from graphify_ghidra.analysis import analyze
from graphify_ghidra.program import Program


def by_kind(ex):
    out = {}
    for n in ex["nodes"]:
        out.setdefault(n["metadata"]["ghidra_kind"], []).append(n)
    return out


def node(ex, label):
    return next(n for n in ex["nodes"] if n["label"] == label)


def edges(ex, rel, src=None, dst=None):
    ids = {n["label"]: n["id"] for n in ex["nodes"]}
    return [e for e in ex["edges"] if e["relation"] == rel
            and (src is None or e["source"] == ids[src]) and (dst is None or e["target"] == ids[dst])]


# ----------------------------------------------------------------- graph shape

def test_extraction_is_schema_valid_and_endpoint_safe(synthetic):
    ex = ingest_export(synthetic)
    assert validate_extraction(ex) == []
    ids = {n["id"] for n in ex["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in ex["edges"])
    assert len(ids) == len(ex["nodes"]), "node ids must be unique"


def test_node_kinds(synthetic):
    kinds = by_kind(ingest_export(synthetic))
    assert len(kinds["binary"]) == 1
    assert len(kinds["function"]) == 8 and len(kinds["thunk"]) == 1
    assert {n["label"] for n in kinds["import"]} == {"connect", "send", "WriteProcessMemory", "CreateRemoteThread", "GetTickCount"}
    assert {n["label"] for n in kinds["library"]} == {"WS2_32.DLL", "KERNEL32.DLL"}
    assert len(kinds["segment"]) == 2
    assert kinds["capability"], "capability concepts expected"


def test_file_types_are_graphify_valid(synthetic):
    ex = ingest_export(synthetic)
    ft = {n["metadata"]["ghidra_kind"]: n["file_type"] for n in ex["nodes"]}
    assert ft["function"] == "code" and ft["capability"] == "concept" and ft["string"] == "document"
    assert ft["comment"] == "rationale"


def test_source_file_is_cleaned_path(synthetic):
    ex = ingest_export(synthetic)
    assert {n["source_file"] for n in ex["nodes"]} == {"C:/samples/sample.exe"}


def test_function_source_location_is_address(synthetic):
    fn = node(ingest_export(synthetic), "main")
    assert fn["source_location"] == "0x401100"
    assert fn["metadata"]["address"] == "0x401100"


# --------------------------------------------------------------------- calls

def test_direct_calls_extracted_computed_calls_inferred(synthetic):
    ex = ingest_export(synthetic)
    direct = edges(ex, "calls", "main", "FUN_net")[0]
    assert direct["confidence"] == "EXTRACTED"
    assert direct["weight"] == 2.0, "two call sites aggregate into one weighted edge"
    assert "2 call sites" in direct["context"]
    computed = edges(ex, "calls", "main", "FUN_viaptr")[0]
    assert computed["confidence"] == "INFERRED" and computed["confidence_score"] < 1.0
    assert "computed/indirect" in computed["context"]


def test_import_calls_are_observations_not_inferences(synthetic):
    # `connect` is a COMPUTED_CALL in Ghidra's flow types (CALL [IAT]) but the target
    # is fixed by the loader.
    e = edges(ingest_export(synthetic), "calls", "FUN_net", "connect")[0]
    assert e["confidence"] == "EXTRACTED"


def test_unresolved_calls_do_not_become_edges_but_are_counted(synthetic):
    ex = ingest_export(synthetic)
    assert ex["ghidra"]["summary"]["unresolved_call_sites"] == 1
    # 7 unique fn->fn pairs (main->FUN_net's two sites aggregate) + 4 fn->import pairs;
    # the unresolved site contributes no edge.
    assert Counter(e["relation"] for e in ex["edges"])["calls"] == 7 + 4


def test_thunk_edge(synthetic):
    synthetic["functions"].append({**synthetic["functions"][0], "address": "0x500000", "name": "real_connect",
                                   "is_entry": False})
    ex = ingest_export(synthetic)
    assert edges(ex, "thunks_to", "thunk_connect", "real_connect")


def test_unused_import_is_kept_and_flagged(synthetic):
    n = node(ingest_export(synthetic), "GetTickCount")
    assert n["metadata"]["called_by_code"] is False
    assert node(ingest_export(synthetic), "connect")["metadata"]["called_by_code"] is True


# ---------------------------------------------------------------- capabilities

def test_capability_edges_are_inferred_and_carry_evidence(synthetic):
    ex = ingest_export(synthetic)
    e = edges(ex, "exhibits", "FUN_inject", "Code injection")[0]
    assert e["confidence"] == "INFERRED"
    assert "WriteProcessMemory" in e["context"]
    assert edges(ex, "exhibits", "connect", "Networking")


def test_string_evidence_is_weaker_than_api_evidence(synthetic):
    ex = ingest_export(synthetic)
    api = edges(ex, "exhibits", "FUN_net", "Networking")[0]
    assert api["confidence_score"] == 0.75
    # main has no network API but references only a usage string: no network capability.
    assert not edges(ex, "exhibits", "main", "Networking")


def test_capability_hyperedges_respect_minimum(synthetic):
    ex = ingest_export(synthetic, ProgramOptions(min_capability_members=1))
    assert ex["hyperedges"]
    ex = ingest_export(synthetic, ProgramOptions(min_capability_members=50))
    assert ex["hyperedges"] == []


def test_capabilities_can_be_disabled(synthetic):
    ex = ingest_export(synthetic, ProgramOptions(include_capabilities=False))
    assert "capability" not in by_kind(ex) and not edges(ex, "exhibits")


# --------------------------------------------------------------------- strings

def test_string_modes(synthetic):
    labels = lambda mode: {n["label"] for n in by_kind(ingest_export(synthetic, ProgramOptions(strings=mode))).get("string", [])}
    assert labels("none") == set()
    ref = labels("referenced")
    assert "usage: sample.exe <host>" in ref and "http://203.0.113.9/beacon" in ref
    assert "unreferenced boring text" not in ref
    assert any("CurrentVersion" in s for s in ref), "unreferenced but rule-matching strings are kept"
    assert labels("interesting") == {s for s in ref if "usage" not in s}
    assert "unreferenced boring text" in labels("all")


def test_invalid_string_mode_rejected():
    with pytest.raises(ValueError):
        ProgramOptions(strings="everything")


def test_string_nodes_are_flagged_untrusted(synthetic):
    kinds = by_kind(ingest_export(synthetic))
    assert all(n["metadata"]["untrusted_content"] for n in kinds["string"])


def test_string_reference_edges(synthetic):
    ex = ingest_export(synthetic)
    assert edges(ex, "references", "FUN_net", "http://203.0.113.9/beacon")


# --------------------------------------------------------------- comments & FID

def test_analyst_comment_becomes_rationale(synthetic):
    ex = ingest_export(synthetic)
    note = node(ex, "Note on main")
    assert note["file_type"] == "rationale"
    assert edges(ex, "rationale_for", "Note on main", "main")


def test_function_id_library_match_is_not_an_analyst_note(synthetic):
    ex = ingest_export(synthetic)
    assert not any(n["label"] == "Note on _Init_thread_footer" for n in ex["nodes"])
    fn = node(ex, "_Init_thread_footer")
    assert "library" in fn["metadata"]["roles"]
    assert "Library Function" in fn["metadata"]["library_match"]
    assert "Visual Studio 2019" in fn["metadata"]["library_match"]


# --------------------------------------------------------------------- ids

def test_ids_are_stable_across_runs(synthetic):
    a = {n["id"] for n in ingest_export(synthetic)["nodes"]}
    b = {n["id"] for n in ingest_export(synthetic)["nodes"]}
    assert a == b


def test_per_binary_ids_scoped_but_import_ids_global(synthetic):
    other = {**synthetic, "program": {**synthetic["program"], "name": "other.exe", "sha256": "cd" * 32}}
    a, b = ingest_export(synthetic), ingest_export(other)
    ids_a, ids_b = {n["id"] for n in a["nodes"]}, {n["id"] for n in b["nodes"]}
    shared = ids_a & ids_b
    shared_kinds = {n["metadata"]["ghidra_kind"] for n in a["nodes"] if n["id"] in shared}
    assert shared_kinds <= {"import", "library", "capability"} and shared_kinds
    assert not any(n["metadata"]["ghidra_kind"] == "function" for n in a["nodes"] if n["id"] in shared)


def test_duplicate_function_names_get_address_suffix(synthetic):
    synthetic["functions"].append({**synthetic["functions"][2], "address": "0x409000"})
    labels = [n["label"] for n in ingest_export(synthetic)["nodes"] if n["metadata"]["ghidra_kind"] == "function"]
    assert len(labels) == len(set(labels))
    assert any("FUN_net @0x" in lbl for lbl in labels)


# --------------------------------------------------------------------- pseudo-C

def test_pseudo_c_goes_to_sidecar_not_metadata(synthetic):
    synthetic["functions"][1]["pseudo_c"] = "int main(void) {\n  return a->b < 3 && x;\n}\n" * 40
    ex = ingest_export(synthetic)
    fn = node(ex, "main")
    assert fn["metadata"]["pseudo_c_path"].startswith("ghidra/sample_exe_abababab/pseudo/0x401100")
    assert "pseudo_c" not in fn["metadata"]
    assert len(fn["metadata"]["pseudo_c_preview"]) <= 300 * 6  # escaped, still bounded
    text = ex["ghidra"]["sidecars"][fn["metadata"]["pseudo_c_path"]]
    assert "a->b < 3" in text and len(text) <= 1500, "sidecar keeps raw, unescaped text"
    assert fn["metadata"]["untrusted_content"] is True


# ------------------------------------------------------------------- analysis

def test_reachability_and_depth(synthetic, addr):
    a = analyze(Program(synthetic))
    m = a.metrics
    assert m[addr("entry")].depth == 0 and m[addr("main")].depth == 1 and m[addr("do_net")].depth == 2
    assert not m[addr("orphan_cb")].reachable
    assert a.summary["unreachable_functions"] == 2  # orphan_cb and thunk_connect


def test_roles(synthetic, addr):
    m = analyze(Program(synthetic)).metrics
    assert "entry" in m[addr("entry")].roles
    assert "wrapper" in m[addr("wrapper_fn")].roles
    assert "library" in m[addr("crt_helper")].roles
    assert "unreferenced" in m[addr("orphan_cb")].roles
    assert "thunk" in m[addr("thunk_connect")].roles
    assert "leaf" in m[addr("via_ptr")].roles


def test_triage_prefers_capable_functions_over_wrappers_and_library(synthetic, addr):
    a = analyze(Program(synthetic))
    assert a.metrics[addr("do_inject")].score > a.metrics[addr("wrapper_fn")].score
    assert a.metrics[addr("do_inject")].score > a.metrics[addr("crt_helper")].score
    assert a.metrics[addr("crt_helper")].score == 0
    assert any("injection" in r for r in a.metrics[addr("do_inject")].reasons)
    assert a.ranked[0] in {addr("do_inject"), addr("orphan_cb"), addr("main"), addr("entry")}


def test_unreferenced_but_capable_gets_a_lead(synthetic, addr):
    m = analyze(Program(synthetic)).metrics[addr("orphan_cb")]
    assert any("unreferenced but capable" in r for r in m.reasons)
    assert "injection" in m.capabilities


def test_direct_recursion_does_not_inflate_fan_in(synthetic, addr):
    synthetic["calls"].append({"from": addr("do_net"), "to": addr("do_net"), "kind": "UNCONDITIONAL_CALL"})
    m = analyze(Program(synthetic)).metrics[addr("do_net")]
    assert m.fan_in == 2  # main + wrapper_fn, not itself


def test_summary_counts(synthetic):
    s = analyze(Program(synthetic)).summary
    assert s["functions"] == 9 and s["thunks"] == 1 and s["library_functions"] == 1
    assert s["imports"] == 5 and s["entry_points"] == ["0x401000"]
    assert s["capability_function_counts"]["network"] >= 1


def test_malformed_doc_raises(synthetic):
    from graphify_ghidra.model import ExportError
    synthetic["program"] = {}
    with pytest.raises(ExportError):
        Program(synthetic)
