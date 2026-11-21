import json

import pytest

from graphify_ghidra import ingest_export, write_extraction
from graphify_ghidra.annotations import AnnotationStore, load_stores, reapply, validate_name
from graphify_ghidra.graph_io import patch_graph

SCOPE = "sample_exe_abababab"


@pytest.mark.parametrize("raw,expected", [
    ("parse_config", "parse_config"),
    ("  parse config line  ", "parse_config_line"),
    ("net::send-packet", "net_send_packet"),
    ("9lives", "_9lives"),
    ("a" * 200, "a" * 96),
    ("?weird@@name", "weird_name"),
])
def test_validate_name_normalises(raw, expected):
    assert validate_name(raw)[0] == expected


@pytest.mark.parametrize("raw", ["", "   ", "!!!", "FUN_140003bc0", "DAT_1234", "param_1", "local_48", "thunk_FUN_00401000", None, 5])
def test_validate_name_rejects_unusable(raw):
    name, why = validate_name(raw)
    assert name is None and why


@pytest.fixture
def store(tmp_path):
    return AnnotationStore.open(tmp_path, SCOPE)


def test_set_name_outcomes(store):
    r = store.set_name("0x401000", "open_config", confidence="medium", evidence=["CreateFileW"])
    assert r.status == "named"
    assert store.set_name("0x401000", "open_config", confidence="medium").status == "unchanged"
    # a weaker claim never displaces a stronger one
    kept = store.set_name("0x401000", "something_else", confidence="low")
    assert kept.status == "kept" and store.names["0x401000"]["name"] == "open_config"
    # a stronger one does, and history remembers
    assert store.set_name("0x401000", "load_config", confidence="high").status == "renamed"
    assert store.names["0x401000"]["history"][-1]["name"] == "open_config"
    # the same name at higher confidence only strengthens
    r = store.set_name("0x401000", "load_config", confidence="high", by="analyst")
    assert r.status == "renamed" and store.names["0x401000"]["by"] == "analyst"


def test_ai_cannot_override_analyst_without_force(store):
    store.set_name("0x1000", "analyst_name", by="analyst", confidence="high")
    assert store.set_name("0x1000", "ai_name", confidence="high", by="ai").status == "kept"
    assert store.set_name("0x1000", "ai_name", confidence="high", by="ai", force=True).status == "renamed"


def test_protected_ghidra_names(store):
    r = store.set_name("0x1000", "mine", protected=True)
    assert r.status == "protected" and "0x1000" not in store.names
    assert store.set_name("0x1000", "mine", protected=True, force=True).status == "named"


def test_invalid_inputs(store):
    assert store.set_name("nonsense", "x_y").status == "invalid"
    assert store.set_name("0x1", "FUN_00401000").status == "invalid"
    assert store.set_name("0x1", "ok_name", confidence="bogus").status == "named"   # coerced to medium
    assert store.names["0x1"]["confidence"] == "medium"


def test_evidence_is_bounded(store):
    store.set_name("0x1", "ok_name", evidence=[f"e{i}" * 100 for i in range(20)])
    ev = store.names["0x1"]["evidence"]
    assert len(ev) == 8 and all(len(e) <= 200 for e in ev)


def test_naming_clears_examined(store):
    store.mark_examined("0x5", "unclear")
    assert "0x5" in store.data["examined"]
    store.set_name("0x5", "now_known")
    assert "0x5" not in store.data["examined"]
    store.mark_examined("0x5", "ignored: already named")
    assert "0x5" not in store.data["examined"]


def test_store_roundtrip_and_corruption(tmp_path):
    s = AnnotationStore.open(tmp_path, SCOPE)
    s.set_name("0x1", "persisted")
    s.save()
    assert AnnotationStore.open(tmp_path, SCOPE).names["0x1"]["name"] == "persisted"
    s.path.write_text("{not json")
    with pytest.raises(ValueError, match="corrupted"):
        AnnotationStore.open(tmp_path, SCOPE)       # never silently start empty (that would erase work on save)


def test_behavior_membership_and_cycles(store):
    slug, err = store.set_behavior("Config Parsing!", label="Config parsing", members=["0x1", "0x2"])
    assert slug == "config_parsing" and not err
    store.set_behavior(slug, add_members=["0x3", "0x2"], remove_members=["0x1"])
    assert store.data["behaviors"][slug]["members"] == ["0x2", "0x3"]
    store.set_behavior("startup", members=["0x9"])
    store.set_behavior(slug, parent="startup")
    assert store.set_behavior("startup", parent=slug)[1].startswith("'config_parsing' is already a sub-behaviour")
    assert store.set_behavior("startup", parent="startup")[1] == "a behaviour cannot be its own parent"
    assert store.set_behavior("???")[0] == ""


def test_links_validate_kind_and_endpoints(store):
    assert store.add_link("0x1", "0x2", "similar") == (True, "added")
    assert store.add_link("0x1", "0x2", "similar", rationale="again") == (True, "updated")
    assert store.add_link("0x1", "0x1", "similar")[0] is False
    assert store.add_link("0x1", "0x2", "teleports")[0] is False
    assert store.add_link("zzz", "0x2", "similar")[0] is False
    assert store.add_link("other_scope:0x10", "0x2", "related") == (True, "added")
    assert store.data["links"][-1]["a"] == "other_scope:0x10"


# ----------------------------------------------------------- applying to a graph

def _graph(synthetic):
    ex = ingest_export(synthetic)
    return {"directed": True, "nodes": ex["nodes"], "links": ex["edges"], "hyperedges": [], "graph": {}}


def _label(g, addr):
    return next(n["label"] for n in g["nodes"] if (n.get("metadata") or {}).get("address") == addr
                and n["metadata"].get("ghidra_kind") in ("function", "thunk"))


def test_reapply_names_nodes_and_is_idempotent(synthetic, tmp_path):
    g = _graph(synthetic)
    s = AnnotationStore.open(tmp_path, SCOPE)
    s.set_name("0x401200", "send_beacon", confidence="high", evidence=["connect", "send"])
    counts = reapply(g, {SCOPE: s})
    assert counts["names"] == 1 and _label(g, "0x401200") == "send_beacon"
    n = next(x for x in g["nodes"] if x["label"] == "send_beacon")
    assert n["metadata"]["original_label"] == "FUN_net" and n["metadata"]["name_confidence"] == "high"
    before = json.dumps(g, sort_keys=True)
    reapply(g, {SCOPE: s})
    assert json.dumps(g, sort_keys=True) == before, "reapply must converge"


def test_reapply_restores_label_when_name_removed(synthetic, tmp_path):
    g = _graph(synthetic)
    s = AnnotationStore.open(tmp_path, SCOPE)
    s.set_name("0x401200", "send_beacon")
    reapply(g, {SCOPE: s})
    s.clear_name("0x401200")
    reapply(g, {SCOPE: s})
    assert _label(g, "0x401200") == "FUN_net"
    assert not any((n.get("metadata") or {}).get("ai_name") for n in g["nodes"])


def test_label_collisions_get_address_suffix(synthetic, tmp_path):
    g = _graph(synthetic)
    s = AnnotationStore.open(tmp_path, SCOPE)
    s.set_name("0x401200", "worker")
    s.set_name("0x401300", "worker")
    reapply(g, {SCOPE: s})
    labels = sorted(_label(g, a) for a in ("0x401200", "0x401300"))
    assert labels[0] == "worker" and labels[1].startswith("worker @0x")


def test_behaviors_become_concept_nodes_edges_and_hyperedges(synthetic, tmp_path):
    g = _graph(synthetic)
    s = AnnotationStore.open(tmp_path, SCOPE)
    s.set_behavior("net_io", label="Network I/O", description="talks to the C2", members=["0x401200", "0x401100", "0x401400"])
    s.set_behavior("startup", label="Startup", members=["0x401000"])
    s.set_behavior("net_io", parent="startup")
    reapply(g, {SCOPE: s})
    beh = [n for n in g["nodes"] if (n["metadata"] or {}).get("ghidra_kind") == "behavior"]
    assert {b["label"] for b in beh} == {"Network I/O", "Startup"} and all(b["file_type"] == "concept" for b in beh)
    impl = [e for e in g["links"] if e["relation"] == "implements" and e.get("origin") == "annotation"]
    assert len(impl) == 4
    assert any(e["relation"] == "conceptually_related_to" and "sub-behaviour" in e["context"] for e in g["links"])
    assert [h for h in g["hyperedges"] if h["relation"] == "implement" and len(h["nodes"]) == 3]
    s.data["behaviors"].pop("net_io")
    reapply(g, {SCOPE: s})
    assert len([n for n in g["nodes"] if (n["metadata"] or {}).get("ghidra_kind") == "behavior"]) == 1, "removal cleans up"


def test_variables_links_and_types(synthetic, tmp_path):
    g = _graph(synthetic)
    s = AnnotationStore.open(tmp_path, SCOPE)
    s.set_variable("0x401200", "param_1", "target_host", type_="HostInfo *")
    s.add_link("0x401200", "0x401300", "similar", confidence="high", rationale="same loop shape")
    s.add_link("0x401000", "0x401300", "calls", rationale="callback table at 0x403000")
    reapply(g, {SCOPE: s})
    var = next(n for n in g["nodes"] if (n["metadata"] or {}).get("ghidra_kind") == "variable")
    assert var["label"].endswith("::target_host") and var["metadata"]["original"] == "param_1"
    assert any(n["label"] == "HostInfo *" and n["metadata"]["ghidra_kind"] == "datatype" for n in g["nodes"])
    rel = {(e["relation"], e["confidence"]) for e in g["links"] if e.get("origin") == "annotation"}
    assert ("semantically_similar_to", "INFERRED") in rel and ("calls", "INFERRED") in rel
    sim = next(e for e in g["links"] if e["relation"] == "semantically_similar_to" and e.get("origin") == "annotation")
    assert sim["confidence_score"] == 0.85 and "same loop shape" in sim["context"]


def test_links_to_unknown_functions_are_dropped_not_dangling(synthetic, tmp_path):
    g = _graph(synthetic)
    s = AnnotationStore.open(tmp_path, SCOPE)
    s.add_link("0x401200", "0xdead0000", "similar")
    reapply(g, {SCOPE: s})
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in g["links"])


def test_annotations_survive_reingest(tmp_path, synthetic):
    out = tmp_path / "go"
    write_extraction(ingest_export(synthetic), out)
    s = AnnotationStore.open(out, SCOPE)
    s.set_name("0x401200", "send_beacon", confidence="high")
    s.save()
    patch_graph(out)
    g = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert "send_beacon" in {n["label"] for n in g["nodes"]}
    write_extraction(ingest_export(synthetic), out)               # a re-analysis resets Ghidra's own names...
    g = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert "send_beacon" in {n["label"] for n in g["nodes"]}, "...but never loses the analyst's work"
    assert "FUN_net" not in {n["label"] for n in g["nodes"]}
    assert load_stores(out)[SCOPE].names["0x401200"]["confidence"] == "high"
