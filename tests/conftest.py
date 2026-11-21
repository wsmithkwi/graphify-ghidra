"""Shared fixtures: a small synthetic export that exercises every code path.

Layout (addresses are hex offsets from 0x401000):

    entry ──> main ──> do_net ──> connect (import, ws2_32)            [network]
                  │       └────> send    (import, ws2_32)
                  ├────> do_inject ──> WriteProcessMemory (kernel32)  [injection]
                  ├────> wrapper_fn ──> do_net                         (tiny wrapper)
                  ├────> crt_helper                                    (FID library match)
                  └────> via_ptr   (COMPUTED_CALL, so INFERRED)
    orphan_cb  (nothing calls it)          thunk_connect ─thunk─> connect
"""

from __future__ import annotations

import copy

import pytest


def _fn(addr: int, name: str, **kw):
    fn = {
        "address": f"0x{addr:x}", "name": name, "is_thunk": False, "is_external": False,
        "is_entry": False, "user_named": False, "auto_named": name.startswith("FUN_"),
        "name_source": "DEFAULT" if name.startswith("FUN_") else "USER_DEFINED",
        "instruction_count": 60, "call_sites": 0, "indirect_calls": 0,
        "cyclomatic_complexity": 3, "size": 200, "string_refs": [], "data_refs": [], "api_calls": [],
    }
    fn.update(kw)
    return fn


A = {n: 0x401000 + i * 0x100 for i, n in enumerate(
    ["entry", "main", "do_net", "do_inject", "wrapper_fn", "crt_helper", "via_ptr", "orphan_cb", "thunk_connect"])}


def _a(name: str) -> str:
    return f"0x{A[name]:x}"


SYNTHETIC = {
    "schema": "graphify-ghidra/1",
    "producer": {"name": "test", "ghidra_version": "0"},
    "program": {"name": "sample.exe", "executable_path": "/C:/samples/sample.exe", "format": "Portable Executable (PE)",
                "language": "x86:LE:64:default", "sha256": "ab" * 32, "image_base": "0x400000", "processor": "x86"},
    "segments": [
        {"name": ".text", "start": "0x401000", "end": "0x402000", "size": 4096, "read": True, "write": False, "execute": True},
        {"name": ".data", "start": "0x403000", "end": "0x404000", "size": 4096, "read": True, "write": True, "execute": False},
    ],
    "functions": [
        _fn(A["entry"], "entry", is_entry=True, call_sites=1, user_named=True),
        _fn(A["main"], "main", call_sites=5, user_named=True, comment="Parses argv then dispatches work.",
            cyclomatic_complexity=12, string_refs=["0x403010"]),
        _fn(A["do_net"], "FUN_net", call_sites=2, api_calls=["connect", "send"], string_refs=["0x403020"]),
        _fn(A["do_inject"], "FUN_inject", call_sites=1, api_calls=["WriteProcessMemory"], cyclomatic_complexity=15),
        _fn(A["wrapper_fn"], "FUN_wrapper", instruction_count=8, call_sites=1),
        _fn(A["crt_helper"], "_Init_thread_footer", name_source="ANALYSIS", auto_named=False,
            comment="Library Function - Single Match\n _Init_thread_footer\n\nLibrary: Visual Studio 2019 Release"),
        _fn(A["via_ptr"], "FUN_viaptr"),
        _fn(A["orphan_cb"], "FUN_cb", call_sites=1, api_calls=["CreateRemoteThread"]),
        _fn(A["thunk_connect"], "thunk_connect", is_thunk=True, thunk_target="0x500000", instruction_count=1),
    ],
    "calls": [
        {"from": _a("entry"), "to": _a("main"), "call_site": "0x401005", "kind": "UNCONDITIONAL_CALL"},
        {"from": _a("main"), "to": _a("do_net"), "call_site": "0x401105", "kind": "UNCONDITIONAL_CALL"},
        {"from": _a("main"), "to": _a("do_net"), "call_site": "0x40110a", "kind": "UNCONDITIONAL_CALL"},
        {"from": _a("main"), "to": _a("do_inject"), "call_site": "0x401110", "kind": "UNCONDITIONAL_CALL"},
        {"from": _a("main"), "to": _a("wrapper_fn"), "call_site": "0x401120", "kind": "UNCONDITIONAL_CALL"},
        {"from": _a("main"), "to": _a("crt_helper"), "call_site": "0x401130", "kind": "UNCONDITIONAL_CALL"},
        {"from": _a("main"), "to": _a("via_ptr"), "call_site": "0x401140", "kind": "COMPUTED_CALL"},
        {"from": _a("wrapper_fn"), "to": _a("do_net"), "call_site": "0x401405", "kind": "UNCONDITIONAL_CALL"},
        {"from": _a("do_net"), "external_name": "connect", "external_library": "WS2_32.DLL",
         "call_site": "0x401205", "kind": "COMPUTED_CALL"},
        {"from": _a("do_net"), "external_name": "send", "external_library": "WS2_32.DLL",
         "call_site": "0x40120a", "kind": "COMPUTED_CALL"},
        {"from": _a("do_inject"), "external_name": "WriteProcessMemory", "external_library": "KERNEL32.DLL",
         "call_site": "0x401305", "kind": "COMPUTED_CALL", "via_thunk": _a("thunk_connect")},
        {"from": _a("orphan_cb"), "external_name": "CreateRemoteThread", "external_library": "KERNEL32.DLL",
         "call_site": "0x401705", "kind": "COMPUTED_CALL"},
        {"from": _a("main"), "call_site": "0x401150", "kind": "COMPUTED_CALL", "unresolved": True,
         "reason": "no_resolved_target"},
    ],
    "imports": [
        {"name": "connect", "library": "WS2_32.DLL"},
        {"name": "send", "library": "WS2_32.DLL"},
        {"name": "WriteProcessMemory", "library": "KERNEL32.DLL"},
        {"name": "CreateRemoteThread", "library": "KERNEL32.DLL"},
        {"name": "GetTickCount", "library": "KERNEL32.DLL"},   # imported, never called
    ],
    "exports": [{"name": "entry", "address": _a("entry")}],
    "strings": [
        {"address": "0x403010", "value": "usage: sample.exe <host>", "refs": [_a("main")]},
        {"address": "0x403020", "value": "http://203.0.113.9/beacon", "refs": [_a("do_net")]},
        {"address": "0x403030", "value": "unreferenced boring text", "refs": []},
        {"address": "0x403040", "value": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "refs": []},
    ],
    "data": [
        {"address": "0x403100", "name": "g_config", "type": "struct", "size": 64, "refs": [_a("main")]},
        {"address": "0x403200", "name": "DAT_unref", "type": "byte", "size": 1, "refs": []},
    ],
}


@pytest.fixture
def synthetic():
    return copy.deepcopy(SYNTHETIC)


@pytest.fixture
def addr():
    return _a


@pytest.fixture
def graph_dir(tmp_path, synthetic):
    """A real graphify-out written through graphify's own merge/cluster/to_json."""
    from graphify_ghidra import ingest_export, write_extraction
    out = tmp_path / "graphify-out"
    res = write_extraction(ingest_export(synthetic), out)
    assert res.written, res.message
    return out


# --------------------------------------------------------------------------- tool-layer fixtures

COPY_MN = ("push push sub mov mov lea call test jz mov xor cmp jnz add mov call mov ret lea mov call test jnz "
           "mov and cmp jz sub mov ret").split()


@pytest.fixture
def similar_doc(synthetic):
    """Synthetic export plus two near-identical routines (and mnemonics for features)."""
    doc = synthetic
    doc["functions"].append(_fn(0x402000, "FUN_copy_a", instruction_count=len(COPY_MN), call_sites=3,
                                api_calls=["connect"], mnemonics=" ".join(COPY_MN), constants=["0xdeadbeef", "0xcafebabe"]))
    mutated = COPY_MN[:12] + ["nop"] + COPY_MN[13:]
    doc["functions"].append(_fn(0x402100, "FUN_copy_b", instruction_count=len(mutated), call_sites=3,
                                api_calls=["connect"], mnemonics=" ".join(mutated), constants=["0xdeadbeef", "0xcafebabe"]))
    for f in doc["functions"][:9]:
        f.setdefault("mnemonics", "")
    doc["calls"].append({"from": _a("main"), "to": "0x402000", "call_site": "0x401160", "kind": "UNCONDITIONAL_CALL"})
    doc["calls"].append({"from": _a("main"), "to": "0x402100", "call_site": "0x401170", "kind": "UNCONDITIONAL_CALL"})
    return doc


@pytest.fixture
def ghidra_out(tmp_path, similar_doc):
    from graphify_ghidra import ingest_export, write_extraction
    out = tmp_path / "graphify-out"
    res = write_extraction(ingest_export(similar_doc), out, engine="python")
    assert res.written, res.message
    return out


@pytest.fixture
def ws(ghidra_out):
    from graphify_ghidra.workspace import Workspace
    w = Workspace(ghidra_out).ensure()
    yield w
    w.close()


SCOPE = "sample_exe_abababab"
