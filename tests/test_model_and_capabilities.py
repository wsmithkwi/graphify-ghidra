import pytest

from graphify_ghidra.capabilities import (
    CAPABILITIES, classify_api, classify_string, normalize_api_name, register_api_rules,
)
from graphify_ghidra.model import SCHEMA, canon_addr, empty_export, validate_export


@pytest.mark.parametrize("raw,expected", [
    (0x401000, "0x401000"),
    ("0x401000", "0x401000"),
    ("0X00401000", "0x401000"),
    ("401000h", "0x401000"),
    ("ram:0x10", "ram:0x10"),
    ("EXTERNAL:0x0000FF", "EXTERNAL:0xff"),
    (None, None), ("", None), ("main", None), (True, None), (-1, None), (3.5, None),
])
def test_canon_addr(raw, expected):
    assert canon_addr(raw) == expected


def test_validate_export_accepts_minimal():
    assert validate_export(empty_export("a.out")) == []


def test_validate_export_reports_problems():
    assert validate_export([]) == ["export must be a JSON object"]
    doc = empty_export("a.out")
    doc["schema"] = "nope"
    doc["functions"] = [{"address": "not-an-address"}]
    doc["calls"] = "x"
    errs = validate_export(doc)
    assert any("schema must be" in e for e in errs)
    assert any("no usable address" in e for e in errs)
    assert any("calls must be a list" in e for e in errs)
    assert SCHEMA in errs[0]


@pytest.mark.parametrize("raw,base", [
    ("KERNEL32.DLL!CreateFileW", "CreateFile"),
    ("CreateFileA", "CreateFile"),
    ("_open", "open"),
    ("__imp_connect", "connect"),
    ("Ordinal_12", "Ordinal_12"),
    ("open", "open"),           # libc names must not be mangled by Win32 suffix stripping
    ("Send", "Send"),           # too short to strip
])
def test_normalize_api_name(raw, base):
    assert normalize_api_name(raw) == base


@pytest.mark.parametrize("api,cap", [
    ("CreateFileW", "file-io"), ("RegSetValueExA", "registry"), ("connect", "network"),
    ("InternetOpenUrlW", "http"), ("WriteProcessMemory", "injection"), ("CryptEncrypt", "crypto"),
    ("IsDebuggerPresent", "anti-analysis"), ("AdjustTokenPrivileges", "privilege"),
    ("LoadLibraryA", "dynamic-loading"), ("_open", "posix-io"), ("ShellExecuteW", "exec"),
])
def test_classify_api_hits(api, cap):
    assert cap in classify_api(api)


@pytest.mark.parametrize("api", ["GetTickCount", "CloseHandle", "RaiseException", "NtClose", "", None])
def test_noisy_apis_are_not_anti_analysis(api):
    assert "anti-analysis" not in classify_api(api)


def test_classify_string():
    assert "network" in classify_string("http://203.0.113.9/x")
    assert "registry" in classify_string("HKLM\\SOFTWARE\\Foo")
    assert "crypto" in classify_string("-----BEGIN PRIVATE KEY-----")
    assert classify_string("hi") == []
    assert classify_string(None) == []


def test_every_rule_key_is_a_known_capability():
    from graphify_ghidra import capabilities as c
    for key, _ in c._API_RULES + c._STRING_RULES:
        assert key in CAPABILITIES


def test_register_api_rules_extends_taxonomy():
    register_api_rules("test-only-cap", [r"^FrobnicateWidget$"], label="Frob", risk=1)
    assert classify_api("FrobnicateWidget") == ["test-only-cap"]
    assert CAPABILITIES["test-only-cap"].risk == 1
