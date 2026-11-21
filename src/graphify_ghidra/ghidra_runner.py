"""Run Ghidra headless with the packaged export script.

The contract mirrors REA's Ghidra rules so the two tools can share an install
and a configuration:

* **Bring your own Ghidra.** We never download, install or upgrade Ghidra or
  Java. ``GHIDRA_INSTALL_DIR`` (REA's variable) is honoured first.
* **Read-only, ephemeral.** The binary is imported into a throw-away project
  with ``-readOnly -deleteProject``; its bytes are never modified and nothing
  is saved. The project directory is a private temp dir removed on exit.
* **REA's overrides apply.** ``REA_GHIDRA_LANGUAGE_ID`` and
  ``REA_GHIDRA_COMPILER_SPEC_ID`` select the import language the same way they
  do for REA, so a raw firmware image analysed in both tools is analysed under
  the same processor definition.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import hashlib
import json

__all__ = ["GhidraNotFound", "ExportFailed", "find_ghidra", "export_binary", "query_program",
           "file_sha256", "SCRIPT_NAME", "PROJECT_NAME"]

SCRIPT_NAME = "GraphifyGhidraExport.java"
QUERY_SCRIPT_NAME = "GraphifyGhidraQuery.java"
_SCRIPT_DIR = Path(__file__).parent / "ghidra_scripts"
PROJECT_NAME = "gg"


class GhidraNotFound(RuntimeError):
    """No usable Ghidra installation could be located."""


class ExportFailed(RuntimeError):
    """The headless run did not produce an export."""

    def __init__(self, message: str, log: str = "") -> None:
        super().__init__(message)
        self.log = log


def _headless(root: Path) -> Path | None:
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    p = root / "support" / name
    return p if p.is_file() else None


def _candidates() -> list[Path]:
    home = Path.home()
    found: list[Path] = []
    for base in (Path("C:/tools"), Path("C:/"), Path("C:/Program Files"), home, home / "tools",
                 Path("/opt"), Path("/usr/local"), Path("/Applications"), Path("/usr/share")):
        try:
            if base.is_dir():
                found.extend(sorted(base.glob("ghidra*"), reverse=True))
        except OSError:
            continue
    return found


def find_ghidra(explicit: str | os.PathLike | None = None) -> Path:
    """Locate a Ghidra install root (the directory containing ``support/``)."""
    tried: list[str] = []
    order: list[Path] = []
    if explicit:
        order.append(Path(explicit))
    for var in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        if os.environ.get(var):
            order.append(Path(os.environ[var]))
    on_path = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")
    if on_path:
        order.append(Path(on_path).resolve().parent.parent)
    order.extend(_candidates())
    for root in order:
        tried.append(str(root))
        if _headless(root):
            return root
        # Tolerate the user pointing at the extracted release's parent directory.
        try:
            for child in sorted(root.glob("ghidra*")):
                if _headless(child):
                    return child
        except OSError:
            pass
    raise GhidraNotFound(
        "Could not find a Ghidra installation (looked for support/analyzeHeadless). "
        "Set GHIDRA_INSTALL_DIR to an extracted official Ghidra release, or pass --ghidra-home. "
        "graphify-ghidra never installs Ghidra or Java for you. Tried: " + ", ".join(tried[:8])
    )


@dataclass
class ExportResult:
    out_path: Path
    log: str
    ghidra_root: Path


def export_binary(
    binary: str | os.PathLike,
    out_json: str | os.PathLike,
    *,
    ghidra_home: str | os.PathLike | None = None,
    decompile: int = 0,
    decompile_timeout: int = 20,
    max_strings: int = 50000,
    language: str | None = None,
    compiler_spec: str | None = None,
    loader: str | None = None,
    timeout: int | None = 1800,
    log_to: Path | None = None,
    project_dir: str | os.PathLike | None = None,
) -> ExportResult:
    """Import ``binary`` into a Ghidra project and export it as JSON.

    By default the project is a throw-away temp dir (read-only, deleted on exit).
    With ``project_dir`` the analysed project is **kept** there so later live
    queries (:func:`query_program`) reuse the analysis instead of repeating it.
    The original binary is never modified either way: Ghidra imports a copy.
    """
    src = Path(binary).expanduser().resolve()
    if not src.is_file():
        raise ExportFailed(f"binary not found or not a regular file: {src}")
    out = Path(out_json).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    root = find_ghidra(ghidra_home)
    headless = _headless(root)
    assert headless is not None

    language = language or os.environ.get("REA_GHIDRA_LANGUAGE_ID") or None
    compiler_spec = compiler_spec or os.environ.get("REA_GHIDRA_COMPILER_SPEC_ID") or None

    keep = Path(project_dir).expanduser().resolve() if project_dir else None
    with tempfile.TemporaryDirectory(prefix="graphify-ghidra-") as tmp:
        tmp_path = Path(tmp)
        if keep is not None:
            # A stale project would make -import prompt/overwrite; start clean.
            if keep.exists():
                shutil.rmtree(keep, ignore_errors=True)
            keep.mkdir(parents=True, exist_ok=True)
        project = keep if keep is not None else tmp_path / "project"
        scripts = tmp_path / "scripts"
        project.mkdir(exist_ok=True)
        scripts.mkdir()
        # Run a private copy of the script: Ghidra compiles it next to itself.
        shutil.copy2(_SCRIPT_DIR / SCRIPT_NAME, scripts / SCRIPT_NAME)

        # NB: "key:value" not "key=value". On Windows analyzeHeadless.bat is a batch
        # file and cmd.exe splits arguments at '=', which would turn "decompile=20"
        # into two arguments before the script ever sees it.
        cmd = [
            str(headless), str(project), PROJECT_NAME, "-import", str(src),
            "-scriptPath", str(scripts),
            "-postScript", SCRIPT_NAME, str(out),
            f"decompile:{int(decompile)}", f"decompile_timeout:{int(decompile_timeout)}",
            f"max_strings:{int(max_strings)}",
        ]
        if keep is None:
            cmd += ["-deleteProject", "-readOnly"]
        if language:
            cmd += ["-processor", language]
        if compiler_spec:
            cmd += ["-cspec", compiler_spec]
        if loader:
            cmd += ["-loader", loader]

        env = dict(os.environ)
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, env=env, cwd=str(tmp_path),
            )
        except subprocess.TimeoutExpired as exc:
            raise ExportFailed(f"Ghidra headless analysis timed out after {timeout}s", _tail(exc.stdout)) from exc
        except OSError as exc:
            raise ExportFailed(f"could not launch Ghidra headless: {exc}") from exc

        log = (proc.stdout or "") + (proc.stderr or "")
        if log_to is not None:
            log_to.parent.mkdir(parents=True, exist_ok=True)
            log_to.write_text(log, encoding="utf-8")
        if not out.is_file():
            raise ExportFailed(_diagnose(proc.returncode, log), _tail(log))
        if keep is not None:
            (keep / "project.json").write_text(json.dumps({
                "dir": str(keep), "name": PROJECT_NAME, "program": src.name,
                "binary": str(src), "ghidra_home": str(root),
            }), encoding="utf-8")
        return ExportResult(out, log, root)


def file_sha256(path: str | os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def query_program(
    project_dir: str | os.PathLike,
    mode: str,
    *,
    addrs: list[str],
    ghidra_home: str | os.PathLike | None = None,
    timeout: int | None = 300,
    **opts: object,
) -> dict:
    """Run a live read-only query (decompile / disasm / xrefs) on a kept project."""
    # Absolute: the subprocess runs from a temp cwd, where a relative path would point
    # at a project that does not exist (Ghidra then waits instead of failing).
    proj = Path(project_dir).expanduser().resolve()
    meta_path = proj / "project.json"
    if not meta_path.is_file():
        raise ExportFailed(
            f"no retained Ghidra project at {proj}. Re-run `graphify-ghidra analyze` "
            "(without --no-keep-project) so live queries have an analysed project to open."
        )
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    root = find_ghidra(ghidra_home or meta.get("ghidra_home"))
    headless = _headless(root)
    assert headless is not None
    with tempfile.TemporaryDirectory(prefix="graphify-ghidra-q-") as tmp:
        tmp_path = Path(tmp)
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        shutil.copy2(_SCRIPT_DIR / QUERY_SCRIPT_NAME, scripts / QUERY_SCRIPT_NAME)
        out = tmp_path / "result.json"
        cmd = [
            str(headless), str(proj), meta.get("name", PROJECT_NAME),
            "-process", meta["program"], "-noanalysis", "-readOnly",
            "-scriptPath", str(scripts),
            "-postScript", QUERY_SCRIPT_NAME, str(out), mode,
            "addrs:" + ",".join(addrs),
        ] + [f"{k}:{v}" for k, v in opts.items() if v is not None]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                  timeout=timeout, cwd=str(tmp_path))
        except subprocess.TimeoutExpired as exc:
            raise ExportFailed(f"Ghidra query timed out after {timeout}s", _tail(exc.stdout)) from exc
        log = (proc.stdout or "") + (proc.stderr or "")
        if not out.is_file():
            low = log.lower()
            if "lock" in low and "project" in low:
                raise ExportFailed("the Ghidra project is locked (is it open in the Ghidra GUI?). "
                                   "Close it there, or work from the graph without live=true.", _tail(log))
            raise ExportFailed(_diagnose(proc.returncode, log), _tail(log))
        return json.loads(out.read_text(encoding="utf-8"))


def _tail(text: str | bytes | None, n: int = 4000) -> str:
    if text is None:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    return text[-n:]


def _diagnose(returncode: int, log: str) -> str:
    low = log.lower()
    if "unsupportedclassversionerror" in low or "requires jdk" in low or "java version" in low and "not supported" in low:
        return "Ghidra rejected this Java version; install the JDK the Ghidra release requires."
    if "unable to find a compatible java" in low or "no java" in low:
        return "Ghidra could not find a compatible JDK (set JAVA_HOME or see Ghidra's support/launch.properties)."
    if "unable to find a loader" in low or "no load spec" in low or "no supported loader" in low:
        return ("Ghidra has no loader for this file. For raw firmware pass --language <id> "
                "(for example ARM:LE:32:v7) and optionally --loader BinaryLoader.")
    if "compile" in low and "error" in low and "graphifyghidraexport" in low:
        return "The export script failed to compile against this Ghidra version (see the log)."
    return f"Ghidra headless exited ({returncode}) without writing an export; see the log tail."


def default_log_path(out_json: Path) -> Path:
    return out_json.with_suffix(".ghidra.log")


if __name__ == "__main__":  # pragma: no cover - manual smoke
    print(find_ghidra(sys.argv[1] if len(sys.argv) > 1 else None))
