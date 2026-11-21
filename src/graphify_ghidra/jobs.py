"""Background analysis jobs, so an agent can start a Ghidra analysis from inside its own loop.

Analysing a real DLL takes minutes (sometimes far more), which is longer than any sensible tool-call timeout,
and the session may end before it finishes. So ``ghidra_analyze`` starts a **detached** process that runs
``graphify-ghidra analyze`` and records its state in ``<out>/ghidra/job.json``; ``ghidra_status`` reads it.

State: ``running`` -> ``done`` | ``failed``. A job whose process vanished without finalising (machine reboot,
kill) is reported ``died`` rather than "running" forever.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

__all__ = ["start_analysis", "read_job", "run_job", "pid_alive", "job_summary"]


def job_path(out: str | Path) -> Path:
    return Path(out) / "ghidra" / "job.json"


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".job-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, path)


def pid_alive(pid: int) -> bool:
    if not pid:
        return False
    if os.name == "nt":
        import ctypes
        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        h = k32.OpenProcess(0x1000, False, int(pid))      # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            return bool(k32.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == 259   # STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def read_job(out: str | Path) -> dict[str, Any] | None:
    p = job_path(out)
    if not p.is_file():
        return None
    try:
        job = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if job.get("state") == "running" and not pid_alive(int(job.get("pid") or 0)):
        job["state"] = "died"
        job["error"] = "the analysis process is gone without finishing (killed, or the machine restarted)"
        _write(p, job)
    return job


def _log_tail(job: dict[str, Any], n: int = 600) -> str:
    try:
        text = Path(job["log"]).read_text(encoding="utf-8", errors="replace")
    except (OSError, KeyError):
        return ""
    lines = [ln for ln in text.splitlines() if ln.strip() and "WARNING" not in ln and "Dedup" not in ln]
    return "\n".join(lines[-6:])[-n:]


def job_summary(job: dict[str, Any] | None) -> str:
    if not job:
        return ""
    name = Path(job.get("binary", "?")).name
    mins = (time.time() - job.get("started", time.time())) / 60
    st = job.get("state")
    if st == "running":
        return (f"analysis of {name} is RUNNING ({mins:.1f} min so far). A small binary takes 1-2 minutes; in my tests "
                f"about 2 minutes per MB beyond that, and big DLLs take much longer. The graph appears when it finishes.")
    if st == "done":
        return f"analysis of {name} finished in {(job.get('finished', 0) - job.get('started', 0)) / 60:.1f} min."
    tail = _log_tail(job)
    return f"analysis of {name} {st.upper()}: {job.get('error') or 'see log'}" + (f"\n  log {job.get('log')}:\n  " + tail.replace("\n", "\n  ") if tail else "")


def start_analysis(out: str | Path, binary: str, *, decompile: int = 30, language: str | None = None,
                   loader: str | None = None) -> tuple[bool, str]:
    """Start a detached ``graphify-ghidra analyze``. Returns ``(started, message)``."""
    src = Path(binary).expanduser()
    if not src.is_file():
        return False, f"{binary!r} is not a file. Pass the absolute path of the DLL/EXE/ELF to analyse."
    existing = read_job(out)
    if existing and existing.get("state") == "running":
        return False, "an analysis is already running here: " + job_summary(existing)
    out_p = Path(out)
    log = out_p / "ghidra" / "job.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    jp = job_path(out)
    argv = ["analyze", str(src.resolve()), "--out", str(out_p.resolve()), "--decompile", str(int(decompile))]
    if language:
        argv += ["--language", language]
    if loader:
        argv += ["--loader", loader]
    _write(jp, {"state": "starting", "binary": str(src.resolve()), "started": time.time(), "pid": 0,
                "log": str(log.resolve()), "argv": argv})
    cmd = [sys.executable, "-m", "graphify_ghidra.cli", "_job", str(jp), "--", *argv]
    kwargs: dict[str, Any] = {"stdin": subprocess.DEVNULL, "cwd": str(out_p.resolve().parent)}
    logfh = open(log, "ab")
    kwargs["stdout"] = logfh
    kwargs["stderr"] = subprocess.STDOUT
    if os.name == "nt":
        kwargs["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
                                   | subprocess.CREATE_NO_WINDOW)  # type: ignore[attr-defined]
    else:
        kwargs["start_new_session"] = True
    env = dict(os.environ, GRAPHIFY_NO_AUTO_REFRESH="1", PYTHONIOENCODING="utf-8")
    proc = subprocess.Popen(cmd, env=env, **kwargs)
    logfh.close()
    job = json.loads(jp.read_text(encoding="utf-8"))
    job.update(state="running", pid=proc.pid)
    _write(jp, job)
    return True, (f"Started analysis of {src.name} in the background (pid {proc.pid}). It keeps running even if this "
                  f"session ends. Output goes to {out_p / 'ghidra'}. Poll ghidra_status; when it finishes the "
                  "ghidra_worklist / ghidra_name loop becomes available.")


def run_job(jobfile: str | Path, argv: list[str]) -> int:
    """Entry point of the detached process: run the CLI in-process and record the outcome."""
    from .cli import main
    jp = Path(jobfile)
    job = json.loads(jp.read_text(encoding="utf-8"))
    job.update(state="running", pid=os.getpid())
    _write(jp, job)
    code, err = 1, ""
    try:
        code = int(main(argv) or 0)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        err = "" if isinstance(exc.code, int) else str(exc.code)
    except BaseException as exc:                      # noqa: BLE001 - the job must always record why it ended
        err = f"{type(exc).__name__}: {exc}"
    job = json.loads(jp.read_text(encoding="utf-8"))
    job.update(state="done" if code == 0 else "failed", finished=time.time(), exit_code=code)
    if code != 0:
        job["error"] = err or f"exit code {code}"
    _write(jp, job)
    return code
