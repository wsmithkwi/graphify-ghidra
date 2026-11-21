"""A warm, long-lived Ghidra process for interactive live queries.

Starting headless Ghidra costs ~20s (JVM + project open) per query, which makes
decompile/disassemble/xrefs unusable inside an agent loop. This keeps **one**
analyzeHeadless process alive on a kept project (opened read-only, no analysis)
and talks to it over a loopback socket, so a query costs milliseconds and the
decompiler stays warm.

Safety:
* the socket binds 127.0.0.1 only and every request carries a random token that
  is written to a file in a private temp dir;
* the program is opened ``-readOnly``; nothing is ever saved;
* the process exits by itself after an idle period, and is stopped on interpreter exit.
"""

from __future__ import annotations

import atexit
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .ghidra_runner import (
    PROJECT_NAME, QUERY_SCRIPT_NAME, ExportFailed, _SCRIPT_DIR, _headless, find_ghidra, query_program,
)

__all__ = ["GhidraServer", "LiveBackend"]

_MAX_RESPONSE = 32 * 1024 * 1024


class GhidraServer:
    def __init__(self, project_dir: str | os.PathLike, *, ghidra_home: str | os.PathLike | None = None,
                 idle_seconds: int = 900, startup_timeout: int = 240) -> None:
        self.project = Path(project_dir).expanduser().resolve()
        self.ghidra_home = ghidra_home
        self.idle = idle_seconds
        self.startup_timeout = startup_timeout
        self._proc: subprocess.Popen | None = None
        self._tmp: Path | None = None
        self._port = 0
        self._token = ""
        self._registered = False

    # ----------------------------------------------------------------- lifecycle
    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None and self._port != 0

    def start(self) -> None:
        if self.running:
            return
        meta_path = self.project / "project.json"
        if not meta_path.is_file():
            raise ExportFailed(f"no retained Ghidra project at {self.project}; run `graphify-ghidra analyze` first")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        root = find_ghidra(self.ghidra_home or meta.get("ghidra_home"))
        headless = _headless(root)
        assert headless is not None
        self._tmp = Path(tempfile.mkdtemp(prefix="graphify-ghidra-srv-"))
        scripts = self._tmp / "scripts"
        scripts.mkdir()
        shutil.copy2(_SCRIPT_DIR / QUERY_SCRIPT_NAME, scripts / QUERY_SCRIPT_NAME)
        info = self._tmp / "info.json"
        self._token = secrets.token_hex(16)
        cmd = [str(headless), str(self.project), meta.get("name", PROJECT_NAME), "-process", meta["program"],
               "-noanalysis", "-readOnly", "-scriptPath", str(scripts),
               "-postScript", QUERY_SCRIPT_NAME, "serve", str(info), self._token, f"idle:{self.idle}"]
        flags = 0
        if os.name == "nt":
            flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        log = open(self._tmp / "server.log", "wb")
        self._proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                      cwd=str(self._tmp), creationflags=flags)
        deadline = time.time() + self.startup_timeout
        while time.time() < deadline:
            if info.is_file():
                try:
                    data = json.loads(info.read_text(encoding="utf-8"))
                    self._port = int(data["port"])
                    break
                except (ValueError, KeyError, OSError):
                    pass
            if self._proc.poll() is not None:
                break
            time.sleep(0.2)
        if not self._port:
            tail = (self._tmp / "server.log").read_text(encoding="utf-8", errors="replace")[-1500:]
            self.stop()
            low = tail.lower()
            hint = (" The project may be locked by the Ghidra GUI." if "lock" in low else "")
            raise ExportFailed("the Ghidra server did not start." + hint, tail)
        if not self._registered:
            atexit.register(self.stop)
            self._registered = True

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        port, self._port = self._port, 0
        if proc is not None and proc.poll() is None:
            try:
                if port:
                    self._send({"token": self._token, "mode": "quit"}, port=port, timeout=5)
                proc.wait(timeout=20)
            except Exception:
                _kill_tree(proc)
        if self._tmp is not None:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None

    # ------------------------------------------------------------------ requests
    def request(self, mode: str, addrs: list[str], timeout: float = 180, **opts: Any) -> dict[str, Any]:
        for attempt in (1, 2):
            if not self.running:
                self.start()
            try:
                resp = self._send({"token": self._token, "mode": mode, "addrs": addrs,
                                   "opts": {k: str(v) for k, v in opts.items() if v is not None}}, timeout=timeout)
            except (ConnectionError, socket.timeout, OSError) as exc:
                self.stop()                      # dead or wedged: restart once
                if attempt == 2:
                    raise ExportFailed(f"lost the Ghidra server: {exc}") from exc
                continue
            if "error" in resp and "results" not in resp:
                raise ExportFailed(f"Ghidra server error: {resp['error']}")
            return resp
        raise ExportFailed("unreachable")

    def _send(self, payload: dict[str, Any], *, port: int | None = None, timeout: float = 180) -> dict[str, Any]:
        with socket.create_connection(("127.0.0.1", port or self._port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            buf = bytearray()
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > _MAX_RESPONSE:
                    raise ExportFailed("Ghidra server response too large")
                if buf.endswith(b"\n"):
                    break
        if not buf:
            raise ConnectionError("empty response")
        return json.loads(buf.decode("utf-8"))


def _kill_tree(proc: subprocess.Popen) -> None:
    """analyzeHeadless.bat spawns java as a child; terminate() alone would orphan it."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, timeout=15)
        else:
            proc.terminate()
    except Exception:
        pass


class LiveBackend:
    """Live queries for one project: the warm server, with a one-shot fallback."""

    def __init__(self, project_dir: str | os.PathLike, ghidra_home: str | os.PathLike | None = None) -> None:
        self.project_dir = Path(project_dir)
        self.server = GhidraServer(project_dir, ghidra_home=ghidra_home)
        self._server_failed = False

    def available(self) -> bool:
        return (self.project_dir / "project.json").is_file()

    def query(self, mode: str, addrs: list[str], **opts: Any) -> dict[str, Any]:
        if not self._server_failed:
            try:
                return self.server.request(mode, addrs, **opts)
            except ExportFailed as exc:
                self._server_failed = True          # do not pay the startup timeout on every call
                self._why = str(exc)
        return query_program(self.project_dir, mode, addrs=addrs, **opts)

    def stop(self) -> None:
        self.server.stop()
