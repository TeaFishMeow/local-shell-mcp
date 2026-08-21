from __future__ import annotations

import asyncio
import contextlib
import ctypes
import importlib
import os
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import audit
from .errors import process_start_not_found_error
from .fs_ops import relative_display, resolve_path
from .settings import get_settings
from .shell_environment import (
    persistent_shell_args,
    shell_command_args,
    subprocess_env,
)

CONPTY_BUFFER_BYTES = 1_000_000
CONPTY_READ_CHARS = 65536

try:
    import winpty
except ImportError:  # pragma: no cover - covered through monkeypatched module state.
    winpty = None

_CONPTY_SHELL_SESSIONS: dict[str, ConPtyShellSession] = {}
_CONSOLE_ATTACH_LOCK = threading.Lock()


def _process_pid(process: Any) -> int | None:
    value = getattr(process, "pid", None)
    if callable(value):
        value = value()
    try:
        pid = int(value)
    except (TypeError, ValueError):
        return None
    return pid if pid > 0 else None


def _send_ctrl_c_event(process: Any) -> bool:
    """Deliver a real Ctrl-C event to a pywinpty ConPTY console."""
    if os.name != "nt":
        return False
    child_pid = _process_pid(process)
    if child_pid is None:
        return False

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetConsoleWindow.restype = ctypes.c_void_p
    kernel32.FreeConsole.restype = ctypes.c_int
    kernel32.AttachConsole.argtypes = [ctypes.c_uint32]
    kernel32.AttachConsole.restype = ctypes.c_int
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel32.GetConsoleMode.restype = ctypes.c_int
    kernel32.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.SetConsoleMode.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.SetConsoleCtrlHandler.argtypes = [ctypes.c_void_p, ctypes.c_int]
    kernel32.SetConsoleCtrlHandler.restype = ctypes.c_int
    kernel32.GenerateConsoleCtrlEvent.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    kernel32.GenerateConsoleCtrlEvent.restype = ctypes.c_int

    attach_parent_process = ctypes.c_uint32(-1).value
    enable_processed_input = 0x0001
    generic_read_write = 0x80000000 | 0x40000000
    file_share_read_write = 0x00000001 | 0x00000002
    open_existing = 3
    invalid_handle = ctypes.c_void_p(-1).value

    with _CONSOLE_ATTACH_LOCK:
        had_console = bool(kernel32.GetConsoleWindow())
        kernel32.FreeConsole()
        if not kernel32.AttachConsole(child_pid):
            if had_console:
                kernel32.AttachConsole(attach_parent_process)
            return False

        console_input = kernel32.CreateFileW(
            "CONIN$",
            generic_read_write,
            file_share_read_write,
            None,
            open_existing,
            0,
            None,
        )
        original_mode: int | None = None
        if console_input not in (None, 0, invalid_handle):
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(console_input, ctypes.byref(mode)):
                original_mode = mode.value
                if not original_mode & enable_processed_input:
                    kernel32.SetConsoleMode(console_input, original_mode | enable_processed_input)

        # AttachConsole resets the handler table. Install an explicit handler
        # (rather than relying on the process-wide NULL ignore flag) so Python's
        # own console handler cannot terminate the MCP server during delivery.
        handler_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint32)
        ignore_handler = handler_type(lambda event: 1)
        kernel32.SetConsoleCtrlHandler(ignore_handler, 1)
        delivered = bool(kernel32.GenerateConsoleCtrlEvent(0, 0))
        time.sleep(0.005)

        if original_mode is not None and console_input not in (None, 0, invalid_handle):
            kernel32.SetConsoleMode(console_input, original_mode)
        if console_input not in (None, 0, invalid_handle):
            kernel32.CloseHandle(console_input)

        kernel32.FreeConsole()
        kernel32.SetConsoleCtrlHandler(ignore_handler, 0)
        if had_console:
            kernel32.AttachConsole(attach_parent_process)
        return delivered


@dataclass
class TailBuffer:
    keep_bytes: int
    data: bytearray
    total_bytes: int = 0

    def append(self, chunk: bytes) -> None:
        self.total_bytes += len(chunk)
        self.data.extend(chunk)
        del self.data[: max(0, len(self.data) - self.keep_bytes)]


@dataclass
class ConPtyShellSession:
    session_id: str
    process: Any
    cwd: Path
    command: str
    created: int
    output: TailBuffer
    reader: asyncio.Task[None] | None
    lock: asyncio.Lock
    pending_input: str = ""


def _track_pending_input(current: str, value: str) -> str:
    for char in value:
        if char in "\r\n\x03\x15":
            current = ""
        elif char in "\b\x7f":
            current = current[:-1]
        elif char >= " " and char != "\x7f":
            current += char
    return current


def is_available() -> bool:
    global winpty
    if winpty is None:
        with contextlib.suppress(ImportError, OSError):
            winpty = importlib.import_module("winpty")
    return winpty is not None and hasattr(winpty, "PtyProcess")


def has_session(session_id: str) -> bool:
    return session_id in _CONPTY_SHELL_SESSIONS


def _session_name(name: str | None = None) -> str:
    base = name or f"mcp-{uuid.uuid4().hex[:8]}"
    return re.sub(r"[^A-Za-z0-9_.-]", "-", base)[:64]


def _shell_command_args(command: str) -> list[str]:
    return shell_command_args(get_settings().shell_executable, command)


def _persistent_shell_args(command: str | None = None) -> list[str]:
    return persistent_shell_args(get_settings().shell_executable, command)


def _spawn_command(argv: list[str]) -> str:
    return subprocess.list2cmdline(argv)


def _spawn_pty(argv: list[str], cwd: Path) -> Any:
    if not is_available():
        raise RuntimeError("pywinpty is not available")
    assert winpty is not None
    spawn = winpty.PtyProcess.spawn
    env = subprocess_env()
    try:
        return spawn(argv, cwd=str(cwd), env=env)
    except TypeError:
        return spawn(_spawn_command(argv), cwd=str(cwd), env=env)


def _pty_is_alive(process: Any) -> bool:
    isalive = getattr(process, "isalive", None)
    if callable(isalive):
        return bool(isalive())
    return getattr(process, "exitstatus", None) is None


def _read_pty(process: Any) -> str | bytes:
    try:
        return process.read(CONPTY_READ_CHARS)
    except TypeError:
        return process.read()


def _close_pty_process(process: Any, force: bool) -> None:
    close = getattr(process, "close", None)
    if callable(close):
        if getattr(process, "closed", False):
            # pywinpty marks naturally exited processes as closed before its
            # socket resources have necessarily been released. Re-enable the
            # idempotent close path so fileobj and the listener are closed.
            with contextlib.suppress(Exception):
                process.closed = False
        try:
            close(force=force)
        except TypeError:
            close()
        return

    terminate = getattr(process, "terminate", None)
    if callable(terminate):
        try:
            terminate(force=force)
        except TypeError:
            terminate()


async def _cleanup_reader(reader: asyncio.Task[None] | None) -> None:
    if reader is None:
        return
    try:
        owner_loop = reader.get_loop()
    except Exception:
        return

    current_loop = asyncio.get_running_loop()
    if owner_loop is current_loop:
        if not reader.done():
            reader.cancel()
        await asyncio.gather(reader, return_exceptions=True)
        return

    if reader.done():
        with contextlib.suppress(asyncio.CancelledError, Exception):
            reader.result()
        return

    if not owner_loop.is_closed():
        with contextlib.suppress(RuntimeError):
            owner_loop.call_soon_threadsafe(reader.cancel)
        return

    # A persistent session can outlive a short-lived caller event loop. There is
    # no safe way to await or cancel a task after its owner loop is closed; the
    # PTY close below releases the blocking read, and dropping this reference is
    # the only remaining cleanup available.
    with contextlib.suppress(Exception):
        reader._log_destroy_pending = False  # type: ignore[attr-defined]


async def _cleanup_session(session: ConPtyShellSession, *, force: bool) -> str:
    error = ""
    try:
        await asyncio.to_thread(_close_pty_process, session.process, force)
    except Exception as exc:
        error = repr(exc)
    await _cleanup_reader(session.reader)
    session.reader = None
    return error


async def _read_conpty_shell(session: ConPtyShellSession) -> None:
    try:
        while _pty_is_alive(session.process):
            chunk = await asyncio.to_thread(_read_pty, session.process)
            if not chunk:
                await asyncio.sleep(0.02)
                continue
            if isinstance(chunk, str):
                chunk = chunk.encode(errors="replace")
            session.output.append(chunk)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        session.output.append(f"\n<conpty shell reader stopped: {exc!r}>\n".encode())


async def _get_session(session_id: str) -> ConPtyShellSession:
    session = _CONPTY_SHELL_SESSIONS.get(session_id)
    if session is None:
        raise RuntimeError(f"Persistent shell session not found: {session_id}")
    if not _pty_is_alive(session.process):
        _CONPTY_SHELL_SESSIONS.pop(session_id, None)
        await _cleanup_session(session, force=False)
        raise RuntimeError(f"Persistent shell session exited: {session_id}")
    return session


async def start_shell(
    cwd: str = ".",
    name: str | None = None,
    command: str | None = None,
    check_command_policy=None,
) -> dict:
    resolved_cwd = resolve_path(cwd, must_exist=True)
    max_sessions = max(1, get_settings().max_tmux_sessions)
    active = []
    stale_sessions = []
    for session_id, session in list(_CONPTY_SHELL_SESSIONS.items()):
        if _pty_is_alive(session.process):
            active.append(session_id)
        else:
            _CONPTY_SHELL_SESSIONS.pop(session_id, None)
            stale_sessions.append(session)
    for stale in stale_sessions:
        await _cleanup_session(stale, force=False)
    if len(active) >= max_sessions:
        raise RuntimeError(f"Refusing to start more than {max_sessions} persistent shell sessions")

    session_id = _session_name(name)
    if session_id in _CONPTY_SHELL_SESSIONS:
        raise RuntimeError(f"Persistent shell session already exists: {session_id}")

    initial = command or get_settings().shell_executable
    if check_command_policy is not None:
        check_command_policy(initial)
    args = _persistent_shell_args(command)
    try:
        process = await asyncio.to_thread(_spawn_pty, args, resolved_cwd)
    except FileNotFoundError as exc:
        raise process_start_not_found_error(
            exc,
            executable=str(args[0]),
            command=initial,
            cwd=resolved_cwd,
        ) from exc
    session = ConPtyShellSession(
        session_id=session_id,
        process=process,
        cwd=resolved_cwd,
        command=initial,
        created=int(time.time()),
        output=TailBuffer(CONPTY_BUFFER_BYTES, bytearray()),
        reader=None,
        lock=asyncio.Lock(),
    )
    session.reader = asyncio.create_task(_read_conpty_shell(session))
    _CONPTY_SHELL_SESSIONS[session_id] = session
    audit(
        "shell_start", session=session_id, cwd=str(resolved_cwd), command=initial, backend="conpty"
    )
    return {
        "session_id": session_id,
        "cwd": relative_display(resolved_cwd),
        "command": initial,
        "backend": "conpty",
    }


async def resize_shell(session_id: str, cols: int, rows: int) -> dict:
    session = await _get_session(session_id)
    resize = getattr(session.process, "setwinsize", None)
    if not callable(resize):
        return {
            "session_id": session_id,
            "cols": cols,
            "rows": rows,
            "resized": False,
            "backend": "conpty",
        }
    async with session.lock:
        await asyncio.to_thread(resize, rows, cols)
    return {
        "session_id": session_id,
        "cols": cols,
        "rows": rows,
        "resized": True,
        "backend": "conpty",
    }


async def send_shell(session_id: str, input_text: str, enter: bool = True) -> dict:
    session = await _get_session(session_id)
    data = input_text + ("\r" if enter else "")
    async with session.lock:
        parts = data.split("\x03")
        for index, part in enumerate(parts):
            if part:
                await asyncio.to_thread(session.process.write, part)
                session.pending_input = _track_pending_input(session.pending_input, part)
            if index < len(parts) - 1:
                # ConPTY does not always translate ETX into CTRL_C_EVENT after
                # a raw-mode application changes the console input mode. Send
                # both forms, matching a real Windows terminal's behavior.
                await asyncio.to_thread(session.process.write, "\x03")
                delivered = await asyncio.to_thread(_send_ctrl_c_event, session.process)
                if not delivered and session.pending_input:
                    # Native ConPTY consoles cannot be attached on some pywinpty
                    # builds. ETX still interrupts cooked child processes, but
                    # raw line editors do not consume it. Replay backspaces for
                    # the input observed since the last Enter so Ctrl-C retains
                    # its line-cancel behavior without terminating the shell.
                    await asyncio.to_thread(
                        session.process.write, "\b" * len(session.pending_input)
                    )
                session.pending_input = ""
    audit(
        "shell_send",
        session=session_id,
        bytes=len(input_text.encode()),
        enter=enter,
        backend="conpty",
    )
    return {"session_id": session_id, "sent_bytes": len(input_text.encode()), "enter": enter}


async def read_shell(session_id: str, lines: int = 200) -> dict:
    session = _CONPTY_SHELL_SESSIONS.get(session_id)
    if session is None:
        raise RuntimeError(f"Persistent shell session not found: {session_id}")
    output = bytes(session.output.data).decode(errors="replace")
    if lines > 0:
        split = output.splitlines()
        if split:
            output = "\n".join(split[-max(1, lines) :])
            if bytes(session.output.data).endswith((b"\n", b"\r")):
                output += "\n"
        else:
            output = ""
    audit("shell_read", session=session_id, lines=lines, backend="conpty")
    return {"session_id": session_id, "output": output}


async def kill_shell(session_id: str) -> dict:
    session = _CONPTY_SHELL_SESSIONS.pop(session_id, None)
    if session is None:
        return {
            "session_id": session_id,
            "killed": False,
            "stderr": "Persistent shell session not found",
        }

    stderr = await _cleanup_session(session, force=True)
    audit("shell_kill", session=session_id, ok=not stderr, backend="conpty")
    return {"session_id": session_id, "killed": not stderr, "stderr": stderr}


async def list_shells() -> dict:
    sessions = []
    stale_sessions = []
    for session_id, session in list(_CONPTY_SHELL_SESSIONS.items()):
        if not _pty_is_alive(session.process):
            _CONPTY_SHELL_SESSIONS.pop(session_id, None)
            stale_sessions.append(session)
            continue
        sessions.append(
            {
                "session_id": session_id,
                "created": str(session.created),
                "attached": "0",
                "backend": "conpty",
            }
        )
    for stale in stale_sessions:
        await _cleanup_session(stale, force=False)
    return {"sessions": sessions}
