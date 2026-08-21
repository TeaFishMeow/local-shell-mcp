from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=("conpty", "winpty"), default="conpty")
    parser.add_argument("--shell", choices=("cmd.exe", "powershell.exe"), default="powershell.exe")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    os.environ["LOCAL_SHELL_MCP_WORKSPACE_ROOT"] = str(root)
    os.environ["LOCAL_SHELL_MCP_STATE_DIR"] = str(root / ".ctrl-c-smoke-state")
    os.environ["LOCAL_SHELL_MCP_SHELL_EXECUTABLE"] = args.shell
    os.environ["PYWINPTY_BACKEND"] = "1" if args.backend == "winpty" else "0"

    from local_shell_mcp.settings import get_settings
    from local_shell_mcp.shell_ops import kill_shell, read_shell, send_shell, start_shell

    get_settings.cache_clear()
    session = await start_shell(cwd=".", name=f"ctrl-c-{args.backend}")
    session_id = session["session_id"]
    try:
        await asyncio.sleep(1)
        await send_shell(session_id, "q", enter=False)
        await send_shell(session_id, "\x03", enter=False)
        await asyncio.sleep(0.3)
        if args.shell == "cmd.exe":
            await send_shell(session_id, "echo LINE_CANCEL_OK", enter=True)
            await asyncio.sleep(1)
            await send_shell(session_id, "ping -t 127.0.0.1", enter=True)
        else:
            await send_shell(session_id, "Write-Output LINE_CANCEL_OK", enter=True)
            await asyncio.sleep(1)
            await send_shell(session_id, "ping.exe -t 127.0.0.1", enter=True)
        await asyncio.sleep(1.5)
        await send_shell(session_id, "\x03", enter=False)
        await asyncio.sleep(0.5)
        if args.shell == "cmd.exe":
            await send_shell(session_id, "echo PROCESS_INTERRUPT_OK", enter=True)
        else:
            await send_shell(session_id, "Write-Output PROCESS_INTERRUPT_OK", enter=True)
        await asyncio.sleep(1.5)
        output = (await read_shell(session_id, lines=200))["output"]
        result = {
            "backend": args.backend,
            "shell": args.shell,
            "line_cancel": "LINE_CANCEL_OK" in output and "qecho" not in output and "qWrite-Output" not in output,
            "process_interrupt": "PROCESS_INTERRUPT_OK" in output,
            "session_alive": True,
        }
        if not all(result[key] for key in ("line_cancel", "process_interrupt", "session_alive")):
            result["output_tail"] = output[-2000:]
        print(json.dumps(result, ensure_ascii=True))
        return 0 if all(result[key] for key in ("line_cancel", "process_interrupt", "session_alive")) else 1
    except Exception as exc:
        print(json.dumps({"backend": args.backend, "shell": args.shell, "error": repr(exc)}))
        return 1
    finally:
        await kill_shell(session_id)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
