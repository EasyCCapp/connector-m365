#!/usr/bin/env python3
"""Capture an MCP server's tool surface for hash-pinning.

Launches the connector via its stdio entry point, drives the MCP protocol
through `initialize` + `tools/list`, normalizes the response into stable
canonical JSON, and writes it to --output. The caller hashes the file
(e.g. `sha256sum` in CI).

The canonical form is sorted-keys JSON with:
  - tools array sorted by name
  - each tool object's keys sorted
  - parameter schemas serialized stably

This makes the hash reproducible across runs. Stage 4 of the
[MCP security review pipeline](../../docs/carpe/architecture/mcp-security-review-pipeline.md).

The hash detects rug-pulls: a server that ships clean v1, gets vetted,
then ships malicious v2 with different descriptions will produce a
different hash, and the Carpe desktop app refuses connections whose
live snapshot doesn't match the cataloged hash.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
PROTOCOL_VERSION = "2024-11-05"


class ProtocolError(RuntimeError):
    """The server replied with something we couldn't make sense of."""


def _drain_stderr(proc: subprocess.Popen) -> None:
    """Forward server stderr to ours so log output is visible during CI."""
    assert proc.stderr is not None
    for line in iter(proc.stderr.readline, b""):
        try:
            sys.stderr.write(line.decode("utf-8", errors="replace"))
        except Exception:
            pass


def _send(proc: subprocess.Popen, msg: dict[str, Any]) -> None:
    assert proc.stdin is not None
    payload = (json.dumps(msg) + "\n").encode("utf-8")
    proc.stdin.write(payload)
    proc.stdin.flush()


def _recv_response(proc: subprocess.Popen, expected_id: int, timeout_s: float) -> dict[str, Any]:
    """Read lines until we get the JSON-RPC response matching expected_id.

    Notifications (no `id`), unrelated responses, and non-JSON log noise are
    skipped — some servers misbehave and log to stdout instead of stderr.
    """
    assert proc.stdout is not None
    deadline = time.monotonic() + timeout_s
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError(
                f"server did not respond to request id={expected_id} within {timeout_s}s"
            )
        line = proc.stdout.readline()
        if not line:
            raise ProtocolError("server closed stdout before responding")
        text = line.decode("utf-8", errors="replace").strip()
        if not text:
            continue
        try:
            msg = json.loads(text)
        except json.JSONDecodeError:
            sys.stderr.write(f"[snapshot] skipping non-JSON line on stdout: {text!r}\n")
            continue
        if not isinstance(msg, dict):
            continue
        if msg.get("id") == expected_id:
            return msg
        # Otherwise: notification or stale response. Log and continue.
        method = msg.get("method")
        if method:
            sys.stderr.write(f"[snapshot] notification: {method}\n")


def _canonical_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stable ordering of tools and their fields."""
    return sorted(tools, key=lambda t: (t.get("name") or "", json.dumps(t, sort_keys=True)))


def snapshot(launch_cmd: str, cwd: Path | None, timeout_s: float) -> dict[str, Any]:
    cmd = shlex.split(launch_cmd, posix=os.name != "nt")
    if not cmd:
        raise ValueError("launch_cmd is empty")

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=os.environ.copy(),
        bufsize=0,
    )

    stderr_thread = threading.Thread(target=_drain_stderr, args=(proc,), daemon=True)
    stderr_thread.start()

    try:
        _send(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "carpe-tool-surface-snapshot",
                    "version": "0.1.0",
                },
            },
        })
        init_resp = _recv_response(proc, expected_id=1, timeout_s=timeout_s)
        if "error" in init_resp:
            raise ProtocolError(f"initialize returned error: {init_resp['error']}")
        server_info = init_resp.get("result", {}).get("serverInfo", {})
        negotiated = init_resp.get("result", {}).get("protocolVersion")

        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools_resp = _recv_response(proc, expected_id=2, timeout_s=timeout_s)
        if "error" in tools_resp:
            raise ProtocolError(f"tools/list returned error: {tools_resp['error']}")

        tools = tools_resp.get("result", {}).get("tools", [])
        if not isinstance(tools, list):
            raise ProtocolError("tools/list result.tools is not a list")

        return {
            "schema_version": SCHEMA_VERSION,
            "captured_by": "carpe-tool-surface-snapshot",
            "protocol_version": negotiated,
            "server_info": {
                "name": server_info.get("name"),
                "version": server_info.get("version"),
            },
            "tool_count": len(tools),
            "tools": _canonical_tools(tools),
        }
    finally:
        try:
            assert proc.stdin is not None
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--launch-cmd", required=True,
        help="Shell-quoted command that launches the MCP server in stdio mode",
    )
    parser.add_argument(
        "--output", type=Path, required=True,
        help="Path to write the canonical snapshot JSON",
    )
    parser.add_argument(
        "--cwd", type=Path, default=None,
        help="Working directory for the launched server",
    )
    parser.add_argument(
        "--timeout-s", type=float, default=30.0,
        help="Per-message timeout (default: 30s)",
    )
    args = parser.parse_args()

    try:
        snap = snapshot(args.launch_cmd, args.cwd, args.timeout_s)
    except (ProtocolError, TimeoutError) as exc:
        print(f"snapshot failed: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"launch command not found: {exc}", file=sys.stderr)
        return 2

    canonical = json.dumps(snap, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    args.output.write_text(canonical, encoding="utf-8")

    print(
        f"Captured {snap['tool_count']} tools from "
        f"{snap['server_info'].get('name') or 'unknown'} "
        f"{snap['server_info'].get('version') or ''} → {args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
