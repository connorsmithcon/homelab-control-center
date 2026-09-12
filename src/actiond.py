#!/usr/bin/env python3
"""Narrow privileged action broker for Homelab Control Center."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from typing import Any

MAX_REQUEST = 8192
MAX_OUTPUT = 131072
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,126}\.service$")


def run_command(args: list[str], timeout: int) -> dict[str, Any]:
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "DEBIAN_FRONTEND": "noninteractive",
    }
    try:
        result = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
            env=environment,
        )
        output = result.stdout or ""
        encoded = output.encode("utf-8", errors="replace")
        if len(encoded) > MAX_OUTPUT:
            output = "[older output truncated]\n" + encoded[-MAX_OUTPUT:].decode("utf-8", errors="replace")
        return {"ok": result.returncode == 0, "code": result.returncode, "output": output.strip()}
    except subprocess.TimeoutExpired as error:
        output = ""
        if isinstance(error.stdout, bytes):
            output = error.stdout.decode("utf-8", errors="replace")
        elif isinstance(error.stdout, str):
            output = error.stdout
        return {"ok": False, "code": 124, "output": (output + "\nCommand timed out.").strip()}
    except OSError as error:
        return {"ok": False, "code": 126, "output": str(error)}


def validate_request(value: Any) -> tuple[str, list[str], int, str]:
    if not isinstance(value, dict):
        raise ValueError("request must be an object")
    action = value.get("action")

    if action == "service":
        if set(value) != {"action", "operation", "unit"}:
            raise ValueError("service request contains unknown or missing fields")
        operation = value.get("operation")
        unit = value.get("unit")
        if operation not in ("start", "stop", "restart"):
            raise ValueError("service operation is not allowed")
        if not isinstance(unit, str) or not UNIT_RE.fullmatch(unit):
            raise ValueError("service unit is invalid")
        return action, ["/usr/bin/systemctl", operation, unit], 90, operation + ":" + unit

    if action == "updates-refresh":
        if set(value) != {"action"}:
            raise ValueError("update request contains unknown fields")
        return action, ["/usr/bin/apt-get", "update"], 900, action

    if action == "updates-apply":
        if set(value) != {"action"}:
            raise ValueError("update request contains unknown fields")
        return action, ["/usr/bin/apt-get", "-y", "upgrade"], 3600, action

    raise ValueError("action is not allowed")


def read_request(connection: socket.socket) -> Any:
    connection.settimeout(10)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = connection.recv(1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_REQUEST:
            raise ValueError("request is too large")
        chunks.append(chunk)
        if b"\n" in chunk:
            break
    raw = b"".join(chunks).split(b"\n", 1)[0]
    if not raw:
        raise ValueError("request is empty")
    return json.loads(raw.decode("utf-8"))


def send_response(connection: socket.socket, response: dict[str, Any]) -> None:
    payload = json.dumps(response, separators=(",", ":")).encode("utf-8")
    connection.sendall(payload)


def listener_from_systemd() -> socket.socket:
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("actiond must be started by homelab-control-center-actions.socket")
    listener = socket.socket(fileno=3)
    listener.setblocking(True)
    return listener


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("actiond must run as root")
    listener = listener_from_systemd()
    print(json.dumps({"event": "action-broker-started", "time": int(time.time())}), flush=True)

    while True:
        connection, _ = listener.accept()
        with connection:
            label = "invalid"
            try:
                request = read_request(connection)
                action, command, timeout, label = validate_request(request)
                result = run_command(command, timeout)
                print(
                    json.dumps(
                        {
                            "event": "privileged-action",
                            "action": action,
                            "target": label,
                            "code": result["code"],
                            "time": int(time.time()),
                        }
                    ),
                    flush=True,
                )
                send_response(connection, result)
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
                print(
                    json.dumps(
                        {
                            "event": "privileged-action-rejected",
                            "target": label,
                            "reason": str(error),
                            "time": int(time.time()),
                        }
                    ),
                    flush=True,
                )
                send_response(connection, {"ok": False, "code": 2, "output": "Action rejected: " + str(error)})
            except (BrokenPipeError, ConnectionResetError):
                continue
            except Exception as error:
                print(
                    json.dumps(
                        {
                            "event": "privileged-action-error",
                            "target": label,
                            "reason": type(error).__name__,
                            "time": int(time.time()),
                        }
                    ),
                    flush=True,
                )
                try:
                    send_response(connection, {"ok": False, "code": 1, "output": "Internal action broker error."})
                except OSError:
                    pass


if __name__ == "__main__":
    main()
