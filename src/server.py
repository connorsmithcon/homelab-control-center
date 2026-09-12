#!/usr/bin/env python3
"""Homelab Control Center web service.

The service intentionally uses only the Python standard library. It runs as the
unprivileged hcc user and delegates the small local write-action allowlist to
the separate action broker over a Unix socket.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import http.cookies
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parent.parent
STATIC_ROOT = Path(__file__).resolve().parent / "static"
VERSION_FILE = APP_ROOT / "VERSION"
VERSION = VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "development"

DEFAULT_CONFIG: dict[str, Any] = {
    "bind": "127.0.0.1",
    "port": 8088,
    "secure_cookies": False,
    "session_hours": 12,
    "database": "/var/lib/homelab-control-center/control-center.db",
    "bootstrap_token_file": "/var/lib/homelab-control-center/bootstrap-token",
    "ssh_directory": "/var/lib/homelab-control-center/.ssh",
    "action_socket": "/run/homelab-control-center/actions.sock",
    "command_timeout_seconds": 15,
    "max_log_lines": 500,
}

CONFIG: dict[str, Any] = {}
LOGIN_WINDOW_SECONDS = 600
LOGIN_MAX_ATTEMPTS = 5
MAX_BODY_BYTES = 65536
MAX_OUTPUT_BYTES = 131072
SESSION_COOKIE = "hcc_session"
CSRF_COOKIE = "hcc_csrf"

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")
SSH_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,126}\.service$")

_login_attempts: dict[str, list[float]] = {}
_login_lock = threading.Lock()
_cpu_samples: dict[str, tuple[int, int]] = {}
_cpu_lock = threading.Lock()
_known_hosts_lock = threading.Lock()
_update_cache: dict[str, tuple[float, int | None]] = {}
_update_lock = threading.Lock()


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def now() -> int:
    return int(time.time())


def load_config(path: str) -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    with open(path, "r", encoding="utf-8") as handle:
        supplied = json.load(handle)
    if not isinstance(supplied, dict):
        raise ValueError("configuration root must be an object")
    unknown = sorted(set(supplied) - set(DEFAULT_CONFIG))
    if unknown:
        raise ValueError("unknown configuration keys: " + ", ".join(unknown))
    config.update(supplied)

    if not isinstance(config["bind"], str) or not config["bind"]:
        raise ValueError("bind must be a non-empty string")
    if not isinstance(config["port"], int) or not 1 <= config["port"] <= 65535:
        raise ValueError("port must be an integer from 1 through 65535")
    if not isinstance(config["secure_cookies"], bool):
        raise ValueError("secure_cookies must be true or false")
    if not isinstance(config["session_hours"], int) or not 1 <= config["session_hours"] <= 168:
        raise ValueError("session_hours must be from 1 through 168")
    if not isinstance(config["command_timeout_seconds"], int) or not 3 <= config["command_timeout_seconds"] <= 120:
        raise ValueError("command_timeout_seconds must be from 3 through 120")
    if not isinstance(config["max_log_lines"], int) or not 50 <= config["max_log_lines"] <= 5000:
        raise ValueError("max_log_lines must be from 50 through 5000")
    return config


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(CONFIG["database"], timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def initialize_database() -> None:
    database = Path(CONFIG["database"])
    database.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as connection:
        connection.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role = 'admin'),
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS nodes (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(host, port, username)
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                outcome TEXT NOT NULL,
                details TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_created_idx ON audit(created_at DESC);
            """
        )
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now(),))
    os.chmod(database, 0o600)


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    encoded = password.encode("utf-8")
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        encoded,
        salt=salt,
        n=32768,
        r=8,
        p=1,
        maxmem=64 * 1024 * 1024,
        dklen=32,
    )
    return "scrypt$32768$8$1$" + b64encode(salt) + "$" + b64encode(derived)


def verify_password(password: str, record: str) -> bool:
    try:
        algorithm, n_value, r_value, p_value, salt_value, hash_value = record.split("$")
        if algorithm != "scrypt":
            return False
        expected = b64decode(hash_value)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=b64decode(salt_value),
            n=int(n_value),
            r=int(r_value),
            p=int(p_value),
            maxmem=64 * 1024 * 1024,
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_password(password: Any) -> str:
    if not isinstance(password, str):
        raise ApiError(400, "Password must be a string.")
    if len(password) < 12:
        raise ApiError(400, "Password must contain at least 12 characters.")
    if len(password) > 256 or len(password.encode("utf-8")) > 1024:
        raise ApiError(400, "Password is too long.")
    return password


def validate_username(username: Any) -> str:
    if not isinstance(username, str):
        raise ApiError(400, "Username must be a string.")
    username = username.strip()
    if not USERNAME_RE.fullmatch(username):
        raise ApiError(400, "Username must be 3-32 characters using letters, numbers, dot, dash, or underscore.")
    return username


def validate_node_fields(data: dict[str, Any]) -> tuple[str, str, int, str]:
    name = data.get("name")
    host = data.get("host")
    username = data.get("username")
    port = data.get("port", 22)
    if not isinstance(name, str) or not NODE_NAME_RE.fullmatch(name.strip()):
        raise ApiError(400, "Node name is invalid.")
    if not isinstance(host, str) or not HOST_RE.fullmatch(host.strip()):
        raise ApiError(400, "Host is invalid.")
    if not isinstance(username, str) or not SSH_USER_RE.fullmatch(username.strip()):
        raise ApiError(400, "SSH username is invalid.")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ApiError(400, "SSH port must be from 1 through 65535.")
    return name.strip(), host.strip(), port, username.strip()


def validate_unit(unit: Any) -> str:
    if not isinstance(unit, str) or not UNIT_RE.fullmatch(unit):
        raise ApiError(400, "A valid .service unit name is required.")
    return unit


def audit(username: str, source_ip: str, action: str, target: str, outcome: str, details: dict[str, Any] | None = None) -> None:
    safe_details = json.dumps(details or {}, separators=(",", ":"), sort_keys=True)
    if len(safe_details) > 2048:
        safe_details = '{"notice":"details truncated"}'
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO audit(created_at, username, source_ip, action, target, outcome, details) VALUES(?,?,?,?,?,?,?)",
            (now(), username, source_ip, action[:64], target[:160], outcome[:32], safe_details),
        )


def users_exist() -> bool:
    with connect_db() as connection:
        return connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def create_session(user_id: int) -> tuple[str, str, int]:
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    created = now()
    expires = created + int(CONFIG["session_hours"]) * 3600
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO sessions(token_hash, user_id, csrf_hash, created_at, expires_at, last_seen) VALUES(?,?,?,?,?,?)",
            (token_digest(session_token), user_id, token_digest(csrf_token), created, expires, created),
        )
    return session_token, csrf_token, expires


def parse_cookie(header: str | None) -> dict[str, str]:
    if not header:
        return {}
    jar = http.cookies.SimpleCookie()
    try:
        jar.load(header)
    except http.cookies.CookieError:
        return {}
    return {name: morsel.value for name, morsel in jar.items()}


def prune_login_attempts(source_ip: str) -> list[float]:
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    with _login_lock:
        attempts = [value for value in _login_attempts.get(source_ip, []) if value >= cutoff]
        _login_attempts[source_ip] = attempts
        return attempts


def check_login_limit(source_ip: str) -> None:
    if len(prune_login_attempts(source_ip)) >= LOGIN_MAX_ATTEMPTS:
        raise ApiError(429, "Too many attempts. Wait ten minutes and try again.")


def record_login_failure(source_ip: str) -> None:
    with _login_lock:
        _login_attempts.setdefault(source_ip, []).append(time.time())


def clear_login_failures(source_ip: str) -> None:
    with _login_lock:
        _login_attempts.pop(source_ip, None)


def run_command(args: list[str], timeout: int | None = None, input_text: str | None = None) -> tuple[int, str]:
    try:
        result = subprocess.run(
            args,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout or int(CONFIG["command_timeout_seconds"]),
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except FileNotFoundError:
        return 127, "Command is not available."
    except subprocess.TimeoutExpired:
        return 124, "Command timed out."
    output = result.stdout or ""
    encoded = output.encode("utf-8", errors="replace")
    if len(encoded) > MAX_OUTPUT_BYTES:
        output = encoded[-MAX_OUTPUT_BYTES:].decode("utf-8", errors="replace")
        output = "[older output truncated]\n" + output
    return result.returncode, output.strip()


def parse_os_release(text: str) -> str:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values.get("PRETTY_NAME") or values.get("NAME") or "Linux"


def cpu_percent(key: str, stat_text: str) -> float | None:
    line = next((item for item in stat_text.splitlines() if item.startswith("cpu ")), "")
    parts = line.split()
    if len(parts) < 5:
        return None
    try:
        numbers = [int(value) for value in parts[1:]]
    except ValueError:
        return None
    total = sum(numbers)
    idle = numbers[3] + (numbers[4] if len(numbers) > 4 else 0)
    with _cpu_lock:
        previous = _cpu_samples.get(key)
        _cpu_samples[key] = (total, idle)
    if previous is None:
        return None
    total_delta = total - previous[0]
    idle_delta = idle - previous[1]
    if total_delta <= 0:
        return None
    return round(100.0 * (total_delta - idle_delta) / total_delta, 1)


def parse_meminfo(text: str) -> tuple[int, int, float]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        token = raw.strip().split()[0] if raw.strip() else "0"
        if token.isdigit():
            values[key] = int(token) * 1024
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    used = max(0, total - available)
    percent = round(used * 100.0 / total, 1) if total else 0.0
    return total, used, percent


def parse_network(text: str) -> tuple[int, int]:
    received = 0
    sent = 0
    for line in text.splitlines():
        if ":" not in line:
            continue
        _, raw = line.split(":", 1)
        fields = raw.split()
        if len(fields) >= 9 and fields[0].isdigit() and fields[8].isdigit():
            received += int(fields[0])
            sent += int(fields[8])
    return received, sent


def cached_local_update_count() -> int | None:
    key = "local"
    with _update_lock:
        cached = _update_cache.get(key)
        if cached and time.time() - cached[0] < 600:
            return cached[1]
    code, output = run_command(["/usr/bin/apt-get", "-s", "upgrade"], timeout=30)
    value = sum(1 for line in output.splitlines() if line.startswith("Inst ")) if code == 0 else None
    with _update_lock:
        _update_cache[key] = (time.time(), value)
    return value


def local_snapshot() -> dict[str, Any]:
    stat_text = Path("/proc/stat").read_text(encoding="utf-8", errors="replace")
    mem_text = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
    net_text = Path("/proc/net/dev").read_text(encoding="utf-8", errors="replace")
    uptime = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
    load = os.getloadavg()
    disk = shutil.disk_usage("/")
    total_memory, used_memory, memory_percent = parse_meminfo(mem_text)
    received, sent = parse_network(net_text)
    os_text = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace") if Path("/etc/os-release").exists() else ""
    return {
        "id": 0,
        "name": socket.gethostname(),
        "host": "local",
        "online": True,
        "os": parse_os_release(os_text),
        "kernel": os.uname().release,
        "uptime_seconds": int(uptime),
        "load": [round(value, 2) for value in load],
        "cpu_percent": cpu_percent("local", stat_text),
        "memory": {"total": total_memory, "used": used_memory, "percent": memory_percent},
        "disk": {"total": disk.total, "used": disk.used, "percent": round(disk.used * 100.0 / disk.total, 1) if disk.total else 0},
        "network": {"received": received, "sent": sent},
        "updates": cached_local_update_count(),
    }


REMOTE_SNAPSHOT_COMMAND = """printf '%s\n' __HCC_HOSTNAME__; hostname; printf '%s\n' __HCC_KERNEL__; uname -sr; printf '%s\n' __HCC_UPTIME__; cat /proc/uptime; printf '%s\n' __HCC_LOAD__; cat /proc/loadavg; printf '%s\n' __HCC_STAT__; cat /proc/stat; printf '%s\n' __HCC_MEM__; cat /proc/meminfo; printf '%s\n' __HCC_DISK__; df -Pk /; printf '%s\n' __HCC_NET__; cat /proc/net/dev; printf '%s\n' __HCC_OS__; cat /etc/os-release 2>/dev/null || true"""


def sectioned_output(text: str) -> dict[str, str]:
    result: dict[str, list[str]] = {}
    current = ""
    for line in text.splitlines():
        if line.startswith("__HCC_") and line.endswith("__"):
            current = line
            result[current] = []
        elif current:
            result[current].append(line)
    return {key: "\n".join(value) for key, value in result.items()}


def ssh_paths() -> tuple[Path, Path]:
    directory = Path(CONFIG["ssh_directory"])
    return directory / "id_ed25519", directory / "known_hosts"


def ssh_args(node: dict[str, Any], remote_command: str) -> list[str]:
    identity, known_hosts = ssh_paths()
    return [
        "/usr/bin/ssh",
        "-i",
        str(identity),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=" + str(known_hosts),
        "-o",
        "ConnectTimeout=" + str(min(15, int(CONFIG["command_timeout_seconds"]))),
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        "-p",
        str(node["port"]),
        str(node["username"]) + "@" + str(node["host"]),
        "--",
        remote_command,
    ]


def ssh_run(node: dict[str, Any], command: str, timeout: int | None = None) -> tuple[int, str]:
    return run_command(ssh_args(node, command), timeout=timeout)


def remote_snapshot(node: dict[str, Any]) -> dict[str, Any]:
    code, output = ssh_run(node, REMOTE_SNAPSHOT_COMMAND, timeout=int(CONFIG["command_timeout_seconds"]) + 5)
    base = {"id": node["id"], "name": node["name"], "host": node["host"], "online": False}
    if code != 0:
        base["error"] = output or "SSH connection failed."
        return base

    parts = sectioned_output(output)
    uptime_tokens = parts.get("__HCC_UPTIME__", "0").split()
    load_tokens = parts.get("__HCC_LOAD__", "0 0 0").split()
    total_memory, used_memory, memory_percent = parse_meminfo(parts.get("__HCC_MEM__", ""))
    received, sent = parse_network(parts.get("__HCC_NET__", ""))

    disk_total = 0
    disk_used = 0
    disk_lines = parts.get("__HCC_DISK__", "").splitlines()
    if len(disk_lines) >= 2:
        fields = disk_lines[-1].split()
        if len(fields) >= 3 and fields[1].isdigit() and fields[2].isdigit():
            disk_total = int(fields[1]) * 1024
            disk_used = int(fields[2]) * 1024

    return {
        **base,
        "online": True,
        "os": parse_os_release(parts.get("__HCC_OS__", "")),
        "kernel": parts.get("__HCC_KERNEL__", "Linux").strip(),
        "uptime_seconds": int(float(uptime_tokens[0])) if uptime_tokens else 0,
        "load": [float(value) for value in load_tokens[:3]] if len(load_tokens) >= 3 else [0, 0, 0],
        "cpu_percent": cpu_percent("node:" + str(node["id"]), parts.get("__HCC_STAT__", "")),
        "memory": {"total": total_memory, "used": used_memory, "percent": memory_percent},
        "disk": {
            "total": disk_total,
            "used": disk_used,
            "percent": round(disk_used * 100.0 / disk_total, 1) if disk_total else 0,
        },
        "network": {"received": received, "sent": sent},
        "updates": None,
    }


def node_rows() -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute("SELECT id, name, host, port, username, created_at FROM nodes ORDER BY name").fetchall()
    return [dict(row) for row in rows]


def get_node(node_id: int) -> dict[str, Any]:
    if node_id == 0:
        return {"id": 0, "name": socket.gethostname(), "host": "local", "port": 0, "username": "hcc"}
    with connect_db() as connection:
        row = connection.execute("SELECT id, name, host, port, username, created_at FROM nodes WHERE id = ?", (node_id,)).fetchone()
    if row is None:
        raise ApiError(404, "Node was not found.")
    return dict(row)


def all_snapshots() -> list[dict[str, Any]]:
    nodes = node_rows()
    snapshots: list[dict[str, Any]] = []
    try:
        snapshots.append(local_snapshot())
    except Exception as error:
        snapshots.append({"id": 0, "name": socket.gethostname(), "host": "local", "online": False, "error": str(error)})
    if nodes:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(nodes))) as executor:
            snapshots.extend(executor.map(remote_snapshot, nodes))
    return snapshots


def parse_service_output(output: str) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.lstrip("● ").strip()
        fields = line.split(None, 4)
        if len(fields) < 4 or not fields[0].endswith(".service"):
            continue
        services.append(
            {
                "unit": fields[0],
                "load": fields[1],
                "active": fields[2],
                "sub": fields[3],
                "description": fields[4] if len(fields) > 4 else "",
            }
        )
        if len(services) >= 500:
            break
    return services


def list_services(node: dict[str, Any]) -> list[dict[str, str]]:
    command = ["/usr/bin/systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"]
    if node["id"] == 0:
        code, output = run_command(command)
    else:
        code, output = ssh_run(node, "LC_ALL=C systemctl list-units --type=service --all --no-legend --no-pager --plain")
    if code != 0:
        raise ApiError(502, output or "Unable to list services.")
    return parse_service_output(output)


def read_logs(node: dict[str, Any], unit: str, lines: int) -> str:
    if node["id"] == 0:
        code, output = run_command(
            ["/usr/bin/journalctl", "-u", unit, "-n", str(lines), "--no-pager", "-o", "short-iso"],
            timeout=int(CONFIG["command_timeout_seconds"]),
        )
    else:
        command = "LC_ALL=C journalctl -u " + unit + " -n " + str(lines) + " --no-pager -o short-iso"
        code, output = ssh_run(node, command)
    if code not in (0, 1):
        raise ApiError(502, output or "Unable to read journal.")
    return output


def list_updates(node: dict[str, Any]) -> dict[str, Any]:
    if node["id"] == 0:
        code, output = run_command(["/usr/bin/apt-get", "-s", "upgrade"], timeout=45)
    else:
        code, output = ssh_run(node, "LC_ALL=C apt-get -s upgrade", timeout=45)
    if code != 0:
        return {"supported": False, "packages": [], "message": output or "apt-get simulation failed."}
    packages: list[dict[str, str]] = []
    for line in output.splitlines():
        if not line.startswith("Inst "):
            continue
        fields = line.split()
        packages.append({"name": fields[1] if len(fields) > 1 else "unknown", "detail": line})
    return {"supported": True, "packages": packages, "count": len(packages)}


def broker_action(payload: dict[str, Any]) -> dict[str, Any]:
    socket_path = str(CONFIG["action_socket"])
    request = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(request) > 8192:
        raise ApiError(400, "Action request is too large.")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3700)
    try:
        client.connect(socket_path)
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = client.recv(8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_OUTPUT_BYTES:
                raise ApiError(502, "Action broker response is too large.")
            chunks.append(chunk)
    except (FileNotFoundError, ConnectionRefusedError):
        raise ApiError(503, "The local action broker is unavailable.")
    except socket.timeout:
        raise ApiError(504, "The local action timed out.")
    finally:
        client.close()
    try:
        response = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ApiError(502, "The action broker returned an invalid response.")
    if not isinstance(response, dict):
        raise ApiError(502, "The action broker returned an invalid response.")
    return response


def probe_host_keys(host: str, port: int) -> dict[str, Any]:
    code, output = run_command(["/usr/bin/ssh-keyscan", "-T", "5", "-p", str(port), host], timeout=10)
    lines = [line.strip() for line in output.splitlines() if line.strip() and not line.startswith("#")]
    if code != 0 and not lines:
        raise ApiError(502, "Could not retrieve an SSH host key.")
    keys = "\n".join(lines) + "\n"
    fingerprint_code, fingerprints = run_command(["/usr/bin/ssh-keygen", "-lf", "-", "-E", "sha256"], timeout=10, input_text=keys)
    if fingerprint_code != 0:
        raise ApiError(502, "The SSH host key was invalid.")
    return {"host_keys": keys, "fingerprints": fingerprints.splitlines()}


def verify_submitted_host_keys(host: str, port: int, submitted: Any) -> str:
    if not isinstance(submitted, str) or len(submitted.encode("utf-8")) > 32768:
        raise ApiError(400, "Trusted host keys are required.")
    submitted_lines = {line.strip() for line in submitted.splitlines() if line.strip() and not line.startswith("#")}
    if not submitted_lines:
        raise ApiError(400, "Trusted host keys are required.")
    fresh = probe_host_keys(host, port)["host_keys"]
    fresh_lines = {line.strip() for line in fresh.splitlines() if line.strip()}
    trusted = submitted_lines.intersection(fresh_lines)
    if not trusted:
        raise ApiError(409, "The host key changed after it was probed. Verify the host before trying again.")
    key_text = "\n".join(sorted(trusted)) + "\n"
    code, _ = run_command(["/usr/bin/ssh-keygen", "-lf", "-", "-E", "sha256"], input_text=key_text)
    if code != 0:
        raise ApiError(400, "Trusted host key data is invalid.")
    return key_text


def append_known_hosts(key_text: str) -> None:
    _, known_hosts = ssh_paths()
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    with _known_hosts_lock:
        with open(known_hosts, "a", encoding="utf-8") as handle:
            handle.write(key_text)
        os.chmod(known_hosts, 0o600)


def public_key() -> str:
    identity, _ = ssh_paths()
    public = Path(str(identity) + ".pub")
    if not public.exists():
        return ""
    return public.read_text(encoding="utf-8").strip()


class Handler(BaseHTTPRequestHandler):
    server_version = "HomelabControlCenter"
    sys_version = ""

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format_string: str, *args: Any) -> None:
        message = format_string % args
        print(json.dumps({"time": now(), "source_ip": self.client_address[0], "http": message}), flush=True)

    def send_common_headers(self) -> None:
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    def send_json(self, value: Any, status: int = 200, cookies: list[str] | None = None) -> None:
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_common_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(payload)

    def send_empty(self, status: int = 204, cookies: list[str] | None = None) -> None:
        self.send_response(status)
        self.send_common_headers()
        self.send_header("Cache-Control", "no-store")
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def send_static(self, filename: str, content_type: str) -> None:
        candidate = STATIC_ROOT / filename
        if not candidate.is_file():
            raise ApiError(404, "Not found.")
        payload = candidate.read_bytes()
        self.send_response(200)
        self.send_common_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache" if filename == "index.html" else "public, max-age=3600")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def read_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            raise ApiError(415, "Content-Type must be application/json.")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ApiError(411, "Content-Length is required.")
        try:
            length = int(raw_length)
        except ValueError:
            raise ApiError(400, "Content-Length is invalid.")
        if length < 0 or length > MAX_BODY_BYTES:
            raise ApiError(413, "Request body is too large.")
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "Request body is not valid JSON.")
        if not isinstance(value, dict):
            raise ApiError(400, "JSON body must be an object.")
        return value

    @property
    def source_ip(self) -> str:
        return self.client_address[0]

    def session(self) -> sqlite3.Row:
        token = parse_cookie(self.headers.get("Cookie")).get(SESSION_COOKIE, "")
        if not token:
            raise ApiError(401, "Authentication required.")
        digest = token_digest(token)
        with connect_db() as connection:
            row = connection.execute(
                """
                SELECT sessions.token_hash, sessions.csrf_hash, sessions.expires_at,
                       sessions.last_seen, users.id AS user_id, users.username, users.role
                FROM sessions JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ?
                """,
                (digest,),
            ).fetchone()
            if row is None or row["expires_at"] <= now():
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))
                raise ApiError(401, "Session expired.")
            if row["last_seen"] < now() - 300:
                connection.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now(), digest))
        return row

    def require_csrf(self, session: sqlite3.Row) -> None:
        cookie = parse_cookie(self.headers.get("Cookie")).get(CSRF_COOKIE, "")
        header = self.headers.get("X-CSRF-Token", "")
        if not cookie or not header or not hmac.compare_digest(cookie, header):
            raise ApiError(403, "CSRF validation failed.")
        if not hmac.compare_digest(token_digest(header), session["csrf_hash"]):
            raise ApiError(403, "CSRF validation failed.")

    def auth_cookies(self, session_token: str, csrf_token: str, expires: int) -> list[str]:
        max_age = max(0, expires - now())
        secure = "; Secure" if CONFIG["secure_cookies"] else ""
        return [
            SESSION_COOKIE + "=" + session_token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + str(max_age) + secure,
            CSRF_COOKIE + "=" + csrf_token + "; Path=/; SameSite=Strict; Max-Age=" + str(max_age) + secure,
        ]

    def expired_cookies(self) -> list[str]:
        secure = "; Secure" if CONFIG["secure_cookies"] else ""
        return [
            SESSION_COOKIE + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + secure,
            CSRF_COOKIE + "=; Path=/; SameSite=Strict; Max-Age=0" + secure,
        ]

    def do_GET(self) -> None:
        self.dispatch("GET")

    def do_POST(self) -> None:
        self.dispatch("POST")

    def do_DELETE(self) -> None:
        self.dispatch("DELETE")

    def do_OPTIONS(self) -> None:
        self.send_json({"error": "Cross-origin API access is not enabled."}, 405)

    def dispatch(self, method: str) -> None:
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)

            if method == "GET" and path in ("/", "/index.html"):
                self.send_static("index.html", "text/html; charset=utf-8")
                return
            if method == "GET" and path == "/app.js":
                self.send_static("app.js", "text/javascript; charset=utf-8")
                return
            if method == "GET" and path == "/styles.css":
                self.send_static("styles.css", "text/css; charset=utf-8")
                return
            if method == "GET" and path == "/api/health":
                self.send_json({"ok": True, "version": VERSION, "setup_required": not users_exist()})
                return
            if method == "POST" and path == "/api/setup":
                self.handle_setup()
                return
            if method == "POST" and path == "/api/login":
                self.handle_login()
                return

            session = self.session()

            if method == "GET" and path == "/api/me":
                self.send_json({"username": session["username"], "role": session["role"], "version": VERSION})
            elif method == "POST" and path == "/api/logout":
                self.require_csrf(session)
                self.handle_logout(session)
            elif method == "POST" and path == "/api/password":
                self.require_csrf(session)
                self.handle_password(session)
            elif method == "GET" and path == "/api/overview":
                self.send_json({"nodes": all_snapshots(), "generated_at": now()})
            elif method == "GET" and path == "/api/nodes":
                self.send_json({"nodes": [{"id": 0, "name": socket.gethostname(), "host": "local", "port": 0, "username": "hcc", "created_at": 0}] + node_rows()})
            elif method == "POST" and path == "/api/nodes/probe":
                self.require_csrf(session)
                self.handle_probe()
            elif method == "POST" and path == "/api/nodes":
                self.require_csrf(session)
                self.handle_add_node(session)
            elif method == "DELETE" and path.startswith("/api/nodes/"):
                self.require_csrf(session)
                self.handle_delete_node(session, path)
            elif method == "GET" and path == "/api/services":
                node = get_node(self.query_int(query, "node_id", 0, 0, 2147483647))
                self.send_json({"node": node, "services": list_services(node)})
            elif method == "GET" and path == "/api/logs":
                node = get_node(self.query_int(query, "node_id", 0, 0, 2147483647))
                unit = validate_unit(self.query_string(query, "unit"))
                lines = self.query_int(query, "lines", 200, 1, int(CONFIG["max_log_lines"]))
                self.send_json({"node": node, "unit": unit, "lines": read_logs(node, unit, lines)})
            elif method == "GET" and path == "/api/updates":
                node = get_node(self.query_int(query, "node_id", 0, 0, 2147483647))
                self.send_json({"node": node, **list_updates(node)})
            elif method == "POST" and path == "/api/action/service":
                self.require_csrf(session)
                self.handle_service_action(session)
            elif method == "POST" and path == "/api/action/updates":
                self.require_csrf(session)
                self.handle_update_action(session)
            elif method == "GET" and path == "/api/audit":
                self.handle_audit()
            elif method == "GET" and path == "/api/settings":
                self.send_json(
                    {
                        "version": VERSION,
                        "listener": str(CONFIG["bind"]) + ":" + str(CONFIG["port"]),
                        "secure_cookies": CONFIG["secure_cookies"],
                        "session_hours": CONFIG["session_hours"],
                        "ssh_public_key": public_key(),
                    }
                )
            else:
                raise ApiError(404, "Not found.")
        except ApiError as error:
            self.send_json({"error": error.message}, error.status)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            traceback.print_exc()
            self.send_json({"error": "Internal server error."}, 500)

    def query_string(self, query: dict[str, list[str]], name: str) -> str:
        values = query.get(name)
        if not values or not values[0]:
            raise ApiError(400, name + " is required.")
        return values[0]

    def query_int(self, query: dict[str, list[str]], name: str, default: int, minimum: int, maximum: int) -> int:
        values = query.get(name)
        if not values:
            return default
        try:
            value = int(values[0])
        except ValueError:
            raise ApiError(400, name + " must be an integer.")
        if not minimum <= value <= maximum:
            raise ApiError(400, name + " is outside the allowed range.")
        return value

    def handle_setup(self) -> None:
        check_login_limit(self.source_ip)
        if users_exist():
            raise ApiError(409, "Setup is already complete.")
        data = self.read_json()
        username = validate_username(data.get("username"))
        password = validate_password(data.get("password"))
        supplied_token = data.get("bootstrap_token")
        if not isinstance(supplied_token, str):
            raise ApiError(400, "Bootstrap token is required.")
        token_path = Path(CONFIG["bootstrap_token_file"])
        try:
            expected_token = token_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            raise ApiError(503, "Bootstrap token is unavailable. Run homelabctl bootstrap-token.")
        if not hmac.compare_digest(supplied_token, expected_token):
            record_login_failure(self.source_ip)
            audit("setup", self.source_ip, "setup", "administrator", "denied")
            raise ApiError(401, "Setup credentials are invalid.")

        with connect_db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None:
                raise ApiError(409, "Setup is already complete.")
            cursor = connection.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)",
                (username, hash_password(password), "admin", now()),
            )
            user_id = int(cursor.lastrowid)
        try:
            token_path.unlink()
        except FileNotFoundError:
            pass
        clear_login_failures(self.source_ip)
        session_token, csrf_token, expires = create_session(user_id)
        audit(username, self.source_ip, "setup", "administrator", "success")
        self.send_json(
            {"username": username, "role": "admin", "version": VERSION},
            201,
            self.auth_cookies(session_token, csrf_token, expires),
        )

    def handle_login(self) -> None:
        check_login_limit(self.source_ip)
        data = self.read_json()
        username = data.get("username")
        password = data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            raise ApiError(400, "Username and password are required.")
        with connect_db() as connection:
            row = connection.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ? COLLATE NOCASE",
                (username.strip(),),
            ).fetchone()
        if row is None or not verify_password(password, row["password_hash"]):
            record_login_failure(self.source_ip)
            audit(username.strip()[:32] or "unknown", self.source_ip, "login", "session", "denied")
            raise ApiError(401, "Username or password is incorrect.")
        clear_login_failures(self.source_ip)
        session_token, csrf_token, expires = create_session(int(row["id"]))
        audit(row["username"], self.source_ip, "login", "session", "success")
        self.send_json(
            {"username": row["username"], "role": row["role"], "version": VERSION},
            cookies=self.auth_cookies(session_token, csrf_token, expires),
        )

    def handle_logout(self, session: sqlite3.Row) -> None:
        with connect_db() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (session["token_hash"],))
        audit(session["username"], self.source_ip, "logout", "session", "success")
        self.send_empty(cookies=self.expired_cookies())

    def handle_password(self, session: sqlite3.Row) -> None:
        data = self.read_json()
        current_password = data.get("current_password")
        new_password = validate_password(data.get("new_password"))
        if not isinstance(current_password, str):
            raise ApiError(400, "Current password is required.")
        with connect_db() as connection:
            user = connection.execute("SELECT password_hash FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            if user is None or not verify_password(current_password, user["password_hash"]):
                audit(session["username"], self.source_ip, "password-change", "administrator", "denied")
                raise ApiError(401, "Current password is incorrect.")
            connection.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), session["user_id"]))
            connection.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?",
                (session["user_id"], session["token_hash"]),
            )
        audit(session["username"], self.source_ip, "password-change", "administrator", "success")
        self.send_json({"ok": True})

    def handle_probe(self) -> None:
        data = self.read_json()
        _, host, port, _ = validate_node_fields(
            {
                "name": data.get("name", "Probe"),
                "host": data.get("host"),
                "port": data.get("port", 22),
                "username": data.get("username", "monitor"),
            }
        )
        self.send_json(probe_host_keys(host, port))

    def handle_add_node(self, session: sqlite3.Row) -> None:
        data = self.read_json()
        name, host, port, username = validate_node_fields(data)
        key_text = verify_submitted_host_keys(host, port, data.get("host_keys"))
        try:
            with connect_db() as connection:
                cursor = connection.execute(
                    "INSERT INTO nodes(name, host, port, username, created_at) VALUES(?,?,?,?,?)",
                    (name, host, port, username, now()),
                )
                node_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError:
            raise ApiError(409, "That node name or SSH target already exists.")
        append_known_hosts(key_text)
        audit(session["username"], self.source_ip, "node-add", name, "success", {"host": host, "port": port, "username": username})
        self.send_json({"id": node_id, "name": name, "host": host, "port": port, "username": username}, 201)

    def handle_delete_node(self, session: sqlite3.Row, path: str) -> None:
        raw_id = path.removeprefix("/api/nodes/")
        try:
            node_id = int(raw_id)
        except ValueError:
            raise ApiError(400, "Node id is invalid.")
        if node_id <= 0:
            raise ApiError(400, "The local node cannot be removed.")
        node = get_node(node_id)
        with connect_db() as connection:
            connection.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
        audit(session["username"], self.source_ip, "node-delete", node["name"], "success", {"host": node["host"]})
        self.send_empty()

    def handle_service_action(self, session: sqlite3.Row) -> None:
        data = self.read_json()
        node = get_node(int(data.get("node_id", 0)))
        unit = validate_unit(data.get("unit"))
        action = data.get("action")
        if action not in ("start", "stop", "restart"):
            raise ApiError(400, "Service action must be start, stop, or restart.")
        if node["id"] == 0:
            result = broker_action({"action": "service", "operation": action, "unit": unit})
        else:
            code, output = ssh_run(
                node,
                "sudo -n /usr/local/sbin/hcc-node-helper service " + action + " " + unit,
                timeout=90,
            )
            result = {"ok": code == 0, "code": code, "output": output}
        outcome = "success" if result.get("ok") else "failed"
        audit(session["username"], self.source_ip, "service-" + action, node["name"] + ":" + unit, outcome)
        status = 200 if result.get("ok") else 502
        self.send_json(result, status)

    def handle_update_action(self, session: sqlite3.Row) -> None:
        data = self.read_json()
        node = get_node(int(data.get("node_id", 0)))
        operation = data.get("operation")
        if operation not in ("refresh", "apply"):
            raise ApiError(400, "Update operation must be refresh or apply.")
        if operation == "apply" and data.get("confirm") != "APPLY":
            raise ApiError(400, "Type APPLY to confirm package installation.")
        if node["id"] == 0:
            result = broker_action({"action": "updates-" + operation})
        else:
            code, output = ssh_run(
                node,
                "sudo -n /usr/local/sbin/hcc-node-helper updates-" + operation,
                timeout=3700,
            )
            result = {"ok": code == 0, "code": code, "output": output}
        with _update_lock:
            _update_cache.clear()
        outcome = "success" if result.get("ok") else "failed"
        audit(session["username"], self.source_ip, "updates-" + operation, node["name"], outcome)
        status = 200 if result.get("ok") else 502
        self.send_json(result, status)

    def handle_audit(self) -> None:
        with connect_db() as connection:
            rows = connection.execute(
                "SELECT id, created_at, username, source_ip, action, target, outcome, details FROM audit ORDER BY id DESC LIMIT 200"
            ).fetchall()
        events = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item["details"])
            except json.JSONDecodeError:
                item["details"] = {}
            events.append(item)
        self.send_json({"events": events})


def main() -> None:
    parser = argparse.ArgumentParser(description="Homelab Control Center web service")
    parser.add_argument("--config", required=True, help="Path to config.json")
    parser.add_argument("--check", action="store_true", help="Validate configuration and database, then exit")
    arguments = parser.parse_args()

    global CONFIG
    CONFIG = load_config(arguments.config)
    initialize_database()

    if arguments.check:
        print("configuration and database are valid")
        return

    server = ThreadingHTTPServer((CONFIG["bind"], int(CONFIG["port"])), Handler)
    server.daemon_threads = True
    print(
        json.dumps(
            {
                "event": "started",
                "version": VERSION,
                "bind": CONFIG["bind"],
                "port": CONFIG["port"],
            }
        ),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
