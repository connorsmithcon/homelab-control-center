#!/usr/bin/env python3
from __future__ import annotations

import http.client
import importlib.util
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load " + str(path))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


server_module = load_module("hcc_server", ROOT / "src" / "server.py")
action_module = load_module("hcc_actiond", ROOT / "src" / "actiond.py")


class PasswordTests(unittest.TestCase):
    def test_scrypt_round_trip(self):
        record = server_module.hash_password("correct horse battery staple")
        self.assertTrue(record.startswith("scrypt$32768$8$1$"))
        self.assertTrue(server_module.verify_password("correct horse battery staple", record))
        self.assertFalse(server_module.verify_password("wrong password", record))
        self.assertNotIn("correct horse battery staple", record)

    def test_identifier_validation(self):
        self.assertEqual(server_module.validate_username("admin-user"), "admin-user")
        self.assertEqual(server_module.validate_unit("ssh@worker.service"), "ssh@worker.service")
        with self.assertRaises(server_module.ApiError):
            server_module.validate_unit("ssh.service; reboot")
        with self.assertRaises(server_module.ApiError):
            server_module.validate_username("../admin")


class BrokerValidationTests(unittest.TestCase):
    def test_service_allowlist(self):
        action, command, timeout, label = action_module.validate_request(
            {"action": "service", "operation": "restart", "unit": "ssh.service"}
        )
        self.assertEqual(action, "service")
        self.assertEqual(command, ["/usr/bin/systemctl", "restart", "ssh.service"])
        self.assertGreater(timeout, 0)
        self.assertEqual(label, "restart:ssh.service")

    def test_broker_rejects_shell_fragments_and_unknown_fields(self):
        invalid = [
            {"action": "service", "operation": "restart", "unit": "ssh.service;id"},
            {"action": "service", "operation": "reload", "unit": "ssh.service"},
            {"action": "updates-apply", "command": "id"},
            {"action": "shell", "command": "id"},
        ]
        for request in invalid:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    action_module.validate_request(request)


class AuthenticationFlowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        token_file = root / "bootstrap-token"
        token_file.write_text("test-bootstrap-token\n", encoding="utf-8")
        ssh_directory = root / ".ssh"
        ssh_directory.mkdir()
        (ssh_directory / "id_ed25519.pub").write_text("ssh-ed25519 test public-key\n", encoding="utf-8")

        config = dict(server_module.DEFAULT_CONFIG)
        config.update(
            {
                "bind": "127.0.0.1",
                "port": 0,
                "database": str(root / "test.db"),
                "bootstrap_token_file": str(token_file),
                "ssh_directory": str(ssh_directory),
                "action_socket": str(root / "actions.sock"),
            }
        )
        server_module.CONFIG = config
        server_module._login_attempts.clear()
        server_module.initialize_database()

        self.httpd = server_module.ThreadingHTTPServer(("127.0.0.1", 0), server_module.Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method: str, path: str, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        request_headers = dict(headers or {})
        encoded = None
        if body is not None:
            encoded = json.dumps(body)
            request_headers["Content-Type"] = "application/json"
        connection.request(method, path, body=encoded, headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        payload = json.loads(raw) if raw else None
        all_headers = response.getheaders()
        connection.close()
        return response.status, payload, all_headers

    def test_setup_session_csrf_and_hashed_storage(self):
        status, payload, headers = self.request(
            "POST",
            "/api/setup",
            {
                "username": "admin",
                "password": "a secure test password",
                "bootstrap_token": "test-bootstrap-token",
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(payload["username"], "admin")

        cookie_values = [value.split(";", 1)[0] for name, value in headers if name.lower() == "set-cookie"]
        cookie_header = "; ".join(cookie_values)
        csrf = next(value.split("=", 1)[1] for value in cookie_values if value.startswith("hcc_csrf="))
        session = next(value.split("=", 1)[1] for value in cookie_values if value.startswith("hcc_session="))

        status, payload, _ = self.request("GET", "/api/me", headers={"Cookie": cookie_header})
        self.assertEqual(status, 200)
        self.assertEqual(payload["role"], "admin")

        status, payload, _ = self.request(
            "POST",
            "/api/password",
            {"current_password": "a secure test password", "new_password": "another secure password"},
            headers={"Cookie": cookie_header},
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "CSRF validation failed.")

        status, payload, _ = self.request(
            "POST",
            "/api/password",
            {"current_password": "a secure test password", "new_password": "another secure password"},
            headers={"Cookie": cookie_header, "X-CSRF-Token": csrf},
        )
        self.assertEqual(status, 200)

        database = server_module.CONFIG["database"]
        with sqlite3.connect(database) as connection:
            stored_session, stored_csrf = connection.execute(
                "SELECT token_hash, csrf_hash FROM sessions LIMIT 1"
            ).fetchone()
            password_record = connection.execute("SELECT password_hash FROM users LIMIT 1").fetchone()[0]
        self.assertNotEqual(stored_session, session)
        self.assertNotEqual(stored_csrf, csrf)
        self.assertNotIn("another secure password", password_record)
        self.assertFalse(Path(server_module.CONFIG["bootstrap_token_file"]).exists())


if __name__ == "__main__":
    unittest.main()
