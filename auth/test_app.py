import os
import unittest
from unittest.mock import patch

from app import app


class AuthSmokeTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health(self):
        response = self.client.get("/keyring/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})

    def test_auth_accepts_configured_credential(self):
        with patch.dict(os.environ, {"KEYRING_CREDENTIAL": "owner@example.com:correct-horse"}):
            response = self.client.post(
                "/keyring/api/auth",
                json={"id": "owner@example.com", "password": "correct-horse"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"ok": True})

    def test_auth_rejects_invalid_credential(self):
        with patch.dict(os.environ, {"KEYRING_CREDENTIAL": "owner@example.com:correct-horse"}):
            response = self.client.post(
                "/keyring/api/auth",
                json={"id": "owner@example.com", "password": "wrong"},
            )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json(), {"error": "Invalid credentials"})

    def test_auth_reports_missing_server_credential(self):
        with patch.dict(os.environ, {}, clear=True):
            response = self.client.post(
                "/keyring/api/auth",
                json={"id": "owner@example.com", "password": "correct-horse"},
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json(), {"error": "Server misconfigured"})


if __name__ == "__main__":
    unittest.main()
