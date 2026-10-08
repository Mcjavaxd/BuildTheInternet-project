import tempfile
import unittest
from pathlib import Path

from app import create_app


class UserApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temporary_directory.name) / "users.db")
        self.app = create_app(
            {"TESTING": True, "DATABASE": self.database_path}
        )
        self.client = self.app.test_client()
        self.user = {
            "username": "alice",
            "password_hash": (
                "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
            ),
        }

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_creates_user(self):
        response = self.client.post("/db/users", json=self.user)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json(), {"status": "ok", "user_id": 1})

    def test_rejects_duplicate_username(self):
        self.client.post("/db/users", json=self.user)

        response = self.client.post("/db/users", json=self.user)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(), {"error": "Username already exists"}
        )

    def test_fetches_existing_user(self):
        self.client.post("/db/users", json=self.user)

        response = self.client.get("/db/users/alice")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "user_id": 1,
                "username": "alice",
                "password_hash": self.user["password_hash"],
            },
        )

    def test_returns_not_found_for_unknown_user(self):
        response = self.client.get("/db/users/missing")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json(), {"error": "User not found"})

    def test_rejects_missing_username(self):
        response = self.client.post(
            "/db/users", json={"password_hash": self.user["password_hash"]}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"error": "username is required"})

    def test_rejects_missing_password_hash(self):
        response = self.client.post("/db/users", json={"username": "alice"})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(), {"error": "password_hash is required"}
        )

    def test_rejects_empty_password_hash(self):
        response = self.client.post(
            "/db/users", json={"username": "alice", "password_hash": "   "}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(), {"error": "password_hash must not be empty"}
        )

    def test_rejects_malformed_json(self):
        response = self.client.post(
            "/db/users",
            data='{"username":',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(), {"error": "Invalid JSON request body"}
        )

    def test_rejects_invalid_types_and_empty_username(self):
        invalid_requests = (
            {"username": 42, "password_hash": "hash"},
            {"username": "alice", "password_hash": 42},
            {"username": "  ", "password_hash": "hash"},
        )

        for payload in invalid_requests:
            with self.subTest(payload=payload):
                response = self.client.post("/db/users", json=payload)
                self.assertEqual(response.status_code, 400)
                self.assertIsInstance(response.get_json()["error"], str)

    def test_rejects_non_object_json(self):
        response = self.client.post("/db/users", json=["alice"])

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(),
            {"error": "Request body must be a JSON object"},
        )

    def test_user_persists_when_app_is_recreated(self):
        created = self.client.post("/db/users", json=self.user)
        restarted_app = create_app(
            {"TESTING": True, "DATABASE": self.database_path}
        )

        response = restarted_app.test_client().get("/db/users/alice")

        self.assertEqual(created.status_code, 201)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["username"], "alice")
        self.assertEqual(
            response.get_json()["password_hash"], self.user["password_hash"]
        )


if __name__ == "__main__":
    unittest.main()
