import hashlib
import json
import os
import secrets
from urllib import error, request

from flask import Flask, jsonify, request
from werkzeug.exceptions import BadRequest, HTTPException

SESSION_STORE = {}


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _db_request(app: Flask, method: str, path: str, payload=None):
    db_url = app.config["DB_URL"].rstrip("/")
    url = f"{db_url}{path}"
    body = None
    headers = {
        "Accept": "application/json",
    }

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(url, data=body, headers=headers, method=method)

    try:
        with request.urlopen(req, timeout=5) as response:
            response_text = response.read().decode("utf-8")
            return response.status, json.loads(response_text) if response_text else {}
    except error.HTTPError as exc:
        response_text = exc.read().decode("utf-8")
        try:
            payload = json.loads(response_text) if response_text else {}
        except json.JSONDecodeError:
            payload = {"error": response_text or exc.reason}
        return exc.code, payload
    except error.URLError as exc:
        raise RuntimeError(f"Database service unavailable: {exc.reason}") from exc


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        DB_URL=os.environ.get("ACM_SERVER_DB_URL", "http://127.0.0.1:8001"),
        HOST=os.environ.get("ACM_SERVER_HOST", "127.0.0.1"),
        PORT=int(os.environ.get("ACM_SERVER_PORT", "8002")),
        SECRET_KEY=os.environ.get("ACM_SERVER_SECRET_KEY", "change-me-in-production"),
    )
    if test_config:
        app.config.update(test_config)

    @app.post("/register")
    def register_user():
        if not request.is_json:
            return jsonify(error="Content-Type must be application/json"), 400

        try:
            payload = request.get_json(force=False, silent=False)
        except BadRequest:
            return jsonify(error="Invalid JSON request body"), 400

        if not isinstance(payload, dict):
            return jsonify(error="Request body must be a JSON object"), 400

        for field in ("username", "password"):
            if field not in payload:
                return jsonify(error=f"{field} is required"), 400
            if not isinstance(payload[field], str):
                return jsonify(error=f"{field} must be a string"), 400

        username = payload["username"].strip()
        password = payload["password"]

        if not username:
            return jsonify(error="username must not be empty"), 400
        if not password.strip():
            return jsonify(error="password must not be empty"), 400

        password_hash = _hash_password(password)

        try:
            status_code, db_payload = _db_request(
                app,
                "POST",
                "/db/users",
                {"username": username, "password_hash": password_hash},
            )
        except RuntimeError as exc:
            app.logger.exception("Database service error while registering user")
            return jsonify(error=str(exc)), 503

        if status_code == 201:
            return jsonify(status="ok", message="User registered successfully"), 201

        if status_code == 400 and isinstance(db_payload, dict):
            error_message = str(db_payload.get("error", "Username already exists"))
            if "already exists" in error_message.lower():
                return jsonify(error="Username already exists"), 400

        error_message = str(db_payload.get("error", "Registration failed"))
        return jsonify(error=error_message), status_code if status_code >= 400 else 400

    @app.post("/login")
    def login_user():
        if not request.is_json:
            return jsonify(error="Content-Type must be application/json"), 400

        try:
            payload = request.get_json(force=False, silent=False)
        except BadRequest:
            return jsonify(error="Invalid JSON request body"), 400

        if not isinstance(payload, dict):
            return jsonify(error="Request body must be a JSON object"), 400

        for field in ("username", "password"):
            if field not in payload:
                return jsonify(error=f"{field} is required"), 400
            if not isinstance(payload[field], str):
                return jsonify(error=f"{field} must be a string"), 400

        username = payload["username"].strip()
        password = payload["password"]

        if not username:
            return jsonify(error="username must not be empty"), 400
        if not password.strip():
            return jsonify(error="password must not be empty"), 400

        try:
            status_code, db_payload = _db_request(app, "GET", f"/db/users/{username}")
        except RuntimeError as exc:
            app.logger.exception("Database service error while fetching user")
            return jsonify(error=str(exc)), 503

        if status_code == 404:
            return jsonify(error="Invalid username or password"), 401

        if status_code != 200:
            error_message = str(db_payload.get("error", "Invalid username or password"))
            return jsonify(error=error_message), status_code if status_code >= 400 else 401

        stored_hash = db_payload.get("password_hash")
        if not isinstance(stored_hash, str):
            return jsonify(error="Invalid username or password"), 401

        if _hash_password(password) != stored_hash:
            return jsonify(error="Invalid username or password"), 401

        session_id = secrets.token_urlsafe(32)
        SESSION_STORE[session_id] = username

        response = jsonify(status="ok", message="Login successful")
        response.set_cookie(
            "session_id",
            session_id,
            path="/",
            httponly=True,
            samesite="Lax",
        )
        return response, 200

    @app.get("/whoami")
    def whoami():
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in SESSION_STORE:
            return jsonify(error="Unauthorized - Invalid or missing session cookie"), 401

        username = SESSION_STORE[session_id]

        try:
            status_code, db_payload = _db_request(app, "GET", f"/db/users/{username}")
        except RuntimeError as exc:
            app.logger.exception("Database service error while verifying session")
            return jsonify(error=str(exc)), 503

        if status_code != 200:
            SESSION_STORE.pop(session_id, None)
            return jsonify(error="Unauthorized - Invalid or missing session cookie"), 401

        return (
            jsonify(
                status="ok",
                user_id=db_payload.get("user_id"),
                username=db_payload.get("username", username),
            ),
            200,
        )

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return jsonify(error=error.description), error.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        app.logger.exception("Unhandled request error")
        return jsonify(error="Internal server error"), 500

    return app


if __name__ == "__main__":
    from waitress import serve

    application = create_app()
    serve(application, host=application.config["HOST"], port=application.config["PORT"])
