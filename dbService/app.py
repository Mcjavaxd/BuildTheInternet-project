import os
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException, BadRequest

from database import create_user, get_user, initialize_database


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=os.environ.get(
            "ACM_DB_DATABASE", str(Path(__file__).with_name("users.db"))
        ),
        HOST=os.environ.get("ACM_DB_HOST", "127.0.0.1"),
        PORT=int(os.environ.get("ACM_DB_PORT", "8001")),
    )
    if test_config:
        app.config.update(test_config)

    initialize_database(app.config["DATABASE"])

    @app.post("/db/users")
    def add_user():
        if not request.is_json:
            return jsonify(error="Content-Type must be application/json"), 400

        try:
            payload = request.get_json()
        except BadRequest:
            return jsonify(error="Invalid JSON request body"), 400

        if not isinstance(payload, dict):
            return jsonify(error="Request body must be a JSON object"), 400

        for field in ("username", "password_hash"):
            if field not in payload:
                return jsonify(error=f"{field} is required"), 400
            if not isinstance(payload[field], str):
                return jsonify(error=f"{field} must be a string"), 400

        username = payload["username"]
        password_hash = payload["password_hash"]
        if not username.strip():
            return jsonify(error="username must not be empty"), 400
        if not password_hash.strip():
            return jsonify(error="password_hash must not be empty"), 400

        try:
            user_id = create_user(
                app.config["DATABASE"], username, password_hash
            )
        except sqlite3.IntegrityError:
            return jsonify(error="Username already exists"), 400

        return jsonify(status="ok", user_id=user_id), 201

    @app.get("/db/users/<string:username>")
    def fetch_user(username):
        user = get_user(app.config["DATABASE"], username)
        if user is None:
            return jsonify(error="User not found"), 404
        return jsonify(user), 200

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
