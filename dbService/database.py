import sqlite3
from contextlib import closing
from pathlib import Path


def initialize_database(database_path):
    if database_path != ":memory:":
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(database_path, timeout=5)) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        connection.commit()


def create_user(database_path, username, password_hash):
    with closing(sqlite3.connect(database_path, timeout=5)) as connection:
        cursor = connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        connection.commit()
        return cursor.lastrowid


def get_user(database_path, username):
    with closing(sqlite3.connect(database_path, timeout=5)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT user_id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    return dict(row) if row is not None else None
