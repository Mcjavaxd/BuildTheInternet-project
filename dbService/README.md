# acm-db

`acm-db` is the persistent user-record storage service for the Build the Internet
microservices. It stores usernames and password hashes supplied by `acm-server`;
it does not hash or otherwise transform passwords.

## Requirements and installation

Python 3.9 or newer is required. From this directory, create a virtual
environment and install the service dependencies:

```sh
python -m venv .venv
```

Activate it (`.venv\Scripts\Activate.ps1` in PowerShell, or
`source .venv/bin/activate` on Linux/macOS), then run:

```sh
python -m pip install -r requirements.txt
```

## Configuration and startup

The service uses SQLite and initializes the `users` table automatically when it
starts. The database file defaults to `users.db` in this directory. Configure
the location and listener with these environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `ACM_DB_DATABASE` | `users.db` in this directory | SQLite database file path |
| `ACM_DB_HOST` | `127.0.0.1` | Interface for the HTTP server |
| `ACM_DB_PORT` | `8001` | HTTP server port |

Copy `.env.example` as a reference and set these variables in your shell or
deployment environment; the service does not load `.env` files automatically.
Start the service with:

```sh
python app.py
```

The application listens at `http://127.0.0.1:8001` by default. For access from
other containers or machines, set `ACM_DB_HOST` to the appropriate interface.

## API

All API request and response bodies use JSON.

### `POST /db/users`

Create a user. Both fields are required strings; usernames containing only
whitespace are rejected. The supplied password hash is stored unchanged.

```sh
curl -X POST http://127.0.0.1:8001/db/users \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password_hash":"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}'
```

A successful request returns `201`:

```json
{"status":"ok","user_id":1}
```

A duplicate username returns `400`:

```json
{"error":"Username already exists"}
```

### `GET /db/users/{username}`

Retrieve the stored record by username:

```sh
curl http://127.0.0.1:8001/db/users/alice
```

A successful request returns `200`:

```json
{
  "user_id": 1,
  "username": "alice",
  "password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
}
```

An unknown username returns `404`:

```json
{"error":"User not found"}
```

Invalid or malformed creation requests return `400` with a JSON `error`
message. Unexpected server failures return a generic JSON `500` response; the
service does not return database details to clients.

## Tests

Run the automated API and persistence tests from this directory:

```sh
python -m unittest discover -s tests -v
```
