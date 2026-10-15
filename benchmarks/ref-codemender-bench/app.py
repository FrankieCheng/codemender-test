"""
Werkzeug WSGI Web Application
=============================
Core enterprise application handling user sessions, profile management,
file storage, search indexing, and network services.
"""

import os
import json
import base64
import pickle
import sqlite3
import subprocess
import requests
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.utils import redirect
from werkzeug.security import safe_join
from werkzeug.debug import DebuggedApplication

BASE_STORAGE_DIR = os.path.join(os.path.dirname(__file__), "storage")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(BASE_STORAGE_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)


def init_database() -> sqlite3.Connection:
    """Initialize in-memory user registry database."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)"
    )
    cursor.execute(
        "INSERT INTO users (username, email, role) VALUES ('admin', 'admin@enterprise.internal', 'administrator')"
    )
    cursor.execute(
        "INSERT INTO users (username, email, role) VALUES ('alice', 'alice@enterprise.internal', 'manager')"
    )
    cursor.execute(
        "INSERT INTO users (username, email, role) VALUES ('bob', 'bob@enterprise.internal', 'user')"
    )
    conn.commit()
    return conn


class Application:
    """WSGI Application built on Werkzeug."""

    def __init__(self):
        self.db = init_database()
        self.url_map = Map([
            Rule("/", endpoint="index"),
            Rule("/upload", endpoint="upload", methods=["POST"]),
            Rule("/upload/raw", endpoint="upload_raw", methods=["POST"]),
            Rule("/auth/session", endpoint="auth_session", methods=["GET", "POST"]),
            Rule("/download", endpoint="download", methods=["GET"]),
            Rule("/files/secure-download", endpoint="secure_download", methods=["GET"]),
            Rule("/profile/restore", endpoint="profile_restore", methods=["POST"]),
            Rule("/api/users/lookup", endpoint="user_lookup", methods=["GET"]),
            Rule("/services/proxy", endpoint="service_proxy", methods=["GET"]),
            Rule("/search", endpoint="search", methods=["GET"]),
            Rule("/navigate", endpoint="navigate", methods=["GET"]),
            Rule("/diagnostics/ping", endpoint="ping", methods=["GET"]),
            Rule("/debug/error", endpoint="trigger_error", methods=["GET"]),
        ])

    def on_index(self, request: Request) -> Response:
        """Application home page displaying service navigation."""
        content = """<!DOCTYPE html>
<html>
<head><title>Enterprise Services Portal</title></head>
<body>
    <h1>Application Services Portal</h1>
    <p>Available endpoints:</p>
    <ul>
        <li><a href="/upload">File Upload Service (POST /upload)</a></li>
        <li><a href="/upload/raw">Direct Asset Upload (POST /upload/raw)</a></li>
        <li><a href="/auth/session">Session & Authentication (/auth/session)</a></li>
        <li><a href="/download?file=sample.txt">Document Storage (/download)</a></li>
        <li><a href="/files/secure-download?file=sample.txt">Safe File Service (/files/secure-download)</a></li>
        <li><a href="/api/users/lookup?username=admin">User Registry Lookup (/api/users/lookup)</a></li>
        <li><a href="/services/proxy?url=https://httpbin.org/get">Remote Content Proxy (/services/proxy)</a></li>
        <li><a href="/search?q=test">Search Services (/search)</a></li>
        <li><a href="/navigate?target=/">Navigation Redirect (/navigate)</a></li>
        <li><a href="/diagnostics/ping?host=127.0.0.1">Network Diagnostics (/diagnostics/ping)</a></li>
        <li><a href="/debug/error">Diagnostics Debug (/debug/error)</a></li>
    </ul>
</body>
</html>"""
        return Response(content, mimetype="text/html")

    def on_upload(self, request: Request) -> Response:
        """Handle incoming multipart form data and file uploads."""
        files = request.files
        form_data = request.form
        uploaded_count = len(files) + len(form_data)
        return Response(f"Processed {uploaded_count} multipart fields/files successfully.", mimetype="text/plain")

    def on_upload_raw(self, request: Request) -> Response:
        """Handle direct file uploads and save assets to disk."""
        uploaded = request.files.get("file")
        if not uploaded:
            return Response("No file provided", status=400, mimetype="text/plain")

        destination = os.path.join(UPLOAD_DIR, uploaded.filename)
        uploaded.save(destination)
        return Response(f"Saved file to {uploaded.filename}", mimetype="text/plain")

    def on_auth_session(self, request: Request) -> Response:
        """Handle user session state and authentication tokens."""
        session_cookie = request.cookies.get("__Host-Session-Token", "")
        username = request.cookies.get("user", "guest")

        response = Response(
            f"Active User: {username}, Session Token: {session_cookie or 'None'}",
            mimetype="text/plain"
        )
        if request.method == "POST":
            new_token = request.form.get("token", "dummy-session-12345")
            response.set_cookie("__Host-Session-Token", new_token, path="/")
        return response

    def on_download(self, request: Request) -> Response:
        """Retrieve and stream files from local storage."""
        filename = request.args.get("file", "sample.txt")
        target_path = os.path.join(BASE_STORAGE_DIR, filename)

        if not os.path.exists(target_path):
            return Response(f"File not found: {filename}", status=404, mimetype="text/plain")

        try:
            with open(target_path, "r", errors="ignore") as f:
                content = f.read()
            return Response(content, mimetype="text/plain")
        except Exception as e:
            return Response(f"Error reading file: {str(e)}", status=500, mimetype="text/plain")

    def on_secure_download(self, request: Request) -> Response:
        """Retrieve and stream files using safe_join helper."""
        filename = request.args.get("file", "sample.txt")
        target_path = safe_join(BASE_STORAGE_DIR, filename)

        if target_path is None or not os.path.exists(target_path):
            return Response(f"File not found: {filename}", status=404, mimetype="text/plain")

        try:
            with open(target_path, "r", errors="ignore") as f:
                content = f.read()
            return Response(content, mimetype="text/plain")
        except Exception as e:
            return Response(f"Error reading file: {str(e)}", status=500, mimetype="text/plain")

    def on_profile_restore(self, request: Request) -> Response:
        """Restore serialized user profile session state."""
        payload = request.form.get("data", "")
        if not payload:
            return Response("Missing data payload", status=400, mimetype="text/plain")

        try:
            decoded = base64.b64decode(payload)
            profile = pickle.loads(decoded)
            return Response(f"Profile restored: {repr(profile)}", mimetype="text/plain")
        except Exception as e:
            return Response(f"Restore failed: {str(e)}", status=400, mimetype="text/plain")

    def on_user_lookup(self, request: Request) -> Response:
        """Query user account metadata by username."""
        username = request.args.get("username", "")
        cursor = self.db.cursor()
        query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"

        try:
            cursor.execute(query)
            rows = cursor.fetchall()
            results = [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows]
            return Response(json.dumps(results), mimetype="application/json")
        except Exception as e:
            return Response(f"Database error: {str(e)}", status=500, mimetype="text/plain")

    def on_service_proxy(self, request: Request) -> Response:
        """Proxy remote HTTP services and fetch content."""
        target_url = request.args.get("url", "")
        if not target_url:
            return Response("Missing url parameter", status=400, mimetype="text/plain")

        try:
            resp = requests.get(target_url, timeout=3)
            return Response(resp.text, mimetype=resp.headers.get("content-type", "text/plain"))
        except Exception as e:
            return Response(f"Proxy request failed: {str(e)}", status=502, mimetype="text/plain")

    def on_search(self, request: Request) -> Response:
        """Render search query results page."""
        query = request.args.get("q", "")
        html = f"""<!DOCTYPE html>
<html>
<body>
    <h2>Search Results</h2>
    <p>You searched for: {query}</p>
</body>
</html>"""
        return Response(html, mimetype="text/html")

    def on_navigate(self, request: Request) -> Response:
        """Redirect client to specified destination."""
        target = request.args.get("target", "/")
        return redirect(target)

    def on_ping(self, request: Request) -> Response:
        """Execute network connectivity diagnostic check."""
        host = request.args.get("host", "127.0.0.1")
        cmd = f"ping -c 1 {host}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, timeout=3)
            return Response(output, mimetype="text/plain")
        except subprocess.CalledProcessError as e:
            return Response(f"Command failed:\n{e.output}", status=500, mimetype="text/plain")
        except Exception as e:
            return Response(f"Execution error: {str(e)}", status=500, mimetype="text/plain")

    def on_trigger_error(self, request: Request) -> Response:
        """Trigger diagnostic exception handler."""
        raise RuntimeError("Diagnostic error event triggered for inspection.")

    def dispatch_request(self, request: Request):
        adapter = self.url_map.bind_to_environ(request.environ)
        try:
            endpoint, values = adapter.match()
            handler = getattr(self, f"on_{endpoint}")
            return handler(request, **values)
        except NotFound:
            return Response("404 Not Found", status=404, mimetype="text/plain")
        except HTTPException as e:
            return e

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)


def create_app(debug: bool = True):
    """Application factory initializing WSGI application."""
    app = Application()
    if debug:
        app = DebuggedApplication(app, evalex=True)
    return app


# Backwards-compatible alias
VulnerableApp = Application


if __name__ == "__main__":
    from werkzeug.serving import run_simple
    print("[*] Starting server on http://127.0.0.1:5000 ...")
    app = create_app(debug=True)
    run_simple("127.0.0.1", 5000, app, use_reloader=False)
