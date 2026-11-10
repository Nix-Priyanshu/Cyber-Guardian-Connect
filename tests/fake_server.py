"""
A tiny stand-in for source_app/main.py built on the standard library.

It serves the same routes with the same API-key rule and the same data logic
(source_app/data.py), so the REST connector can be tested over real HTTP
without needing FastAPI installed.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from source_app.data import IncidentStore

API_KEY = "test-key"


def make_handler(store):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):   # keep test output quiet
            pass

        def _send(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self):
            return self.headers.get("X-API-Key") == API_KEY

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"status": "ok"})
            if not self._authorized():
                return self._send(401, {"detail": "Invalid or missing API key"})
            if self.path == "/api/v1/incidents":
                items = store.list_summaries()
                return self._send(200, {"count": len(items), "incidents": items})
            if self.path.startswith("/api/v1/incidents/"):
                incident = store.get(self.path.rsplit("/", 1)[-1])
                if incident is None:
                    return self._send(404, {"detail": "Incident not found"})
                return self._send(200, incident)
            return self._send(404, {"detail": "Not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            if not self._authorized():
                return self._send(401, {"detail": "Invalid or missing API key"})
            if self.path == "/api/v1/simulate":
                return self._send(200, store.simulate_new())
            if self.path == "/api/v1/actions":
                try:
                    data = json.loads(body or b"{}")
                    record = store.record_action(data.get("incident_id", ""), data.get("action", ""),
                                                 data.get("target", ""), data.get("requested_by", "cyberguardian"))
                except KeyError:
                    return self._send(404, {"detail": "Incident not found"})
                except ValueError as exc:
                    return self._send(400, {"detail": str(exc)})
                return self._send(200, record)
            return self._send(404, {"detail": "Not found"})

    return Handler


class FakeServer:
    def __init__(self):
        self.store = IncidentStore()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.store))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
