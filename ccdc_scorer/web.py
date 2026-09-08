from __future__ import annotations

import json
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from .engine import ScoringEngine
from .presets import PresetRegistry


STATIC_ROOT = Path(__file__).with_name("static")


class ScoreboardServer:
    def __init__(self, host: str, port: int, engine: ScoringEngine):
        self.engine = engine
        handler = self._handler_factory()
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True

    @property
    def address(self):
        return self.httpd.server_address

    def serve_forever(self) -> None:
        self.httpd.serve_forever(poll_interval=0.5)

    def start_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="scoreboard-web", daemon=True)
        thread.start()
        return thread

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def _handler_factory(self):
        engine = self.engine

        class Handler(BaseHTTPRequestHandler):
            server_version = "EKUCCDCScoreboard/2.0"

            def log_message(self, fmt, *args):
                return

            def _headers(self, content_type: str, length: int, cache: str = "no-store") -> None:
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(length))
                self.send_header("Cache-Control", cache)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")

            def _json(self, payload: Any, status: int = 200) -> None:
                body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
                self.send_response(status)
                self._headers("application/json; charset=utf-8", len(body))
                self.end_headers()
                self.wfile.write(body)

            def _static(self, relative: str) -> None:
                allowed = {"index.html", "app.css", "app.js"}
                if relative not in allowed:
                    self.send_error(404)
                    return
                path = STATIC_ROOT / relative
                try:
                    body = path.read_bytes()
                except FileNotFoundError:
                    self.send_error(404)
                    return
                content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
                self.send_response(200)
                self._headers(content_type, len(body), "no-cache")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/") or "/"
                if path == "/api/v1/health":
                    snapshot = engine.snapshot()
                    return self._json({
                        "status": "ok",
                        "engine_running": snapshot["running"],
                        "last_round": snapshot["last_round"],
                        "last_updated": snapshot["last_updated"],
                    })
                if path in {"/api/v1/summary", "/api/totals", "/api/status"}:
                    snapshot = engine.snapshot()
                    if path == "/api/totals":
                        return self._json({key: snapshot[key] for key in ("totals", "last_round", "last_updated")})
                    if path == "/api/status":
                        return self._json({"round": snapshot["last_round"], "last_updated": snapshot["last_updated"], "results": snapshot["results"]})
                    return self._json(snapshot)
                if path in {"/api/v1/rounds", "/api/rounds"}:
                    query = parse_qs(parsed.query)
                    try:
                        limit = int(query.get("limit", [str(engine.config.history_limit)])[0])
                    except ValueError:
                        return self._json({"error": "limit must be an integer"}, 400)
                    return self._json({"rounds": engine.store.recent_rounds(limit)})
                if path == "/api/v1/matrix/status":
                    return self._json(engine.status_matrix())
                if path == "/api/v1/matrix/uptime":
                    query = parse_qs(parsed.query)
                    try:
                        rounds = int(query.get("rounds", ["0"])[0])
                    except ValueError:
                        return self._json({"error": "rounds must be an integer"}, 400)
                    if rounds < 0:
                        return self._json({"error": "rounds cannot be negative"}, 400)
                    return self._json(engine.uptime_matrix(rounds))
                if path == "/api/v1/presets":
                    registry = PresetRegistry(engine.config.custom_presets)
                    return self._json({"presets": registry.public_catalog()})
                if path == "/":
                    return self._static("index.html")
                if path in {"/app.css", "/app.js"}:
                    return self._static(path[1:])
                self.send_error(404)

        return Handler
