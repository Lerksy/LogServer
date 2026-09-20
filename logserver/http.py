from __future__ import annotations

import hmac
import json
import mimetypes
import queue
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .config import Settings
from .models import SEVERITIES_BY_URGENCY
from .search import SearchSyntaxError
from .service import LogService
from .validation import ValidationError, log_input_from_json


STATIC_DIR = Path(__file__).with_name("static")
STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/styles.css": "styles.css",
}


class LogHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], service: LogService, settings: Settings):
        super().__init__(address, LogRequestHandler)
        self.log_service = service
        self.settings = settings


class LogRequestHandler(BaseHTTPRequestHandler):
    server: LogHTTPServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/api/health":
            self._json(HTTPStatus.OK, {"status": "ok", "logs": self.server.log_service.database.count()})
        elif parsed.path == "/api/logs":
            self._list_logs(parse_qs(parsed.query))
        elif parsed.path == "/api/stream":
            self._stream_logs()
        elif parsed.path in STATIC_FILES:
            self._static(STATIC_FILES[parsed.path])
        else:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Resource not found")

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path != "/api/logs":
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Resource not found")
            return
        if not self._authorized():
            self._error(HTTPStatus.UNAUTHORIZED, "unauthorized", "A valid ingest token is required")
            return

        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "content_type", "Content-Type must be application/json")
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "content_length", "Invalid Content-Length")
            return
        if content_length <= 0 or content_length > self.server.settings.max_body_bytes:
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_size", "Request body is empty or too large")
            return

        try:
            payload = json.loads(self.rfile.read(content_length))
            values = payload if isinstance(payload, list) else [payload]
            if not values or len(values) > 1000:
                raise ValidationError("a batch must contain between 1 and 1000 logs")
            inputs = [log_input_from_json(value, self.client_address[0]) for value in values]
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json", "Request body is not valid JSON")
            return
        except ValidationError as exc:
            self._error(HTTPStatus.UNPROCESSABLE_ENTITY, "validation", str(exc))
            return

        records = [record.to_dict() for record in self.server.log_service.ingest_many(inputs)]
        self._json(HTTPStatus.CREATED, {"items": records, "count": len(records)})

    def _list_logs(self, params: dict[str, list[str]]) -> None:
        minimum_severity = params.get("minimum_severity", ["debug"])[0].lower()
        if minimum_severity not in SEVERITIES_BY_URGENCY:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "minimum_severity",
                f"minimum_severity must be one of: {', '.join(SEVERITIES_BY_URGENCY)}",
            )
            return
        try:
            limit = int(params.get("limit", ["100"])[0])
            if limit < 1 or limit > 500:
                raise ValueError
            before_value = params.get("before_id", [None])[0]
            before_id = int(before_value) if before_value is not None else None
            if before_id is not None and before_id < 1:
                raise ValueError
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "pagination", "limit must be 1-500 and before_id must be positive")
            return
        try:
            records, has_more = self.server.log_service.database.search(
                params.get("q", [None])[0],
                limit=limit,
                before_id=before_id,
                minimum_severity=minimum_severity,
            )
        except SearchSyntaxError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "search_syntax", str(exc))
            return
        items = [record.to_dict() for record in records]
        self._json(
            HTTPStatus.OK,
            {
                "items": items,
                "has_more": has_more,
                "next_before_id": items[-1]["id"] if has_more and items else None,
            },
        )

    def _stream_logs(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            with self.server.log_service.broker.subscribe() as subscriber:
                while True:
                    try:
                        record = subscriber.get(timeout=15)
                        data = json.dumps(record.to_dict(), ensure_ascii=False, separators=(",", ":"))
                        self.wfile.write(f"event: log\ndata: {data}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            return

    def _authorized(self) -> bool:
        expected = self.server.settings.ingest_token
        if expected is None:
            return True
        authorization = self.headers.get("Authorization", "")
        supplied = authorization[7:] if authorization.startswith("Bearer ") else self.headers.get("X-API-Key", "")
        return hmac.compare_digest(supplied, expected)

    def _static(self, filename: str) -> None:
        path = STATIC_DIR / filename
        try:
            body = path.read_bytes()
        except OSError:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Resource not found")
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: HTTPStatus, code: str, message: str) -> None:
        self._json(status, {"error": {"code": code, "message": message}})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"http {self.address_string()} {fmt % args}")
