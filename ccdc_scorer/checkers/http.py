from __future__ import annotations

import http.client
import re
import socket
import time
from typing import Any, List, Tuple

from ..models import CheckOutcome, ServiceConfig
from .base import elapsed_ms, register, server_name, sha256, stable_fingerprint, tls_context


DEFAULT_DYNAMIC_PATTERNS = [
    r"splunkweb_csrf_token\s*=\s*['\"][^'\"]+['\"]",
    r"csrf[_-]?token\s*[:=]\s*['\"][^'\"]+['\"]",
    r"document\.cookie\s*=\s*['\"][^'\"]+['\"]",
    r"\b(JSESSIONID|sessionid|sessid|_session_id)\s*=\s*[^;\"'\s]+",
]


def _status_expected(status: int, expected: Any) -> bool:
    if expected is None:
        return 200 <= status < 400
    if isinstance(expected, int):
        return status == expected
    if isinstance(expected, (list, tuple)):
        values = [int(value) for value in expected]
        if len(values) == 2 and values[0] <= values[1]:
            return values[0] <= status <= values[1]
        return status in values
    return status == int(expected)


def _selected_body(service: ServiceConfig, body: bytes) -> bytes:
    text = body.decode("utf-8", "replace")
    patterns = service.option("ignore_patterns")
    if patterns is None and service.option("ignore_cookies", False):
        patterns = service.option("cookie_body_patterns", DEFAULT_DYNAMIC_PATTERNS)
    for pattern in patterns or []:
        text = re.sub(str(pattern), "DYNAMIC_VALUE", text, flags=re.IGNORECASE | re.DOTALL)
    body_regex = service.option("body_regex")
    if body_regex:
        matches = re.findall(str(body_regex), text, flags=re.IGNORECASE | re.DOTALL)
        normalized: List[str] = []
        for match in matches:
            if isinstance(match, tuple):
                normalized.append("|".join(str(part) for part in match))
            else:
                normalized.append(str(match))
        text = "|".join(normalized)
    return text.encode("utf-8")


def _fingerprint(service: ServiceConfig, status: int, content_type: str, body: bytes) -> str:
    mode = str(service.option("fingerprint_mode", "status_ctype")).lower()
    if mode == "status_only":
        return "http:status=%d" % status
    if mode == "status_ctype":
        return "http:status=%d|ctype=%s" % (status, content_type)
    selected = _selected_body(service, body)
    return "http:status=%d|ctype=%s|body=%s" % (status, content_type, sha256(selected))


def _request(service: ServiceConfig, use_tls: bool) -> Tuple[int, str, bytes]:
    method = str(service.option("method", "GET")).upper()
    path = str(service.option("path", "/"))
    if not path.startswith("/"):
        path = "/" + path
    host_header = str(service.option("host_header") or server_name(service))
    headers = {
        "Host": host_header,
        "User-Agent": "eku-ccdc-scorer/2.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    custom_headers = service.option("headers", {})
    if isinstance(custom_headers, dict):
        headers.update({str(key): str(value) for key, value in custom_headers.items()})
    request_body = service.option("request_body")
    encoded_body = None if request_body is None else str(request_body).encode("utf-8")
    request_lines = ["%s %s HTTP/1.1" % (method, path)]
    request_lines.extend("%s: %s" % item for item in headers.items())
    if encoded_body is not None:
        request_lines.append("Content-Length: %d" % len(encoded_body))
    packet = ("\r\n".join(request_lines) + "\r\n\r\n").encode("iso-8859-1") + (encoded_body or b"")

    raw = socket.create_connection((service.host, service.port), timeout=service.timeout)
    sock: socket.socket = raw
    try:
        if use_tls:
            sock = tls_context(service).wrap_socket(raw, server_hostname=server_name(service))
        sock.settimeout(service.timeout)
        sock.sendall(packet)
        response = http.client.HTTPResponse(sock, method=method)
        response.begin()
        max_body = int(service.option("max_body_bytes", 1024 * 1024))
        body = response.read(max_body)
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        return response.status, content_type, body
    finally:
        try:
            sock.close()
        finally:
            if sock is not raw:
                raw.close()


@register("HTTP", "HTTPS")
def check_http(service: ServiceConfig) -> CheckOutcome:
    start = time.perf_counter()
    try:
        status, content_type, body = _request(service, service.type == "HTTPS")
        latency = elapsed_ms(start)
        problems = []
        if not _status_expected(status, service.option("expected_status")):
            problems.append("unexpected HTTP status %d" % status)
        expected_content = service.option("expected_content")
        decoded = body.decode("utf-8", "replace")
        if expected_content is not None and str(expected_content) not in decoded:
            problems.append("required content was not found")
        expected_regex = service.option("expected_regex")
        if expected_regex and not re.search(str(expected_regex), decoded, flags=re.IGNORECASE | re.DOTALL):
            problems.append("required content pattern was not found")
        fingerprint = _fingerprint(service, status, content_type, body)
        if problems:
            return CheckOutcome(False, "; ".join(problems), latency, fingerprint, {"status": status, "content_type": content_type})
        return CheckOutcome(True, "HTTP %d in %d ms" % (status, latency), latency, fingerprint, {"status": status, "content_type": content_type})
    except Exception as exc:
        return CheckOutcome(False, "%s error: %s" % (service.type, exc), elapsed_ms(start), None)
