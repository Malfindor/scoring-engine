from __future__ import annotations

import hashlib
import json
import socket
import ssl
import time
from typing import Callable, Dict, Iterable

from ..models import CheckOutcome, ServiceConfig


Checker = Callable[[ServiceConfig], CheckOutcome]
CHECKERS: Dict[str, Checker] = {}


def register(*service_types: str) -> Callable[[Checker], Checker]:
    def decorator(checker: Checker) -> Checker:
        for service_type in service_types:
            CHECKERS[service_type.upper()] = checker
        return checker
    return decorator


def get_checker(service_type: str) -> Checker | None:
    return CHECKERS.get(service_type.upper())


def supported_types() -> Iterable[str]:
    return sorted(CHECKERS)


def elapsed_ms(start: float) -> int:
    return max(0, int((time.perf_counter() - start) * 1000))


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stable_fingerprint(prefix: str, value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "%s:%s" % (prefix, sha256(encoded))


def tls_context(service: ServiceConfig) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not bool(service.option("verify_cert", True)):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    ca_file = service.option("ca_file")
    if ca_file:
        context.load_verify_locations(cafile=str(ca_file))
    return context


def server_name(service: ServiceConfig) -> str:
    return str(service.option("sni") or service.option("server_name") or service.host)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_until(sock: socket.socket, delimiter: bytes = b"\n", limit: int = 65536) -> bytes:
    data = bytearray()
    while len(data) < limit:
        chunk = sock.recv(min(1024, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if delimiter in data:
            break
    return bytes(data)
