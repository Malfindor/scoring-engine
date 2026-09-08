from __future__ import annotations

import contextlib
import socket
import time
from typing import Tuple

from ..models import CheckOutcome, ServiceConfig
from .base import elapsed_ms, recv_until, register, server_name, sha256, stable_fingerprint, tls_context


def _ftp_response(sock: socket.socket) -> Tuple[int, bytes]:
    first = recv_until(sock, b"\n", 65536)
    if len(first) < 3 or not first[:3].isdigit():
        raise RuntimeError("invalid FTP response: %s" % first[:120].decode("utf-8", "replace").strip())
    code = int(first[:3])
    data = bytearray(first)
    if len(first) >= 4 and first[3:4] == b"-":
        terminator = ("%03d " % code).encode("ascii")
        def complete() -> bool:
            return any(line.startswith(terminator) for line in bytes(data).splitlines()[1:])

        while not complete():
            if len(data) >= 65536:
                raise RuntimeError("FTP response exceeded limit")
            line = recv_until(sock, b"\n", 65536 - len(data))
            if not line:
                break
            data.extend(line)
        if not complete():
            raise RuntimeError("incomplete multiline FTP response")
    return code, bytes(data)


def _ftp_command(sock: socket.socket, command: str) -> Tuple[int, bytes]:
    sock.sendall(command.encode("utf-8") + b"\r\n")
    return _ftp_response(sock)


@register("FTP")
def check_ftp(service: ServiceConfig) -> CheckOutcome:
    start = time.perf_counter()
    raw = None
    sock = None
    try:
        mode = str(service.option("tls_mode", "plain")).lower()
        raw = socket.create_connection((service.host, service.port), timeout=service.timeout)
        raw.settimeout(service.timeout)
        sock = raw
        if mode == "implicit":
            sock = tls_context(service).wrap_socket(raw, server_hostname=server_name(service))
        code, banner = _ftp_response(sock)
        if code != 220:
            raise RuntimeError("greeting returned %d" % code)
        if mode == "starttls":
            code, _ = _ftp_command(sock, "AUTH TLS")
            if code != 234:
                raise RuntimeError("AUTH TLS returned %d" % code)
            sock = tls_context(service).wrap_socket(sock, server_hostname=server_name(service))

        username = service.option("username")
        password = service.option("password")
        authenticated = False
        if username is not None:
            code, _ = _ftp_command(sock, "USER %s" % username)
            if code == 331:
                code, _ = _ftp_command(sock, "PASS %s" % ("" if password is None else password))
            if code not in {202, 230}:
                raise RuntimeError("authentication returned %d" % code)
            authenticated = True

        features = []
        code, feature_response = _ftp_command(sock, "FEAT")
        if code == 211:
            lines = feature_response.decode("utf-8", "replace").splitlines()[1:-1]
            features = sorted(line.strip().upper() for line in lines if line.strip())
        code, _ = _ftp_command(sock, "NOOP")
        if not 200 <= code < 300:
            raise RuntimeError("NOOP returned %d" % code)
        with contextlib.suppress(Exception):
            _ftp_command(sock, "QUIT")
        latency = elapsed_ms(start)
        fingerprint = stable_fingerprint("ftp", {"banner": sha256(banner), "features": features, "tls": mode})
        return CheckOutcome(True, "FTP%s ready in %d ms" % (" (authenticated)" if authenticated else "", latency), latency, fingerprint, {"features": features, "authenticated": authenticated})
    except Exception as exc:
        return CheckOutcome(False, "FTP error: %s" % exc, elapsed_ms(start), None)
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()
        if raw is not None and raw is not sock:
            with contextlib.suppress(Exception):
                raw.close()


@register("SSH")
def check_ssh(service: ServiceConfig) -> CheckOutcome:
    start = time.perf_counter()
    try:
        banner = b""
        with socket.create_connection((service.host, service.port), timeout=service.timeout) as sock:
            sock.settimeout(service.timeout)
            for _ in range(50):
                line = recv_until(sock, b"\n", 8192)
                if not line:
                    break
                if line.startswith(b"SSH-"):
                    banner = line.strip()
                    break
        if not banner.startswith((b"SSH-2.0-", b"SSH-1.99-")):
            raise RuntimeError("server did not return an SSH protocol banner")

        authenticated = False
        username = service.option("username")
        require_auth = bool(service.option("require_auth", username is not None))
        if require_auth:
            if username is None:
                raise RuntimeError("require_auth is enabled but username is missing")
            try:
                import paramiko  # type: ignore
            except ImportError as exc:
                raise RuntimeError("authenticated SSH checks require the optional 'paramiko' package") from exc
            client = paramiko.SSHClient()
            known_hosts = service.option("known_hosts")
            if known_hosts:
                client.load_host_keys(str(known_hosts))
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    service.host,
                    port=service.port,
                    username=str(username),
                    password=service.option("password"),
                    key_filename=service.option("key_file"),
                    timeout=service.timeout,
                    auth_timeout=service.timeout,
                    banner_timeout=service.timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
                authenticated = True
            finally:
                client.close()
        latency = elapsed_ms(start)
        text_banner = banner.decode("ascii", "replace")
        return CheckOutcome(True, "SSH%s ready in %d ms" % (" (authenticated)" if authenticated else "", latency), latency, "ssh:%s" % sha256(banner), {"banner": text_banner, "authenticated": authenticated})
    except Exception as exc:
        return CheckOutcome(False, "SSH error: %s" % exc, elapsed_ms(start), None)
