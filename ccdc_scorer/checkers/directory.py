from __future__ import annotations

import contextlib
import socket
import time
from typing import Tuple

from ..models import CheckOutcome, ServiceConfig
from .base import elapsed_ms, recv_exact, register, server_name, stable_fingerprint, tls_context


def _length(value: int) -> bytes:
    if value < 128:
        return bytes([value])
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def _integer(value: int) -> bytes:
    if value == 0:
        encoded = b"\x00"
    else:
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
    return _tlv(0x02, encoded)


def _message(message_id: int, operation: bytes) -> bytes:
    return _tlv(0x30, _integer(message_id) + operation)


def _bind_request(message_id: int, bind_dn: str, password: str) -> bytes:
    content = _integer(3) + _tlv(0x04, bind_dn.encode("utf-8")) + _tlv(0x80, password.encode("utf-8"))
    return _message(message_id, _tlv(0x60, content))


def _starttls_request(message_id: int) -> bytes:
    oid = b"1.3.6.1.4.1.1466.20037"
    return _message(message_id, _tlv(0x77, _tlv(0x80, oid)))


def _read_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated BER length")
    first = data[offset]
    offset += 1
    if first < 128:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise ValueError("invalid BER length")
    return int.from_bytes(data[offset:offset + count], "big"), offset + count


def _read_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("truncated BER value")
    tag = data[offset]
    size, value_offset = _read_length(data, offset + 1)
    end = value_offset + size
    if end > len(data):
        raise ValueError("truncated BER payload")
    return tag, data[value_offset:end], end


def _recv_ldap(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 2)
    first_length = header[1]
    if first_length < 128:
        return header + recv_exact(sock, first_length)
    count = first_length & 0x7F
    length_bytes = recv_exact(sock, count)
    size = int.from_bytes(length_bytes, "big")
    return header + length_bytes + recv_exact(sock, size)


def _result(response: bytes, expected_tag: int) -> Tuple[int, str]:
    tag, sequence, _ = _read_tlv(response)
    if tag != 0x30:
        raise ValueError("LDAP response is not a sequence")
    _, _, offset = _read_tlv(sequence, 0)  # message ID
    operation_tag, operation, _ = _read_tlv(sequence, offset)
    if operation_tag != expected_tag:
        raise ValueError("unexpected LDAP response tag 0x%02x" % operation_tag)
    result_tag, result_value, cursor = _read_tlv(operation, 0)
    if result_tag != 0x0A:
        raise ValueError("LDAP response omitted result code")
    result_code = int.from_bytes(result_value, "big")
    _, _, cursor = _read_tlv(operation, cursor)  # matched DN
    _, diagnostic, _ = _read_tlv(operation, cursor)
    return result_code, diagnostic.decode("utf-8", "replace")


@register("LDAP")
def check_ldap(service: ServiceConfig) -> CheckOutcome:
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
        elif mode == "starttls":
            sock.sendall(_starttls_request(1))
            code, diagnostic = _result(_recv_ldap(sock), 0x78)
            if code != 0:
                raise RuntimeError("StartTLS failed with result %d: %s" % (code, diagnostic))
            sock = tls_context(service).wrap_socket(sock, server_hostname=server_name(service))

        bind_dn = str(service.option("bind_dn", service.option("username", "")) or "")
        password = str(service.option("password", "") or "")
        message_id = 2 if mode == "starttls" else 1
        sock.sendall(_bind_request(message_id, bind_dn, password))
        code, diagnostic = _result(_recv_ldap(sock), 0x61)
        latency = elapsed_ms(start)
        fingerprint = stable_fingerprint("ldap", {"result": code, "tls": mode})
        if code != 0:
            return CheckOutcome(False, "LDAP bind failed with result %d%s" % (code, ": " + diagnostic if diagnostic else ""), latency, fingerprint, {"result_code": code})
        return CheckOutcome(True, "LDAP%s bind succeeded in %d ms" % (" anonymous" if not bind_dn else "", latency), latency, fingerprint, {"result_code": code})
    except Exception as exc:
        return CheckOutcome(False, "LDAP error: %s" % exc, elapsed_ms(start), None)
    finally:
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()
        if raw is not None and raw is not sock:
            with contextlib.suppress(Exception):
                raw.close()
