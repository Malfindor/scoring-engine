from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
from typing import Dict, List, Tuple

from ..models import CheckOutcome, ServiceConfig
from .base import elapsed_ms, recv_exact, register, stable_fingerprint


QUERY_TYPES: Dict[str, int] = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}


def _encode_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    encoded = bytearray()
    for label in labels:
        value = label.encode("idna")
        if not value or len(value) > 63:
            raise ValueError("Invalid DNS label in %r" % name)
        encoded.append(len(value))
        encoded.extend(value)
    encoded.append(0)
    return bytes(encoded)


def _decode_name(packet: bytes, offset: int, visited: set[int] | None = None) -> Tuple[str, int]:
    labels: List[str] = []
    next_offset = offset
    jumped = False
    visited = visited or set()
    while True:
        if offset >= len(packet):
            raise ValueError("DNS name exceeds packet")
        if offset in visited:
            raise ValueError("DNS compression pointer loop")
        visited.add(offset)
        length = packet[offset]
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            return ".".join(labels), next_offset
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                next_offset = offset + 2
                jumped = True
            pointed, _ = _decode_name(packet, pointer, visited)
            labels.extend(pointed.split(".") if pointed else [])
            return ".".join(labels), next_offset
        if length & 0xC0:
            raise ValueError("Unsupported DNS label encoding")
        offset += 1
        if offset + length > len(packet):
            raise ValueError("Truncated DNS label")
        labels.append(packet[offset:offset + length].decode("idna"))
        offset += length
        if not jumped:
            next_offset = offset


def _parse_answer(packet: bytes, offset: int) -> Tuple[str, int]:
    _, offset = _decode_name(packet, offset)
    if offset + 10 > len(packet):
        raise ValueError("Truncated DNS resource record")
    record_type, record_class, _ttl, data_length = struct.unpack("!HHIH", packet[offset:offset + 10])
    data_offset = offset + 10
    next_offset = data_offset + data_length
    if next_offset > len(packet):
        raise ValueError("Truncated DNS record data")
    data = packet[data_offset:next_offset]
    if record_class != 1:
        return "CLASS%d:%s" % (record_class, data.hex()), next_offset
    if record_type == 1 and len(data) == 4:
        value = str(ipaddress.IPv4Address(data))
    elif record_type == 28 and len(data) == 16:
        value = str(ipaddress.IPv6Address(data))
    elif record_type in {2, 5, 12}:
        value, _ = _decode_name(packet, data_offset)
    elif record_type == 15 and len(data) >= 3:
        preference = struct.unpack("!H", data[:2])[0]
        exchange, _ = _decode_name(packet, data_offset + 2)
        value = "%d %s" % (preference, exchange)
    elif record_type == 16:
        parts, cursor = [], 0
        while cursor < len(data):
            size = data[cursor]
            cursor += 1
            parts.append(data[cursor:cursor + size].decode("utf-8", "replace"))
            cursor += size
        value = "".join(parts)
    elif record_type == 33 and len(data) >= 7:
        priority, weight, port = struct.unpack("!HHH", data[:6])
        target, _ = _decode_name(packet, data_offset + 6)
        value = "%d %d %d %s" % (priority, weight, port, target)
    else:
        value = data.hex()
    type_name = next((name for name, number in QUERY_TYPES.items() if number == record_type), "TYPE%d" % record_type)
    return "%s:%s" % (type_name, value.rstrip(".")), next_offset


def _parse_response(packet: bytes, transaction_id: int) -> Tuple[int, bool, List[str]]:
    if len(packet) < 12:
        raise ValueError("Truncated DNS header")
    response_id, flags, question_count, answer_count, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if response_id != transaction_id:
        raise ValueError("DNS transaction ID mismatch")
    if not flags & 0x8000:
        raise ValueError("DNS packet is not a response")
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)
    offset = 12
    for _ in range(question_count):
        _, offset = _decode_name(packet, offset)
        offset += 4
        if offset > len(packet):
            raise ValueError("Truncated DNS question")
    answers = []
    for _ in range(answer_count):
        answer, offset = _parse_answer(packet, offset)
        answers.append(answer)
    return rcode, truncated, answers


def _query(service: ServiceConfig, payload: bytes) -> bytes:
    family = socket.AF_INET6 if ":" in service.host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(service.timeout)
        sock.sendto(payload, (service.host, service.port))
        response, _ = sock.recvfrom(65535)
    return response


def _query_tcp(service: ServiceConfig, payload: bytes) -> bytes:
    with socket.create_connection((service.host, service.port), timeout=service.timeout) as sock:
        sock.settimeout(service.timeout)
        sock.sendall(struct.pack("!H", len(payload)) + payload)
        size = struct.unpack("!H", recv_exact(sock, 2))[0]
        return recv_exact(sock, size)


@register("DNS")
def check_dns(service: ServiceConfig) -> CheckOutcome:
    start = time.perf_counter()
    try:
        query_name = str(service.option("query_name", "example.com"))
        query_type_name = str(service.option("query_type", "A")).upper()
        if query_type_name not in QUERY_TYPES:
            raise ValueError("Unsupported DNS query type %s" % query_type_name)
        transaction_id = random.SystemRandom().randint(0, 65535)
        header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        payload = header + _encode_name(query_name) + struct.pack("!HH", QUERY_TYPES[query_type_name], 1)
        response = _query(service, payload)
        rcode, truncated, answers = _parse_response(response, transaction_id)
        if truncated:
            response = _query_tcp(service, payload)
            rcode, _, answers = _parse_response(response, transaction_id)
        latency = elapsed_ms(start)
        if rcode:
            return CheckOutcome(False, "DNS returned RCODE %d" % rcode, latency, None, {"rcode": rcode})
        expected = [str(value).lower().rstrip(".") for value in service.option("expected_answers", [])]
        answer_values = [answer.split(":", 1)[-1].lower().rstrip(".") for answer in answers]
        missing = [value for value in expected if value not in answer_values]
        if not answers:
            return CheckOutcome(False, "DNS returned no answers", latency, stable_fingerprint("dns", []), {"answers": []})
        if missing:
            return CheckOutcome(False, "DNS answers missing: %s" % ", ".join(missing), latency, stable_fingerprint("dns", sorted(answers)), {"answers": answers})
        return CheckOutcome(True, "%s %s returned %d answer(s) in %d ms" % (query_name, query_type_name, len(answers), latency), latency, stable_fingerprint("dns", sorted(answers)), {"answers": answers})
    except Exception as exc:
        return CheckOutcome(False, "DNS error: %s" % exc, elapsed_ms(start), None)
