from __future__ import annotations

import base64
import re
import socket
import struct
import time

from ..models import CheckOutcome, ServiceConfig
from .base import elapsed_ms, recv_exact, recv_until, register, server_name, sha256, stable_fingerprint, tls_context


RDP_NEGOTIATION_REQUEST = bytes.fromhex("030000130ee000000000000100080003000000")
RDP_PROTOCOLS = {0: "RDP", 1: "TLS", 2: "CredSSP", 8: "CredSSP+EarlyAuth"}


@register("RDP")
def check_rdp(service: ServiceConfig) -> CheckOutcome:
    start = time.perf_counter()
    try:
        with socket.create_connection((service.host, service.port), timeout=service.timeout) as sock:
            sock.settimeout(service.timeout)
            sock.sendall(RDP_NEGOTIATION_REQUEST)
            header = recv_exact(sock, 4)
            if header[0] != 3:
                raise RuntimeError("invalid TPKT version")
            packet_length = struct.unpack("!H", header[2:4])[0]
            if packet_length < 11 or packet_length > 65535:
                raise RuntimeError("invalid TPKT length")
            packet = header + recv_exact(sock, packet_length - 4)
        if len(packet) < 6 or packet[5] != 0xD0:
            raise RuntimeError("server did not return an X.224 connection confirm")
        selected = 0
        if len(packet) >= 19 and packet[11] == 0x02:
            selected = struct.unpack("<I", packet[15:19])[0]
        elif len(packet) >= 19 and packet[11] == 0x03:
            failure = struct.unpack("<I", packet[15:19])[0]
            raise RuntimeError("RDP negotiation failed with code 0x%08x" % failure)
        protocol = RDP_PROTOCOLS.get(selected, "0x%08x" % selected)
        latency = elapsed_ms(start)
        return CheckOutcome(True, "RDP negotiation selected %s in %d ms" % (protocol, latency), latency, stable_fingerprint("rdp", {"protocol": selected}), {"protocol": protocol})
    except Exception as exc:
        return CheckOutcome(False, "RDP error: %s" % exc, elapsed_ms(start), None)


def _smb2_negotiate_request() -> bytes:
    header = (
        b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0) + struct.pack("<I", 0)
        + struct.pack("<H", 0) + struct.pack("<H", 1) + struct.pack("<I", 0)
        + struct.pack("<I", 0) + struct.pack("<Q", 1) + struct.pack("<I", 0)
        + struct.pack("<I", 0) + struct.pack("<Q", 0) + (b"\x00" * 16)
    )
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = (
        struct.pack("<H", 36) + struct.pack("<H", len(dialects)) + struct.pack("<H", 1)
        + struct.pack("<H", 0) + struct.pack("<I", 0) + (b"\x00" * 16)
        + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 0)
        + b"".join(struct.pack("<H", dialect) for dialect in dialects)
    )
    payload = header + body
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


@register("SMB")
def check_smb(service: ServiceConfig) -> CheckOutcome:
    start = time.perf_counter()
    try:
        with socket.create_connection((service.host, service.port), timeout=service.timeout) as sock:
            sock.settimeout(service.timeout)
            sock.sendall(_smb2_negotiate_request())
            netbios = recv_exact(sock, 4)
            size = int.from_bytes(netbios[1:4], "big")
            if netbios[0] != 0 or size < 64 or size > 1024 * 1024:
                raise RuntimeError("invalid NetBIOS session response")
            payload = recv_exact(sock, size)
        if payload[:4] != b"\xfeSMB":
            if payload[:4] == b"\xffSMB":
                raise RuntimeError("server only returned legacy SMB1")
            raise RuntimeError("response was not SMB")
        status = struct.unpack("<I", payload[8:12])[0]
        command = struct.unpack("<H", payload[12:14])[0]
        if status != 0 or command != 0:
            raise RuntimeError("SMB2 negotiate returned status 0x%08x" % status)
        if len(payload) < 70:
            raise RuntimeError("truncated SMB2 negotiate response")
        dialect = struct.unpack("<H", payload[68:70])[0]
        dialect_name = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}.get(dialect, "0x%04x" % dialect)
        latency = elapsed_ms(start)
        return CheckOutcome(True, "SMB %s negotiated in %d ms" % (dialect_name, latency), latency, stable_fingerprint("smb", {"dialect": dialect}), {"dialect": dialect_name})
    except Exception as exc:
        return CheckOutcome(False, "SMB error: %s" % exc, elapsed_ms(start), None)


@register("TCP")
def check_tcp(service: ServiceConfig) -> CheckOutcome:
    start = time.perf_counter()
    try:
        with socket.create_connection((service.host, service.port), timeout=service.timeout) as raw:
            raw.settimeout(service.timeout)
            sock = raw
            if bool(service.option("tls", False)):
                sock = tls_context(service).wrap_socket(raw, server_hostname=server_name(service))
            send_value = service.option("send")
            if send_value is not None:
                encoding = str(service.option("send_encoding", "text")).lower()
                if encoding == "hex":
                    packet = bytes.fromhex(str(send_value))
                elif encoding == "base64":
                    packet = base64.b64decode(str(send_value), validate=True)
                else:
                    packet = str(send_value).encode("utf-8")
                sock.sendall(packet)
            read_bytes = int(service.option("read_bytes", 0))
            response = b""
            if read_bytes > 0 or service.option("expected_content") is not None or service.option("expected_regex"):
                response = recv_until(sock, b"\n", read_bytes or 65536)
        decoded = response.decode("utf-8", "replace")
        expected_content = service.option("expected_content")
        if expected_content is not None and str(expected_content) not in decoded:
            raise RuntimeError("required response content was not found")
        expected_regex = service.option("expected_regex")
        if expected_regex and not re.search(str(expected_regex), decoded):
            raise RuntimeError("required response pattern was not found")
        latency = elapsed_ms(start)
        fingerprint = "tcp:%s" % sha256(response) if response else "tcp:connected"
        return CheckOutcome(True, "TCP connection succeeded in %d ms" % latency, latency, fingerprint)
    except Exception as exc:
        return CheckOutcome(False, "TCP error: %s" % exc, elapsed_ms(start), None)
