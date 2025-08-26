#!/usr/bin/env python3
"""
CCDC All-in-One Scoring Engine + Web UI (Baseline + Cookie-safe HTTPS)

- Baseline: first successful fingerprints saved into baseline.json (in --outdir)
- Accuracy: subsequent rounds must match baseline to earn points
- HTTPS fingerprinting:
    * Reliable low-level TLS + HTTP/1.1 client (works with SNI/Host-on-IP)
    * Optional cookie/token scrubbing for dynamic pages
    * Modes: full | status_ctype | status_only
- Services: HTTPS, DNS, SMTP, POP3
- Web UI: Leaderboard, Service Status (with Accuracy), Last Rounds

Run:
  python ccdc_all_in_one.py --config ccdc_config.json --outdir out --interval 60 \
         --host 0.0.0.0 --port 8080 --rounds 0
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import datetime as dt
import hashlib
import http.client
import json
import os
import poplib
import random
import re
import smtplib
import socket
import ssl
import struct
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple

# ===========================
# Data models / Utilities
# ===========================

@dataclasses.dataclass
class Service:
    id: str
    team: str
    type: str  # HTTPS | DNS | SMTP | POP3
    host: str
    port: int
    weight: int = 10

    # HTTPS options
    path: str = "/"
    verify_cert: bool = True
    host_header: Optional[str] = None
    sni: Optional[str] = None

    # HTTPS fingerprinting options
    fingerprint_mode: str = "full"      # "full" | "status_ctype" | "status_only"
    body_regex: Optional[str] = None    # optional regex to extract stable parts
    ignore_cookies: bool = False        # scrub cookies/tokens from body before hashing
    cookie_body_patterns: Optional[List[str]] = None  # optional custom regex list

    # DNS options
    query_name: str = "example.com"

    # SMTP options
    ssl_only: bool = False   # SMTPS/465 if True
    use_tls: bool = False    # STARTTLS for 25/587 if True
    username: Optional[str] = None
    password: Optional[str] = None

    # POP3 options
    pop_ssl: bool = False    # POP3S/995
    pop_user: Optional[str] = None
    pop_pass: Optional[str] = None

    timeout: float = 6.0


@dataclasses.dataclass
class ServiceResult:
    id: str
    team: str
    type: str
    host: str
    port: int
    passed: bool
    accurate: Optional[bool]  # None if no baseline exists for this service
    points: int
    message: str
    latency_ms: Optional[int]
    fingerprint: Optional[str]
    timestamp: str


def now_iso() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()


def ms_since(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


def csv_escape(s: Any) -> str:
    if s is None:
        return ""
    text = str(s)
    if any(c in text for c in [",", "\"", "\n"]):
        return "\"" + text.replace("\"", "\"\"") + "\""
    return text


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ===========================
# Cookie scrubbing & HTTP fingerprint helper
# ===========================

DEFAULT_COOKIE_BODY_PATTERNS = [
    r"splunkweb_csrf_token\s*=\s*['\"][^'\"]+['\"]",
    r"csrf[_-]?token\s*[:=]\s*['\"][^'\"]+['\"]",
    r"document\.cookie\s*=\s*['\"][^'\"]+['\"]",
    r"\b(JSESSIONID|sessionid|sessid|_session_id)\s*=\s*[^;\"'\s]+",
    r"Set-Cookie:[^\r\n]+",  # in case headers get mirrored into body
]

def scrub_cookies_from_body(body: bytes, svc: Service) -> bytes:
    """Remove cookie/token substrings from body bytes before hashing."""
    try:
        text = body.decode("utf-8", "ignore")
    except Exception:
        return body
    patterns = svc.cookie_body_patterns or DEFAULT_COOKIE_BODY_PATTERNS
    for pat in patterns:
        text = re.sub(pat, "COOKIE_REDACTED", text, flags=re.I | re.S)
    return text.encode("utf-8", "ignore")


def fingerprint_http(svc: Service, status: int, content_type: str, body: bytes) -> str:
    """
    Build a stable fingerprint for HTTP/HTTPS responses with optional cookie scrubbing
    and relaxed modes to avoid mismatches on dynamic pages.
    """
    mode = (svc.fingerprint_mode or "full").lower()
    if mode == "status_only":
        return f"status={status}"
    if mode == "status_ctype":
        return f"status={status}|ctype={content_type or ''}"

    # full mode -> may scrub cookies and/or extract stable part
    if svc.ignore_cookies:
        body = scrub_cookies_from_body(body, svc)

    if svc.body_regex:
        try:
            text = body.decode("utf-8", "ignore")
            matches = re.findall(svc.body_regex, text, flags=re.S | re.I)
            selected = "|".join(matches) if matches else ""
            return f"status={status}|ctype={content_type or ''}|sel={sha256_hex(selected.encode('utf-8'))}"
        except Exception:
            # fall through to plain body hashing
            pass

    return f"status={status}|ctype={content_type or ''}|b64k={sha256_hex(body[:65536])}"


# ===========================
# Minimal DNS client (A)
# ===========================

def _dns_encode_name(name: str) -> bytes:
    parts = name.strip(".").split(".")
    out = b""
    for p in parts:
        bpart = p.encode("utf-8")
        if len(bpart) > 63:
            raise ValueError("DNS label too long")
        out += struct.pack("!B", len(bpart)) + bpart
    return out + b"\x00"


def _dns_decode_name(buf: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    jumped = False
    orig_offset = offset
    while True:
        if offset >= len(buf):
            raise ValueError("DNS name decode out of range")
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("DNS pointer out of range")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            offset += 2
            if not jumped:
                orig_offset = offset
            offset = pointer
            jumped = True
            continue
        else:
            offset += 1
            if offset + length > len(buf):
                raise ValueError("DNS label length out of range")
            labels.append(buf[offset:offset+length].decode("utf-8"))
            offset += length
    name = ".".join(labels)
    return name, (orig_offset if jumped else offset)


def dns_query_a(server: str, port: int, qname: str, timeout: float) -> Tuple[bool, str, List[str]]:
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100  # rd=1
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    q = _dns_encode_name(qname) + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    payload = header + q
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        sock.sendto(payload, (server, port))
        data, _ = sock.recvfrom(4096)
        rtt = ms_since(start)
        if len(data) < 12:
            return False, "Truncated DNS header", []
        r_tid, r_flags, r_qd, r_an, r_ns, r_ar = struct.unpack("!HHHHHH", data[:12])
        if r_tid != tid:
            return False, "Transaction ID mismatch", []
        rcode = r_flags & 0x000F
        if rcode != 0:
            return False, f"DNS error RCODE={rcode}", []
        offset = 12
        for _ in range(r_qd):
            _, offset = _dns_decode_name(data, offset)
            offset += 4
        a_records: List[str] = []
        for _ in range(r_an):
            _, offset = _dns_decode_name(data, offset)
            if offset + 10 > len(data):
                return False, "DNS answer truncated", []
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10
            if offset + rdlen > len(data):
                return False, "DNS rdata truncated", []
            rdata = data[offset:offset+rdlen]
            offset += rdlen
            if rtype == 1 and rclass == 1 and rdlen == 4:
                a_records.append(".".join(str(b) for b in rdata))
        if a_records:
            return True, f"A={','.join(a_records)} ({rtt} ms)", a_records
        return False, "No A records in answer", []
    except socket.timeout:
        return False, "DNS timeout", []
    except Exception as e:
        return False, f"DNS error: {e}", []
    finally:
        sock.close()


# ===========================
# Service checks (with fingerprints)
# ===========================

# Each checker returns: (ok: bool, message: str, latency_ms: Optional[int], fingerprint: Optional[str])

def check_https(svc: Service) -> Tuple[bool, str, Optional[int], Optional[str]]:
    """
    Low-level TLS + HTTP/1.1 client:
    - Connects to svc.host:svc.port
    - Sends SNI = svc.sni or svc.host
    - Uses Host header = svc.host_header or SNI host
    - Reads up to 64KB to build a fingerprint
    """
    # TLS context
    ctx = ssl.create_default_context()
    if not svc.verify_cert:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    sni_host = svc.sni or svc.host
    host_header = svc.host_header or sni_host
    path = svc.path or "/"

    start = time.perf_counter()
    try:
        # TCP connect
        with socket.create_connection((svc.host, svc.port), timeout=svc.timeout) as raw:
            # TLS wrap with SNI
            with ctx.wrap_socket(raw, server_hostname=sni_host) as ssock:
                ssock.settimeout(svc.timeout)

                # Minimal HTTP/1.1 GET
                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"User-Agent: ccdc-scorer/1.0\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode("ascii", "strict")
                ssock.sendall(req)

                # Read up to 64KB
                chunks: List[bytes] = []
                total = 0
                max_bytes = 64 * 1024
                while total < max_bytes:
                    try:
                        data = ssock.recv(min(4096, max_bytes - total))
                    except socket.timeout:
                        break
                    if not data:
                        break
                    chunks.append(data)
                    total += len(data)
                blob = b"".join(chunks)
    except ssl.SSLError as e:
        return False, f"TLS error: {e}", None, None
    except (ConnectionRefusedError, TimeoutError, socket.timeout) as e:
        return False, f"Connect timeout/refused: {e}", None, None
    except Exception as e:
        return False, f"HTTPS error: {e}", None, None

    rtt = ms_since(start)

    # Parse status line + Content-Type (loose)
    try:
        header_end = blob.find(b"\r\n\r\n")
        header_block = blob[:header_end if header_end != -1 else len(blob)]
        lines = header_block.split(b"\r\n")
        status_line = lines[0].decode("iso-8859-1", "replace") if lines else "HTTP/1.1 000"
        parts = status_line.split()
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

        ctype = ""
        for ln in lines[1:]:
            if ln.lower().startswith(b"content-type:"):
                ctype = ln.split(b":", 1)[1].strip().decode("iso-8859-1", "replace")
                break

        body = blob[header_end+4:] if header_end != -1 else b""
        fp = fingerprint_http(svc, status, ctype, body)
        ok = (200 <= status < 400)
        if ok:
            return True, f"HTTP {status} OK ({rtt} ms)", rtt, fp
        else:
            reason = " ".join(parts[2:]) if len(parts) >= 3 else ""
            return False, f"HTTP {status} {reason}".strip(), rtt, fp
    except Exception as e:
        fp = f"raw={sha256_hex(blob)}"
        return False, f"HTTPS parse error: {e}", rtt, fp


def check_dns(svc: Service) -> Tuple[bool, str, Optional[int], Optional[str]]:
    ok, msg, arecs = dns_query_a(svc.host, svc.port, svc.query_name, svc.timeout)
    latency = None
    if "(" in msg and "ms" in msg:
        with contextlib.suppress(Exception):
            latency = int(msg.split("(")[-1].split("ms")[0].strip())
    fp = None
    if arecs:
        fp = "A=" + ",".join(sorted(arecs))
    return ok, msg, latency, fp


def check_smtp(svc: Service) -> Tuple[bool, str, Optional[int], Optional[str]]:
    start = time.perf_counter()
    smtp = None
    try:
        if svc.ssl_only:
            smtp = smtplib.SMTP_SSL(host=svc.host, port=svc.port, timeout=svc.timeout)
        else:
            smtp = smtplib.SMTP(host=svc.host, port=svc.port, timeout=svc.timeout)
        code, banner = smtp.connect(svc.host, svc.port)  # capture banner
        smtp.ehlo_or_helo_if_needed()
        if not svc.ssl_only and svc.use_tls:
            with contextlib.suppress(Exception):
                smtp.starttls()
                smtp.ehlo()
        if svc.username and svc.password:
            smtp.login(svc.username, svc.password)
        rtt = ms_since(start)
        code2, msg2 = smtp.ehlo()  # final EHLO string
        banner_bytes = (banner or b"")
        ehlo_bytes = (msg2 or b"")
        fp = f"banner={sha256_hex(banner_bytes)}|ehlo={sha256_hex(ehlo_bytes)}"
        code3, _ = smtp.noop()
        ok = 200 <= code3 < 400
        return (True if ok else True), f"SMTP {'up' if ok else 'responsive'} ({rtt} ms)", rtt, fp
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP auth failed", None, None
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected) as e:
        return False, f"SMTP connection error: {e}", None, None
    except (socket.timeout, TimeoutError) as e:
        return False, f"SMTP timeout: {e}", None, None
    except Exception as e:
        return False, f"SMTP error: {e}", None, None
    finally:
        with contextlib.suppress(Exception):
            if smtp:
                smtp.quit()


def check_pop3(svc: Service) -> Tuple[bool, str, Optional[int], Optional[str]]:
    start = time.perf_counter()
    pop = None
    try:
        if svc.pop_ssl:
            pop = poplib.POP3_SSL(host=svc.host, port=svc.port, timeout=svc.timeout)
        else:
            pop = poplib.POP3(host=svc.host, port=svc.port, timeout=svc.timeout)
        welcome = pop.getwelcome() or b""
        if svc.pop_user and svc.pop_pass:
            pop.user(svc.pop_user)
            pop.pass_(svc.pop_pass)
        rtt = ms_since(start)
        with contextlib.suppress(Exception):
            pop.stat()
        fp = f"welcome={sha256_hex(welcome)}"
        return True, f"POP3 up ({rtt} ms)", rtt, fp
    except poplib.error_proto as e:
        return False, f"POP3 protocol error: {e}", None, None
    except (socket.timeout, TimeoutError) as e:
        return False, f"POP3 timeout: {e}", None, None
    except Exception as e:
        return False, f"POP3 error: {e}", None, None
    finally:
        with contextlib.suppress(Exception):
            if pop:
                pop.quit()


CHECKERS = {
    "HTTPS": check_https,
    "DNS":   check_dns,
    "SMTP":  check_smtp,
    "POP3":  check_pop3,
}

# ===========================
# Config / Engine helpers
# ===========================

def default_port_for(service_type: str) -> int:
    return {
        "HTTPS": 443,
        "DNS":   53,
        "SMTP":  25,
        "POP3":  110,
    }.get(service_type.upper(), 0)


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_services(cfg: Dict[str, Any]) -> List[Service]:
    services: List[Service] = []
    for raw in cfg.get("services", []):
        svc = Service(
            id=raw["id"],
            team=raw["team"],
            type=raw["type"].upper(),
            host=raw["host"],
            port=int(raw.get("port", default_port_for(raw["type"]))),
            weight=int(raw.get("weight", 10)),

            # HTTPS options
            path=raw.get("path", "/"),
            verify_cert=bool(raw.get("verify_cert", True)),
            host_header=raw.get("host_header"),
            sni=raw.get("sni"),

            # HTTPS fingerprint options
            fingerprint_mode=raw.get("fingerprint_mode", "full"),
            body_regex=raw.get("body_regex"),
            ignore_cookies=bool(raw.get("ignore_cookies", False)),
            cookie_body_patterns=raw.get("cookie_body_patterns"),

            # DNS
            query_name=raw.get("query_name", cfg.get("dns_query_name", "example.com")),

            # SMTP
            ssl_only=bool(raw.get("ssl_only", False)),
            use_tls=bool(raw.get("use_tls", False)),
            username=raw.get("username"),
            password=raw.get("password"),

            # POP3
            pop_ssl=bool(raw.get("pop_ssl", raw.get("ssl_only", False))),
            pop_user=raw.get("pop_user", raw.get("username")),
            pop_pass=raw.get("pop_pass", raw.get("password")),

            timeout=float(raw.get("timeout", cfg.get("timeout_seconds", 6.0))),
        )
        services.append(svc)
    return services


def write_csv_header(path: str):
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write("round,timestamp,team,service_id,type,host,port,passed,accurate,points,message,latency_ms,total_points\n")


def append_csv(path: str, round_num: int, results: List[ServiceResult], totals: Dict[str, int]):
    with open(path, "a", encoding="utf-8", newline="") as f:
        for r in results:
            f.write(
                f"{round_num},{r.timestamp},{csv_escape(r.team)},{csv_escape(r.id)},{r.type},"
                f"{r.host},{r.port},{int(r.passed)},{'' if r.accurate is None else int(bool(r.accurate))},"
                f"{r.points},{csv_escape(r.message)},"
                f"{'' if r.latency_ms is None else r.latency_ms},{totals.get(r.team,0)}\n"
            )


def append_jsonl(path: str, payload: Dict[str, Any]):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")


def run_check(svc: Service) -> ServiceResult:
    checker = CHECKERS.get(svc.type.upper())
    if not checker:
        return ServiceResult(
            id=svc.id, team=svc.team, type=svc.type, host=svc.host, port=svc.port,
            passed=False, accurate=None, points=0, message=f"Unknown service type: {svc.type}",
            latency_ms=None, fingerprint=None, timestamp=now_iso()
        )
    ok, msg, latency, fp = checker(svc)
    return ServiceResult(
        id=svc.id, team=svc.team, type=svc.type.upper(), host=svc.host, port=svc.port,
        passed=ok, accurate=None, points=0, message=msg, latency_ms=latency, fingerprint=fp,
        timestamp=now_iso()
    )


def run_round(services: List[Service], max_workers: int = 16) -> List[ServiceResult]:
    results: List[ServiceResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut_to_svc = {ex.submit(run_check, svc): svc for svc in services}
        for fut in concurrent.futures.as_completed(fut_to_svc):
            svc = fut_to_svc[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                results.append(ServiceResult(
                    id=svc.id, team=svc.team, type=svc.type, host=svc.host, port=svc.port,
                    passed=False, accurate=None, points=0, message=f"Checker crashed: {e}",
                    latency_ms=None, fingerprint=None, timestamp=now_iso()
                ))
    results.sort(key=lambda r: (r.team, r.id))
    return results


def summarize_results(results: List[ServiceResult]) -> Dict[str, Any]:
    per_team_round_points: Dict[str, int] = {}
    per_team_up: Dict[str, int] = {}
    for r in results:
        per_team_round_points[r.team] = per_team_round_points.get(r.team, 0) + r.points
        if r.passed:
            per_team_up[r.team] = per_team_up.get(r.team, 0) + 1
    return {"round_points": per_team_round_points, "services_up": per_team_up}


# ===========================
# In-memory scoreboard state
# ===========================

STATE_LOCK = threading.Lock()
STATE: Dict[str, Any] = {
    "services": [],         # List[Service]
    "baseline": {},         # Dict[service_id, fingerprint]
    "last_results": [],     # List[ServiceResult]
    "totals": {},           # Dict[team, int]
    "last_round": 0,
    "last_updated": None,   # ISO ts
    "outdir": ".",
}

BASELINE_FILE = "baseline.json"


def load_baseline(outdir: str) -> Dict[str, str]:
    path = os.path.join(outdir, BASELINE_FILE)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def save_baseline(outdir: str, baseline: Dict[str, str]) -> None:
    path = os.path.join(outdir, BASELINE_FILE)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def apply_accuracy_and_points(results: List[ServiceResult], baseline: Dict[str, str]) -> None:
    """Mutates results: sets accurate + points (points only if passed & accurate)."""
    for r in results:
        bl = baseline.get(r.id)
        if bl is None or r.fingerprint is None:
            r.accurate = None if bl is None else False
        else:
            r.accurate = (r.fingerprint == bl)
        qualifies = r.passed and (r.accurate is True or r.accurate is None)
        if qualifies:
            svc = next((s for s in STATE.get("services", []) if s.id == r.id), None)
            r.points = (svc.weight if svc else 0)
        else:
            r.points = 0
        if r.passed and r.accurate is False:
            r.message += " (baseline mismatch)"


# ===========================
# Scoring thread
# ===========================

def scoring_loop(cfg: Dict[str, Any], outdir: str, interval: int, rounds: int):
    services = parse_services(cfg)
    with STATE_LOCK:
        STATE["services"] = services
    os.makedirs(outdir, exist_ok=True)
    csv_path = os.path.join(outdir, "scores.csv")
    jsonl_path = os.path.join(outdir, "round_details.jsonl")
    write_csv_header(csv_path)

    # Load or create baseline
    baseline = load_baseline(outdir)
    if not baseline:
        print("No baseline found; creating baseline from initial snapshot…")
        base_results = run_round(services)
        for r in base_results:
            if r.fingerprint:
                baseline[r.id] = r.fingerprint
        save_baseline(outdir, baseline)
        print(f"Baseline saved to {os.path.join(outdir, BASELINE_FILE)} with {len(baseline)} entries.")
    with STATE_LOCK:
        STATE["baseline"] = dict(baseline)

    totals: Dict[str, int] = {}
    round_num = 1
    try:
        while True:
            started = now_iso()
            results = run_round(services)

            # Compare with baseline and assign points accordingly
            with STATE_LOCK:
                current_baseline = STATE.get("baseline", {})
            apply_accuracy_and_points(results, current_baseline)

            # Update totals
            for r in results:
                totals[r.team] = totals.get(r.team, 0) + r.points

            # Persist
            append_csv(csv_path, round_num, results, totals)
            summary = summarize_results(results)
            append_jsonl(jsonl_path, {
                "round": round_num,
                "started": started,
                "finished": now_iso(),
                "results": [dataclasses.asdict(r) for r in results],
                "totals": totals,
                "summary": summary,
            })

            # Update state for API/UI
            with STATE_LOCK:
                STATE["last_results"] = results
                STATE["totals"] = dict(totals)
                STATE["last_round"] = round_num
                STATE["last_updated"] = now_iso()

            # Console view
            print(f"\n=== Round {round_num} @ {started} ===")
            for team, pts in sorted(summary["round_points"].items(), key=lambda kv: kv[0]):
                up = summary["services_up"].get(team, 0)
                print(f"  {team:20} +{pts:4d} pts  |  services up: {up}")
            print("  (cumulative)", {t: totals[t] for t in sorted(totals)})

            if rounds and round_num >= rounds:
                break
            round_num += 1
            time.sleep(max(1, interval))
    except KeyboardInterrupt:
        print("\nScoring interrupted.")


# ===========================
# Web server (APIs + UI)
# ===========================

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CCDC Practice Scoreboard</title>
  <style>
    :root { --bg:#0c0f14; --panel:#131823; --muted:#9fb0c8; --accent:#6ab0ff; --good:#17c964; --bad:#f31260; }
    html,body{margin:0;height:100%;background:var(--bg);color:#e6eef7;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif}
    .wrap{max-width:1100px;margin:0 auto;padding:24px}
    .tabs{display:flex;gap:8px;margin-bottom:16px}
    .tab{padding:10px 14px;border-radius:12px;background:#101723;color:#cbd8ea;cursor:pointer}
    .tab.active{background:#172033;color:#fff;font-weight:600}
    .card{background:var(--panel);border-radius:16px;padding:18px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    .muted{color:var(--muted);font-size:14px}
    table{width:100%;border-collapse:collapse;margin-top:10px}
    th,td{padding:10px 8px;text-align:left;border-bottom:1px solid rgba(255,255,255,.06)}
    th{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#cbd8ea}
    .rank{width:70px}
    .pts{font-variant-numeric:tabular-nums}
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#172033;color:#cbd8ea;font-size:12px}
    .green{color:var(--good)} .red{color:var(--bad)}
    .grid{display:grid;grid-template-columns:1.1fr .9fr;gap:16px}
    @media(max-width:900px){ .grid{grid-template-columns:1fr} }
    .small{font-size:12px}
    .round{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px dashed rgba(255,255,255,.06)}
    .pill{padding:2px 8px;border-radius:999px;background:#172033;color:#cbd8ea;font-size:12px}
    .svcgrid{display:grid;grid-template-columns:1.1fr .7fr .7fr 2fr;gap:8px;align-items:center}
    .svcgrid > div{padding:8px;border-bottom:1px solid rgba(255,255,255,.06)}
    .svcgrid .head{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#cbd8ea}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="tabs">
      <div class="tab active" data-tab="leader">Leaderboard</div>
      <div class="tab" data-tab="status">Service Status</div>
      <div class="tab" data-tab="rounds">Last Rounds</div>
    </div>

    <div id="leader" class="card">
      <h2 style="margin:0 0 6px 0">Leaderboard</h2>
      <div class="muted" id="meta">Loading…</div>
      <table id="leaderTable">
        <thead><tr><th class="rank">Rank</th><th>Team</th><th class="pts">Points</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>

    <div id="status" class="card" style="display:none">
      <h2 style="margin:0 0 6px 0">Service Status</h2>
      <div class="svcgrid">
        <div class="head">Service</div><div class="head">State</div><div class="head">Accuracy</div><div class="head">Message</div>
      </div>
      <div id="svcrows"></div>
      <div class="muted small">Accuracy compares the latest fingerprint with the startup baseline.</div>
    </div>

    <div id="rounds" class="card" style="display:none">
      <h2 style="margin:0 0 6px 0">Last Rounds</h2>
      <div id="roundBox"></div>
      <div class="muted small">APIs: <code>/api/totals</code>, <code>/api/status</code>, <code>/api/rounds</code></div>
    </div>
  </div>
<script>
const TABS = document.querySelectorAll('.tab');
TABS.forEach(t => t.onclick = () => {
  TABS.forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  document.querySelectorAll('.card').forEach(c => c.style.display = 'none');
  document.getElementById(t.dataset.tab).style.display = '';
});

async function fetchJSON(url){ const r = await fetch(url, {cache:'no-store'}); if(!r.ok) throw new Error(await r.text()); return r.json(); }

function renderTotals(data){
  const tbody = document.querySelector('#leaderTable tbody');
  tbody.innerHTML = '';
  data.totals.forEach((row, idx) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="rank"><span class="badge">${idx+1}</span></td>
                    <td>${row.team}</td>
                    <td class="pts"><strong>${row.points}</strong></td>`;
    tbody.appendChild(tr);
  });
  const meta = document.getElementById('meta');
  const ts = data.last_updated ? new Date(data.last_updated).toLocaleString() : '—';
  meta.textContent = `Round ${data.last_round} • Updated ${ts}`;
}

function renderRounds(data){
  const box = document.getElementById('roundBox');
  box.innerHTML = '';
  data.rounds.slice().reverse().forEach(r => {
    const div = document.createElement('div');
    div.className = 'round small';
    const left = document.createElement('div');
    left.innerHTML = `<strong>Round ${r.round}</strong>`;
    const right = document.createElement('div');
    right.innerHTML = r.teams.map(t => `${t.team}: <span class="green">+${t.points}</span>`).join(' &nbsp; ');
    div.appendChild(left); div.appendChild(right);
    box.appendChild(div);
  });
}

function pill(text, good){
  const cls = good === null ? '' : (good ? 'green' : 'red');
  return `<span class="pill ${cls}">${text}</span>`;
}

function renderStatus(data){
  const box = document.getElementById('svcrows');
  box.innerHTML = '';
  data.results.forEach(r => {
    const state = pill(r.passed ? 'UP' : 'DOWN', r.passed);
    const acc = (r.accurate === null) ? pill('N/A', null) : pill(r.accurate ? 'MATCH' : 'MISMATCH', r.accurate);
    const line = document.createElement('div');
    line.className = 'svcgrid';
    line.innerHTML = `
      <div><strong>${r.team}</strong> • ${r.id} <span class="muted small">(${r.type} @ ${r.host}:${r.port})</span></div>
      <div>${state}</div>
      <div>${acc}</div>
      <div class="small">${r.message}</div>`;
    box.appendChild(line);
  });
}

async function refresh(){
  try {
    const [totals, rounds, status] = await Promise.all([
      fetchJSON('/api/totals'),
      fetchJSON('/api/rounds'),
      fetchJSON('/api/status'),
    ]);
    renderTotals(totals);
    renderRounds(rounds);
    renderStatus(status);
  } catch (e) {
    console.error(e);
    document.getElementById('meta').textContent = 'Waiting for scores…';
  }
}
setInterval(refresh, 5000);
refresh();
</script>
</body>
</html>
"""

class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, outdir: str, **kwargs):
        self._outdir = outdir
        super().__init__(*args, directory=self._outdir, **kwargs)

    def log_message(self, fmt, *args):
        return

    def _write_json(self, payload: Dict[str, Any]):
        blob = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def do_GET(self):
        if self.path.startswith("/api/"):
            if self.path == "/api/totals":
                with STATE_LOCK:
                    totals = STATE.get("totals", {})
                    last_round = STATE.get("last_round", 0)
                    last_updated = STATE.get("last_updated")
                return self._write_json({
                    "totals": sorted(
                        [{"team": t, "points": pts} for t, pts in totals.items()],
                        key=lambda x: (-x["points"], x["team"])
                    ),
                    "last_round": last_round,
                    "last_updated": last_updated,
                })

            if self.path == "/api/status":
                with STATE_LOCK:
                    results: List[ServiceResult] = STATE.get("last_results", [])
                    last_round = STATE.get("last_round", 0)
                    last_updated = STATE.get("last_updated")
                payload_results = [dataclasses.asdict(r) for r in results]
                return self._write_json({
                    "round": last_round,
                    "last_updated": last_updated,
                    "results": payload_results,
                })

            if self.path == "/api/rounds":
                import csv
                rows = []
                scores_path = os.path.join(self._outdir, "scores.csv")
                if os.path.exists(scores_path):
                    with open(scores_path, "r", encoding="utf-8", newline="") as f:
                        rows = list(csv.DictReader(f))
                per_round: Dict[int, Dict[str, int]] = {}
                for row in rows:
                    try:
                        rnd = int(row.get("round") or 0)
                        team = row.get("team") or "Unknown"
                        pts = int(row.get("points") or 0)
                        per_round.setdefault(rnd, {}).setdefault(team, 0)
                        per_round[rnd][team] += pts
                    except Exception:
                        pass
                if not per_round:
                    return self._write_json({"rounds": []})
                rounds_sorted = sorted(per_round.keys())[-12:]
                return self._write_json({"rounds": [
                    {"round": rnd,
                     "teams": [{"team": t, "points": per_round[rnd][t]} for t in sorted(per_round[rnd].keys())]}
                    for rnd in rounds_sorted
                ]})

            self.send_error(404, "Unknown API")
            return

        if self.path in ("/", "/index.html"):
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        return super().do_GET()


def start_server(host: str, port: int, outdir: str):
    def handler(*args, **kwargs):
        return AppHandler(*args, outdir=outdir, **kwargs)
    httpd = HTTPServer((host, port), handler)
    print(f"Web UI: http://{host}:{port}  (serving static files from {outdir})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb server stopping…")


# ===========================
# Main
# ===========================

def main():
    ap = argparse.ArgumentParser(description="CCDC All-in-One Scoring Engine + Web UI (Baseline Accuracy)")
    ap.add_argument("--config", required=True, help="Path to config JSON")
    ap.add_argument("--outdir", default=".", help="Directory for outputs")
    ap.add_argument("--interval", type=int, default=None, help="Seconds between rounds (overrides config)")
    ap.add_argument("--rounds", type=int, default=0, help="Number of rounds to run (0=infinite)")
    ap.add_argument("--host", default="0.0.0.0", help="Web server host")
    ap.add_argument("--port", type=int, default=8080, help="Web server port")
    args = ap.parse_args()

    cfg = load_config(args.config)
    interval = args.interval if args.interval is not None else int(cfg.get("interval_seconds", 60))
    os.makedirs(args.outdir, exist_ok=True)

    # Start scoring in background
    scorer = threading.Thread(target=scoring_loop, args=(cfg, args.outdir, interval, int(args.rounds)), daemon=True)
    scorer.start()

    # Start web server (blocks)
    start_server(args.host, args.port, args.outdir)


if __name__ == "__main__":
    main()
