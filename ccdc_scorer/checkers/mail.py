from __future__ import annotations

import contextlib
import imaplib
import poplib
import smtplib
import time

from ..models import CheckOutcome, ServiceConfig
from .base import elapsed_ms, register, sha256, stable_fingerprint, tls_context


def _credentials(service: ServiceConfig):
    return service.option("username"), service.option("password")


@register("SMTP")
def check_smtp(service: ServiceConfig) -> CheckOutcome:
    start = time.perf_counter()
    client = None
    try:
        mode = str(service.option("tls_mode", "plain")).lower()
        if mode == "implicit":
            client = smtplib.SMTP_SSL(timeout=service.timeout, context=tls_context(service))
        else:
            client = smtplib.SMTP(timeout=service.timeout)
        code, _banner = client.connect(service.host, service.port)
        if not 200 <= code < 400:
            raise RuntimeError("server greeting returned %d" % code)
        code, _message = client.ehlo()
        if not 200 <= code < 400:
            code, _message = client.helo()
        if not 200 <= code < 400:
            raise RuntimeError("EHLO/HELO returned %d" % code)
        if mode == "starttls":
            code, _message = client.starttls(context=tls_context(service))
            if not 200 <= code < 400:
                raise RuntimeError("STARTTLS returned %d" % code)
            client.ehlo()
        username, password = _credentials(service)
        if username is not None:
            client.login(str(username), "" if password is None else str(password))
        code, _message = client.noop()
        latency = elapsed_ms(start)
        features = sorted(str(key).lower() for key in client.esmtp_features)
        fingerprint = stable_fingerprint("smtp", {"features": features, "tls": mode})
        if not 200 <= code < 400:
            return CheckOutcome(False, "SMTP NOOP returned %d" % code, latency, fingerprint, {"features": features})
        return CheckOutcome(True, "SMTP ready in %d ms" % latency, latency, fingerprint, {"features": features})
    except Exception as exc:
        return CheckOutcome(False, "SMTP error: %s" % exc, elapsed_ms(start), None)
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.quit()


@register("POP3")
def check_pop3(service: ServiceConfig) -> CheckOutcome:
    start = time.perf_counter()
    client = None
    try:
        mode = str(service.option("tls_mode", "plain")).lower()
        if mode == "implicit":
            client = poplib.POP3_SSL(service.host, service.port, timeout=service.timeout, context=tls_context(service))
        else:
            client = poplib.POP3(service.host, service.port, timeout=service.timeout)
        if mode == "starttls":
            client.stls(context=tls_context(service))
        username, password = _credentials(service)
        if username is not None:
            client.user(str(username))
            client.pass_("" if password is None else str(password))
        client.noop()
        welcome = client.getwelcome() or b""
        latency = elapsed_ms(start)
        fingerprint = "pop3:welcome=%s|tls=%s" % (sha256(welcome), mode)
        return CheckOutcome(True, "POP3 ready in %d ms" % latency, latency, fingerprint)
    except Exception as exc:
        return CheckOutcome(False, "POP3 error: %s" % exc, elapsed_ms(start), None)
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.quit()


@register("IMAP")
def check_imap(service: ServiceConfig) -> CheckOutcome:
    start = time.perf_counter()
    client = None
    try:
        mode = str(service.option("tls_mode", "plain")).lower()
        if mode == "implicit":
            client = imaplib.IMAP4_SSL(service.host, service.port, ssl_context=tls_context(service), timeout=service.timeout)
        else:
            client = imaplib.IMAP4(service.host, service.port, timeout=service.timeout)
        if mode == "starttls":
            status, _ = client.starttls(ssl_context=tls_context(service))
            if status != "OK":
                raise RuntimeError("STARTTLS failed")
        username, password = _credentials(service)
        if username is not None:
            status, _ = client.login(str(username), "" if password is None else str(password))
            if status != "OK":
                raise RuntimeError("login failed")
        status, _ = client.noop()
        if status != "OK":
            raise RuntimeError("NOOP failed")
        capabilities = sorted(
            (item.decode("ascii", "replace") if isinstance(item, bytes) else str(item)).upper()
            for item in client.capabilities
        )
        latency = elapsed_ms(start)
        return CheckOutcome(True, "IMAP ready in %d ms" % latency, latency, stable_fingerprint("imap", {"capabilities": capabilities, "tls": mode}), {"capabilities": capabilities})
    except Exception as exc:
        return CheckOutcome(False, "IMAP error: %s" % exc, elapsed_ms(start), None)
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.logout()
