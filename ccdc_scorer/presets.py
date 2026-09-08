from __future__ import annotations

import copy
from typing import Any, Dict, Iterable, Mapping


# Presets intentionally contain only non-secret defaults. Credentials belong in
# the service instance and can be supplied through ${ENV:VARIABLE} references.
BUILTIN_PRESETS: Dict[str, Dict[str, Any]] = {
    "web-http": {
        "type": "HTTP",
        "port": 80,
        "options": {"path": "/", "expected_status": [200, 399], "fingerprint_mode": "status_ctype"},
    },
    "web-https": {
        "type": "HTTPS",
        "port": 443,
        "options": {"path": "/", "verify_cert": False, "expected_status": [200, 399], "fingerprint_mode": "status_ctype"},
    },
    "splunk-webui": {
        "type": "HTTPS",
        "port": 8000,
        "options": {
            "path": "/en-US/account/login",
            "verify_cert": False,
            "expected_status": [200, 399],
            "fingerprint_mode": "status_ctype",
        },
    },
    "wazuh-webui": {
        "type": "HTTPS",
        "port": 443,
        "options": {
            "path": "/app/login",
            "verify_cert": False,
            "expected_status": [200, 399],
            "fingerprint_mode": "status_ctype",
        },
    },
    "email-smtp": {"type": "SMTP", "port": 25, "options": {"tls_mode": "plain"}},
    "email-submission": {"type": "SMTP", "port": 587, "options": {"tls_mode": "starttls"}},
    "email-smtps": {"type": "SMTP", "port": 465, "options": {"tls_mode": "implicit"}},
    "email-pop3": {"type": "POP3", "port": 110, "options": {"tls_mode": "plain"}},
    "email-pop3s": {"type": "POP3", "port": 995, "options": {"tls_mode": "implicit"}},
    "email-imap": {"type": "IMAP", "port": 143, "options": {"tls_mode": "plain"}},
    "email-imaps": {"type": "IMAP", "port": 993, "options": {"tls_mode": "implicit"}},
    "ftp": {"type": "FTP", "port": 21, "options": {"tls_mode": "plain"}},
    "ftps-explicit": {"type": "FTP", "port": 21, "options": {"tls_mode": "starttls", "verify_cert": False}},
    "ftps-implicit": {"type": "FTP", "port": 990, "options": {"tls_mode": "implicit", "verify_cert": False}},
    "ssh": {"type": "SSH", "port": 22, "options": {"require_auth": False}},
    "dns": {"type": "DNS", "port": 53, "options": {"query_name": "example.com", "query_type": "A"}},
    "ldap": {"type": "LDAP", "port": 389, "options": {"tls_mode": "plain"}},
    "ldaps": {"type": "LDAP", "port": 636, "options": {"tls_mode": "implicit", "verify_cert": False}},
    "rdp": {"type": "RDP", "port": 3389},
    "smb": {"type": "SMB", "port": 445},
    "tcp": {"type": "TCP"},
}

ALIASES = {
    "http": "web-http",
    "https": "web-https",
    "splunk": "splunk-webui",
    "wazuh": "wazuh-webui",
    "smtp": "email-smtp",
    "submission": "email-submission",
    "smtps": "email-smtps",
    "pop3": "email-pop3",
    "pop3s": "email-pop3s",
    "imap": "email-imap",
    "imaps": "email-imaps",
}


def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = copy.deepcopy(dict(base))
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


class PresetRegistry:
    def __init__(self, custom: Mapping[str, Mapping[str, Any]] | None = None):
        self._definitions: Dict[str, Dict[str, Any]] = copy.deepcopy(BUILTIN_PRESETS)
        for name, definition in (custom or {}).items():
            self._definitions[str(name).lower()] = copy.deepcopy(dict(definition))

    def names(self) -> Iterable[str]:
        return sorted(self._definitions)

    def resolve(self, name: str) -> Dict[str, Any]:
        return self._resolve(ALIASES.get(name.lower(), name.lower()), [])

    def _resolve(self, name: str, stack: list[str]) -> Dict[str, Any]:
        if name in stack:
            raise ValueError("Circular preset inheritance: " + " -> ".join(stack + [name]))
        try:
            definition = copy.deepcopy(self._definitions[name])
        except KeyError as exc:
            raise KeyError("Unknown preset: %s" % name) from exc
        parent = definition.pop("extends", None)
        if not parent:
            return definition
        parent_name = ALIASES.get(str(parent).lower(), str(parent).lower())
        return deep_merge(self._resolve(parent_name, stack + [name]), definition)

    def public_catalog(self) -> Dict[str, Dict[str, Any]]:
        return {name: self.resolve(name) for name in self.names()}
