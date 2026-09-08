from __future__ import annotations

import os
import unittest
from unittest import mock

from ccdc_scorer.checkers import supported_types
from ccdc_scorer.config import ConfigError, parse_config
from ccdc_scorer.presets import PresetRegistry


class ConfigTests(unittest.TestCase):
    def test_current_legacy_shape_is_supported(self):
        config = parse_config({
            "timeout_seconds": 8,
            "services": [{
                "id": "ftp-1",
                "team": "Blue 1",
                "type": "ftp",
                "host": "10.0.0.1",
                "ftp_mode": "explicit_tls",
                "ftp_user": "user",
                "ftp_pass": "secret",
            }],
        })
        service = config.services[0]
        self.assertEqual(service.port, 21)
        self.assertEqual(service.timeout, 8)
        self.assertEqual(service.option("tls_mode"), "starttls")
        self.assertEqual(service.option("username"), "user")
        self.assertEqual(service.option("password"), "secret")

    def test_custom_preset_inherits_and_overrides_nested_options(self):
        config = parse_config({
            "presets": {
                "lab-splunk": {
                    "extends": "splunk-webui",
                    "options": {"host_header": "splunk.lab", "expected_content": "Splunk"},
                }
            },
            "services": [{
                "id": "splunk-1", "team": "Blue", "preset": "lab-splunk", "host": "10.0.0.2",
                "options": {"path": "/login"},
            }],
        })
        service = config.services[0]
        self.assertEqual(service.type, "HTTPS")
        self.assertEqual(service.port, 8000)
        self.assertEqual(service.option("host_header"), "splunk.lab")
        self.assertEqual(service.option("path"), "/login")
        self.assertFalse(service.option("verify_cert"))

    def test_environment_secret_expansion(self):
        with mock.patch.dict(os.environ, {"TEST_SCORER_PASSWORD": "from-env"}, clear=False):
            config = parse_config({"services": [{
                "id": "mail", "team": "Blue", "preset": "email-imaps", "host": "mail.lab",
                "options": {"password": "${ENV:TEST_SCORER_PASSWORD}"},
            }]})
        self.assertEqual(config.services[0].option("password"), "from-env")

    def test_unset_environment_secret_is_rejected(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ConfigError, "unset environment variable"):
                parse_config({"services": [{
                    "id": "mail", "team": "Blue", "preset": "email-imaps", "host": "mail.lab",
                    "options": {"password": "${ENV:MISSING_SCORER_PASSWORD}"},
                }]})

    def test_duplicate_ids_are_rejected(self):
        service = {"id": "same", "team": "Blue", "preset": "ssh", "host": "server.lab"}
        with self.assertRaisesRegex(ConfigError, "duplicates"):
            parse_config({"services": [service, dict(service)]})

    def test_preset_cycle_is_rejected(self):
        with self.assertRaisesRegex(ConfigError, "Circular"):
            parse_config({
                "presets": {"one": {"extends": "two"}, "two": {"extends": "one"}},
                "services": [{"id": "cycle", "team": "Blue", "preset": "one", "host": "host"}],
            })

    def test_duplicate_team_matrix_cells_are_rejected(self):
        with self.assertRaisesRegex(ConfigError, "same team/matrix_key cell"):
            parse_config({"services": [
                {"id": "web-a", "team": "Blue", "preset": "web-http", "host": "web-a", "options": {"matrix_key": "Web"}},
                {"id": "web-b", "team": "Blue", "preset": "web-http", "host": "web-b", "options": {"matrix_key": "Web"}},
            ]})

    def test_every_requested_protocol_has_a_checker(self):
        expected = {"HTTP", "HTTPS", "DNS", "SMTP", "POP3", "IMAP", "FTP", "SSH", "LDAP", "RDP", "SMB"}
        self.assertTrue(expected.issubset(set(supported_types())))

    def test_preset_catalog_covers_requested_services(self):
        names = set(PresetRegistry().names())
        self.assertTrue({"splunk-webui", "wazuh-webui", "web-http", "web-https", "ssh", "dns", "ldap", "rdp", "smb"}.issubset(names))


if __name__ == "__main__":
    unittest.main()
