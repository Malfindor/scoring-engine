from __future__ import annotations

import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from ccdc_scorer.engine import ScoringEngine
from ccdc_scorer.models import AppConfig, ServiceConfig
from ccdc_scorer.storage import ScoreStore
from ccdc_scorer.web import ScoreboardServer


class WebTests(unittest.TestCase):
    def test_dashboard_and_api_are_served(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AppConfig(services=[ServiceConfig("ssh", "Blue", "SSH", "127.0.0.1", 22, enabled=False)])
            engine = ScoringEngine(config, ScoreStore(root / "scores.db"), root)
            server = ScoreboardServer("127.0.0.1", 0, engine)
            thread = server.start_background()
            try:
                base = "http://127.0.0.1:%d" % server.address[1]
                with urllib.request.urlopen(base + "/", timeout=2) as response:
                    html = response.read().decode("utf-8")
                    self.assertIn("Scoring operations", html)
                    self.assertIn('class="view active" id="status-board"', html)
                    self.assertNotIn("Operational overview", html)
                    self.assertNotIn('data-view="overview"', html)
                    self.assertIn("Content-Security-Policy", response.headers)
                with urllib.request.urlopen(base + "/api/v1/summary", timeout=2) as response:
                    payload = json.load(response)
                self.assertEqual(payload["last_round"], 0)
                self.assertEqual(payload["results"][0]["message"], "Disabled")
                with urllib.request.urlopen(base + "/api/v1/presets", timeout=2) as response:
                    presets = json.load(response)["presets"]
                self.assertIn("splunk-webui", presets)
                with urllib.request.urlopen(base + "/api/v1/matrix/status", timeout=2) as response:
                    status_matrix = json.load(response)
                self.assertEqual(status_matrix["teams"], ["Blue"])
                self.assertEqual(status_matrix["cells"][0]["state"], "disabled")
                with urllib.request.urlopen(base + "/api/v1/matrix/uptime?rounds=25", timeout=2) as response:
                    uptime_matrix = json.load(response)
                self.assertEqual(uptime_matrix["round_count"], 0)
                self.assertEqual(uptime_matrix["services"][0]["key"], "ssh")
            finally:
                server.shutdown()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
