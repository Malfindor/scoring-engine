from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ccdc_scorer.checkers.base import CHECKERS
from ccdc_scorer.engine import ScoringEngine
from ccdc_scorer.models import AppConfig, CheckOutcome, ServiceConfig
from ccdc_scorer.storage import ScoreStore


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.original_tcp = CHECKERS["TCP"]

    def tearDown(self):
        CHECKERS["TCP"] = self.original_tcp
        self.tempdir.cleanup()

    def _engine(self, **config_options):
        service = ServiceConfig("svc", "Blue", "TCP", "127.0.0.1", 9999, weight=10, timeout=1)
        config = AppConfig(services=[service], **config_options)
        store = ScoreStore(self.root / "scores.db")
        return ScoringEngine(config, store, self.root), store

    def test_baseline_learning_match_and_mismatch(self):
        outcomes = iter([
            CheckOutcome(True, "up", 2, "fingerprint-a"),
            CheckOutcome(True, "up", 2, "fingerprint-a"),
            CheckOutcome(True, "changed", 2, "fingerprint-b"),
        ])
        CHECKERS["TCP"] = lambda _: next(outcomes)
        engine, store = self._engine()
        first = engine.execute_round().results[0]
        second = engine.execute_round().results[0]
        third = engine.execute_round().results[0]
        self.assertEqual((first.baseline_state, first.points), ("learned", 10))
        self.assertEqual((second.baseline_state, second.accurate, second.points), ("match", True, 10))
        self.assertEqual((third.baseline_state, third.accurate, third.points), ("mismatch", False, 0))
        self.assertEqual(store.totals(), {"Blue": 20})
        self.assertEqual(store.next_round_number(), 4)

    def test_failed_initial_check_does_not_poison_baseline(self):
        outcomes = iter([CheckOutcome(False, "down", 1, None), CheckOutcome(True, "up", 1, "good")])
        CHECKERS["TCP"] = lambda _: next(outcomes)
        engine, store = self._engine()
        failed = engine.execute_round().results[0]
        learned = engine.execute_round().results[0]
        self.assertEqual(failed.baseline_state, "pending")
        self.assertEqual(store.load_baselines(), {"svc": "good"})
        self.assertEqual(learned.baseline_state, "learned")

    def test_database_restores_round_and_totals(self):
        CHECKERS["TCP"] = lambda _: CheckOutcome(True, "up", 1, "same")
        engine, store = self._engine()
        engine.execute_round()
        replacement = ScoringEngine(engine.config, ScoreStore(self.root / "scores.db"), self.root)
        record = replacement.execute_round()
        self.assertEqual(record.number, 2)
        self.assertEqual(record.totals, {"Blue": 20})

    def test_disabled_baselines_score_availability(self):
        CHECKERS["TCP"] = lambda _: CheckOutcome(True, "up", 1, "variable")
        engine, _ = self._engine(baseline_mode="disabled")
        result = engine.execute_round().results[0]
        self.assertEqual(result.baseline_state, "disabled")
        self.assertEqual(result.points, 10)

    def test_status_and_uptime_matrices_align_logical_services(self):
        services = [
            ServiceConfig("t1-web", "Team 1", "TCP", "127.0.0.1", 1001, options={"matrix_key": "Web"}),
            ServiceConfig("t1-dns", "Team 1", "TCP", "127.0.0.1", 1002, options={"matrix_key": "DNS"}),
            ServiceConfig("t2-web", "Team 2", "TCP", "127.0.0.1", 2001, options={"matrix_key": "Web"}),
            ServiceConfig("t2-dns", "Team 2", "TCP", "127.0.0.1", 2002, options={"matrix_key": "DNS"}),
        ]
        availability = {service.id: True for service in services}
        CHECKERS["TCP"] = lambda service: CheckOutcome(
            availability[service.id],
            "up" if availability[service.id] else "down",
            1,
            "stable-%s" % service.id if availability[service.id] else None,
        )
        config = AppConfig(services=services, baseline_mode="disabled")
        store = ScoreStore(self.root / "matrix.db")
        engine = ScoringEngine(config, store, self.root)
        engine.execute_round()
        availability["t2-dns"] = False
        engine.execute_round()

        status = engine.status_matrix()
        self.assertEqual(status["teams"], ["Team 1", "Team 2"])
        self.assertEqual([item["key"] for item in status["services"]], ["Web", "DNS"])
        states = {(cell["team"], cell["service"]): cell["state"] for cell in status["cells"]}
        self.assertEqual(states[("Team 2", "DNS")], "down")
        self.assertEqual(states[("Team 1", "DNS")], "up")

        all_time = engine.uptime_matrix()
        percentages = {(cell["team"], cell["service"]): cell["uptime_percent"] for cell in all_time["cells"]}
        self.assertEqual(all_time["round_count"], 2)
        self.assertEqual(percentages[("Team 2", "DNS")], 50.0)
        self.assertEqual(percentages[("Team 1", "Web")], 100.0)
        latest = engine.uptime_matrix(1)
        latest_percentages = {(cell["team"], cell["service"]): cell["uptime_percent"] for cell in latest["cells"]}
        self.assertEqual(latest["round_count"], 1)
        self.assertEqual(latest_percentages[("Team 2", "DNS")], 0.0)


if __name__ == "__main__":
    unittest.main()
