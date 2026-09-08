"""Manual visual-QA server with deterministic demo scoring data."""

from __future__ import annotations

import tempfile
from pathlib import Path

from ccdc_scorer.checkers.base import CHECKERS
from ccdc_scorer.engine import ScoringEngine
from ccdc_scorer.models import AppConfig, CheckOutcome, ServiceConfig
from ccdc_scorer.storage import ScoreStore
from ccdc_scorer.web import ScoreboardServer


TEAMS = ["Apollo", "Borealis", "Cygnus"]
DEFINITIONS = [
    ("Web", "HTTPS", 443, 20, 11),
    ("Splunk", "HTTPS", 8000, 20, 5),
    ("DNS", "DNS", 53, 15, 7),
    ("Mail", "IMAP", 993, 15, 4),
    ("SSH", "SSH", 22, 10, 6),
    ("SMB", "SMB", 445, 10, 3),
]
SERVICES = [
    ServiceConfig(
        "%s-%s" % (team.lower(), label.lower()),
        team,
        service_type,
        "10.20.%d.%d" % (team_index + 1, service_index + 10),
        port,
        weight=weight,
        name=label,
        options={"matrix_key": label, "matrix_order": service_index},
    )
    for team_index, team in enumerate(TEAMS)
    for service_index, (label, service_type, port, weight, _period) in enumerate(DEFINITIONS)
]


def main() -> None:
    root = Path(tempfile.mkdtemp(prefix="eku-dashboard-qa-"))
    store = ScoreStore(root / "scoring.db")
    round_state = {"number": 0}

    def demo_check(service):
        service_index = next(index for index, item in enumerate(DEFINITIONS) if item[0] == service.name)
        team_index = TEAMS.index(service.team)
        period = DEFINITIONS[service_index][4]
        passed = (round_state["number"] + team_index + service_index * 2) % period != 0
        latency = 42 + len(service.id) * 7
        return CheckOutcome(passed, "%s protocol check %s" % (service.type, "completed" if passed else "failed"), latency, "qa-%s" % service.id if passed else None)

    for service_type in {service.type for service in SERVICES}:
        CHECKERS[service_type] = demo_check
    engine = ScoringEngine(AppConfig(services=SERVICES, interval_seconds=3600, baseline_mode="disabled"), store, root)
    for round_number in range(1, 13):
        round_state["number"] = round_number
        engine.execute_round()
    round_state["number"] = 13
    engine.start_background()
    server = ScoreboardServer("127.0.0.1", 8765, engine)
    print("Dashboard QA: http://127.0.0.1:8765", flush=True)
    try:
        server.serve_forever()
    finally:
        engine.stop()
        server.shutdown()


if __name__ == "__main__":
    main()
