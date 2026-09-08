from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .checkers import supported_types
from .config import ConfigError, load_config
from .engine import ScoringEngine
from .presets import PresetRegistry
from .storage import ScoreStore
from .web import ScoreboardServer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="EKU CCDC scoring engine and live scoreboard",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--config", default="config.json", help="JSON configuration file")
    parser.add_argument("--outdir", default="out", help="Database and export directory")
    parser.add_argument("--database", default=None, help="Override the SQLite database filename")
    parser.add_argument("--interval", type=float, default=None, help="Seconds between rounds (overrides config)")
    parser.add_argument("--rounds", type=int, default=0, help="Rounds to run; zero continues until interrupted")
    parser.add_argument("--once", action="store_true", help="Run one round without starting the Web UI")
    parser.add_argument("--no-web", action="store_true", help="Run the scorer without the Web UI")
    parser.add_argument("--host", default="0.0.0.0", help="Web UI listen address")
    parser.add_argument("--port", type=int, default=8080, help="Web UI listen port")
    parser.add_argument("--check-config", action="store_true", help="Validate configuration and exit")
    parser.add_argument("--list-presets", action="store_true", help="Print built-in preset names and exit")
    parser.add_argument("--reset-baselines", action="store_true", help="Delete learned content baselines before starting")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    return parser


def _print_round(record) -> None:
    print("Round %d complete" % record.number)
    for team, points in sorted(record.totals.items(), key=lambda item: (-item[1], item[0])):
        round_points = sum(result.points for result in record.results if result.team == team)
        up = sum(1 for result in record.results if result.team == team and result.passed)
        total = sum(1 for result in record.results if result.team == team)
        print("  %-24s +%4d  cumulative=%-6d services=%d/%d" % (team, round_points, points, up, total))


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.list_presets:
        for name in PresetRegistry().names():
            print(name)
        return 0
    if args.rounds < 0:
        parser.error("--rounds cannot be negative")
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    if args.interval is not None and args.interval <= 0:
        parser.error("--interval must be greater than zero")

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print("Configuration error: %s" % exc, file=sys.stderr)
        return 2
    if args.check_config:
        print("Configuration valid: %d services, %d enabled" % (len(config.services), len(config.enabled_services)))
        print("Registered checkers: %s" % ", ".join(supported_types()))
        return 0

    outdir = Path(args.outdir).expanduser().resolve()
    database_name = args.database or config.database_name
    database_path = Path(database_name)
    if not database_path.is_absolute():
        database_path = outdir / database_path
    store = ScoreStore(database_path)
    if args.reset_baselines:
        print("Removed %d learned baseline(s)." % store.clear_baselines())
    engine = ScoringEngine(config, store, outdir)
    engine.add_listener(_print_round)
    rounds = 1 if args.once else args.rounds
    no_web = args.no_web or args.once
    if no_web:
        try:
            engine.run(rounds=rounds, interval_seconds=args.interval)
        except KeyboardInterrupt:
            engine.stop()
        return 0

    server = ScoreboardServer(args.host, args.port, engine)
    scorer_thread = engine.start_background(rounds=rounds, interval_seconds=args.interval)
    display_host = "127.0.0.1" if args.host in {"0.0.0.0", "::"} else args.host
    print("Web UI: http://%s:%d" % (display_host, server.address[1]))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping scoring engine...")
    finally:
        engine.stop()
        server.shutdown()
        scorer_thread.join(timeout=max(2.0, config.timeout_seconds + 1.0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
