from __future__ import annotations

import concurrent.futures
import csv
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import checkers  # noqa: F401 - registers built-in checkers
from .checkers.base import get_checker
from .models import AppConfig, CheckOutcome, RoundRecord, ServiceConfig, ServiceResult
from .storage import ScoreStore


LOGGER = logging.getLogger(__name__)
RoundListener = Callable[[RoundRecord], None]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScoringEngine:
    def __init__(self, config: AppConfig, store: ScoreStore, outdir: str | Path):
        self.config = config
        self.store = store
        self.outdir = Path(outdir).resolve()
        self.outdir.mkdir(parents=True, exist_ok=True)
        self._stop = threading.Event()
        self._state_lock = threading.RLock()
        self._listeners: List[RoundListener] = []
        self._baselines = store.load_baselines()
        self._last_results: List[ServiceResult] = []
        self._last_updated: Optional[str] = None
        self._running = False

    def add_listener(self, listener: RoundListener) -> None:
        self._listeners.append(listener)

    def stop(self) -> None:
        self._stop.set()

    @property
    def is_running(self) -> bool:
        with self._state_lock:
            return self._running

    def run_check(self, service: ServiceConfig) -> ServiceResult:
        timestamp = utc_now()
        checker = get_checker(service.type)
        if checker is None:
            outcome = CheckOutcome(False, "No checker registered for %s" % service.type, None, None)
        else:
            try:
                outcome = checker(service)
            except Exception as exc:  # checker isolation is a scoring invariant
                LOGGER.exception("Checker %s crashed", service.id)
                outcome = CheckOutcome(False, "Checker crashed: %s" % exc, None, None)
        return ServiceResult(
            id=service.id,
            team=service.team,
            type=service.type,
            host=service.host,
            port=service.port,
            passed=outcome.passed,
            accurate=None,
            points=0,
            message=outcome.message,
            latency_ms=outcome.latency_ms,
            fingerprint=outcome.fingerprint,
            timestamp=timestamp,
            details=outcome.details,
        )

    def _score(self, service: ServiceConfig, result: ServiceResult) -> None:
        if self.config.baseline_mode == "disabled":
            result.baseline_state = "disabled"
            result.points = service.weight if result.passed else 0
            return

        baseline = self._baselines.get(service.id)
        if baseline is None and result.passed and result.fingerprint:
            self._baselines[service.id] = result.fingerprint
            self.store.save_baseline(service.id, result.fingerprint, result.timestamp)
            result.baseline_state = "learned"
            result.accurate = None
            result.points = service.weight if self.config.score_first_success else 0
            return
        if baseline is None:
            result.baseline_state = "pending"
            result.points = service.weight if result.passed and self.config.score_first_success else 0
            return
        if result.fingerprint is None:
            result.baseline_state = "unavailable"
            result.accurate = False if result.passed else None
            result.points = 0
            return
        result.accurate = result.fingerprint == baseline
        result.baseline_state = "match" if result.accurate else "mismatch"
        result.points = service.weight if result.passed and result.accurate else 0
        if result.passed and not result.accurate:
            result.message += " (content baseline mismatch)"

    def execute_round(self) -> RoundRecord:
        services = self.config.enabled_services
        number = self.store.next_round_number()
        started_at = utc_now()
        results: List[ServiceResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.config.max_workers, max(1, len(services)))) as executor:
            futures = {executor.submit(self.run_check, service): service for service in services}
            for future in concurrent.futures.as_completed(futures):
                service = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    LOGGER.exception("Uncaught scoring failure for %s", service.id)
                    result = ServiceResult(
                        id=service.id,
                        team=service.team,
                        type=service.type,
                        host=service.host,
                        port=service.port,
                        passed=False,
                        accurate=None,
                        points=0,
                        message="Scoring failure: %s" % exc,
                        latency_ms=None,
                        fingerprint=None,
                        timestamp=utc_now(),
                    )
                self._score(service, result)
                results.append(result)
        results.sort(key=lambda item: (item.team.lower(), item.id.lower()))
        finished_at = utc_now()
        self.store.record_round(number, started_at, finished_at, results)
        totals = self.store.totals()
        record = RoundRecord(number, started_at, finished_at, results, totals)
        self._write_compatibility_exports(record)
        with self._state_lock:
            self._last_results = list(results)
            self._last_updated = finished_at
        for listener in list(self._listeners):
            try:
                listener(record)
            except Exception:
                LOGGER.exception("Round listener failed")
        return record

    def run(self, rounds: int = 0, interval_seconds: float | None = None) -> None:
        interval = self.config.interval_seconds if interval_seconds is None else interval_seconds
        completed = 0
        with self._state_lock:
            self._running = True
        self._stop.clear()
        try:
            while not self._stop.is_set():
                record = self.execute_round()
                completed += 1
                LOGGER.info("Round %d complete: %s", record.number, record.totals)
                if rounds and completed >= rounds:
                    break
                if self._stop.wait(max(0.1, interval)):
                    break
        finally:
            with self._state_lock:
                self._running = False

    def start_background(self, rounds: int = 0, interval_seconds: float | None = None) -> threading.Thread:
        thread = threading.Thread(
            target=self.run,
            kwargs={"rounds": rounds, "interval_seconds": interval_seconds},
            name="scoring-engine",
            daemon=True,
        )
        thread.start()
        return thread

    def snapshot(self) -> Dict[str, Any]:
        with self._state_lock:
            cached_results = [result.as_dict() for result in self._last_results]
            last_updated = self._last_updated
            running = self._running
        results = cached_results or self.store.latest_results()
        configured = {service.id: service for service in self.config.services}
        for result in results:
            service = configured.get(result["id"])
            if service:
                result["name"] = service.display_name
                result["weight"] = service.weight
        result_ids = {result["id"] for result in results}
        for service in self.config.services:
            if service.id not in result_ids:
                waiting = service.public_dict()
                waiting.update({
                    "passed": None,
                    "accurate": None,
                    "points": 0,
                    "message": "Disabled" if not service.enabled else "Waiting for first round",
                    "latency_ms": None,
                    "timestamp": None,
                    "baseline_state": "disabled" if not service.enabled else "pending",
                    "details": {},
                })
                results.append(waiting)
        return {
            "running": running,
            "last_round": self.store.last_round_number(),
            "last_updated": last_updated or (results[0].get("timestamp") if results else None),
            "totals": [
                {"rank": index + 1, "team": team, "points": points}
                for index, (team, points) in enumerate(sorted(self.store.totals().items(), key=lambda item: (-item[1], item[0].lower())))
            ],
            "results": sorted(results, key=lambda item: (str(item["team"]).lower(), str(item["id"]).lower())),
        }

    def _matrix_catalog(self):
        columns: List[Dict[str, Any]] = []
        service_keys: Dict[str, str] = {}
        known: Dict[str, str] = {}
        for index, service in enumerate(self.config.services):
            key = str(service.option("matrix_key") or service.display_name)
            folded_key = key.casefold()
            canonical_key = known.get(folded_key, key)
            service_keys[service.id] = canonical_key
            if folded_key in known:
                continue
            known[folded_key] = key
            columns.append({
                "key": key,
                "label": str(service.option("matrix_label") or key),
                "type": service.type,
                "order": int(service.option("matrix_order", index)),
            })
        columns.sort(key=lambda item: (item["order"], item["label"].lower()))
        for column in columns:
            column.pop("order", None)
        teams = sorted({service.team for service in self.config.services}, key=str.lower)
        return teams, columns, service_keys

    def status_matrix(self) -> Dict[str, Any]:
        teams, columns, service_keys = self._matrix_catalog()
        snapshot = self.snapshot()
        cells = []
        for result in snapshot["results"]:
            key = service_keys.get(result["id"])
            if key is None:
                continue
            if result.get("message") == "Disabled":
                state = "disabled"
            elif result.get("passed") is True:
                state = "up"
            elif result.get("passed") is False:
                state = "down"
            else:
                state = "waiting"
            cells.append({
                "team": result["team"],
                "service": key,
                "state": state,
                "passed": result.get("passed"),
                "message": result.get("message"),
                "latency_ms": result.get("latency_ms"),
                "timestamp": result.get("timestamp"),
            })
        return {
            "round": snapshot["last_round"],
            "last_updated": snapshot["last_updated"],
            "teams": teams,
            "services": columns,
            "cells": cells,
        }

    def uptime_matrix(self, round_limit: int = 0) -> Dict[str, Any]:
        teams, columns, service_keys = self._matrix_catalog()
        aggregate = self.store.uptime_stats(round_limit)
        cells = []
        for result in aggregate.pop("results"):
            key = service_keys.get(result["id"])
            if key is None:
                continue
            cells.append({
                "team": result["team"],
                "service": key,
                "checks": result["checks"],
                "passed_checks": result["passed_checks"],
                "uptime_percent": result["uptime_percent"],
                "avg_latency_ms": result["avg_latency_ms"],
            })
        return {**aggregate, "teams": teams, "services": columns, "cells": cells}

    def _write_compatibility_exports(self, record: RoundRecord) -> None:
        csv_path = self.outdir / "scores.csv"
        exists = csv_path.exists()
        with csv_path.open("a", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            if not exists:
                writer.writerow(["round", "timestamp", "team", "service_id", "type", "host", "port", "passed", "accurate", "points", "message", "latency_ms", "total_points"])
            for result in record.results:
                writer.writerow([
                    record.number, result.timestamp, result.team, result.id, result.type, result.host, result.port,
                    int(result.passed), "" if result.accurate is None else int(result.accurate), result.points,
                    result.message, "" if result.latency_ms is None else result.latency_ms, record.totals.get(result.team, 0),
                ])
        jsonl_path = self.outdir / "round_details.jsonl"
        with jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "round": record.number,
                "started": record.started_at,
                "finished": record.finished_at,
                "results": [result.as_dict(include_fingerprint=True) for result in record.results],
                "totals": record.totals,
            }, sort_keys=True) + "\n")
