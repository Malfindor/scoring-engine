# Architecture

## Runtime flow

```text
config.json
    │ validation + preset resolution + environment expansion
    ▼
AppConfig ──► ScoringEngine ──► checker registry ──► target services
                  │                    │
                  │ score/baseline     └─ HTTP, mail, DNS, FTP, SSH,
                  │                       LDAP, RDP, SMB, TCP
                  ▼
             SQLite store
              │       │
              │       └─ CSV / JSONL compatibility exports
              ▼
       versioned JSON API ──► dashboard
```

## Component boundaries

- `ccdc_scorer/config.py` validates JSON, resolves built-in/custom presets, normalizes legacy fields, and optionally expands environment-backed credentials. Plaintext credentials remain fully supported for the isolated competition environment.
- `ccdc_scorer/models.py` contains immutable service/application configuration and result records.
- `ccdc_scorer/checkers/` contains isolated protocol implementations. Checkers return availability, a human message, latency, a stable fingerprint, and safe structured details.
- `ccdc_scorer/engine.py` runs checks concurrently, isolates checker failures, learns or compares baselines, assigns points, and publishes round state.
- `ccdc_scorer/storage.py` owns SQLite connections and atomic persistence. Each call owns and closes its connection so the store works correctly on Windows.
- `ccdc_scorer/web.py` exposes read-only APIs and serves the static dashboard with a strict file allowlist and browser security headers.
- `ccdc_scorer/static/` is a dependency-free dashboard. It renders untrusted service fields with DOM `textContent`, not HTML interpolation.

The comparison matrices group service instances with their configured `matrix_key`. Current status comes from the latest result cache/database row, while uptime is calculated from persisted availability results over the requested round window. Content accuracy remains a scoring concern and is intentionally separate from availability uptime.

## Adding a checker

1. Add a module under `ccdc_scorer/checkers/`.
2. Implement a function accepting `ServiceConfig` and returning `CheckOutcome`.
3. Decorate it with `@register("PROTOCOL")`.
4. Import the module in `ccdc_scorer/checkers/__init__.py`.
5. Add the type and default port to `config.py`.
6. Add a non-secret preset to `presets.py` and a simulated protocol test.

A checker must catch expected network/protocol errors and return a failed outcome. The engine provides a final exception boundary so one faulty checker cannot abort a round.

## Fingerprints

Fingerprints should capture stable evidence that the intended service answered, not volatile values such as timestamps, message counts, session cookies, TLS session IDs, or DNS TTLs. A check can pass availability but receive zero points when its fingerprint differs from the learned baseline.

For dynamic web applications, prefer `status_ctype`, `body_regex`, or `ignore_cookies` over hashing an entire response body.

## Concurrency and state

Each round uses a bounded thread pool. Checkers must honor the per-service timeout. The engine stop event interrupts interval waits immediately, while active protocol calls finish within their configured timeout.

SQLite is authoritative. In-memory state is only a latest-round cache for fast dashboard reads. The Web UI uses a threaded HTTP server, and SQLite opens short-lived connections for safe access across scoring and request threads.

## Trust boundary

The scoreboard is read-only and intentionally has no remote configuration or reset endpoint. Competition operators change configuration and reset baselines through local files/CLI access. If the dashboard is exposed outside a trusted scoring network, place it behind an authenticated TLS reverse proxy.
