# EKU CCDC Scoring Engine

A service-availability and content-integrity scoring platform for Eastern Kentucky University's Collegiate Cyber Defense Competition team. Version 2 replaces the original single-file program with a modular checker registry, durable SQLite scoring, reusable configuration presets, and a responsive operations dashboard.

## What it covers

The base installation uses Python's standard library and supports:

| Area | Checks |
| --- | --- |
| Web and SIEM | HTTP, HTTPS, Splunk Web, and Wazuh Dashboard; status/content assertions, SNI, host headers, certificates, and stable fingerprints |
| Email | SMTP, submission, SMTPS, POP3/POP3S, and IMAP/IMAPS; optional authentication and STARTTLS |
| File and remote access | FTP, explicit/implicit FTPS, SSH banner or optional authenticated SSH, RDP negotiation, and SMB2 negotiation |
| Infrastructure | DNS A/AAAA/CNAME/MX/NS/PTR/SRV/TXT queries, LDAP/LDAPS/StartTLS binds, and customizable TCP exchanges |

All checkers perform a protocol-native operation. RDP and SMB checks negotiate their protocols instead of treating an open TCP port as a passing service.

## Requirements

- Python 3.10 or newer. Python 3.12 is recommended.
- No required third-party runtime packages.
- `paramiko` is optional when an SSH service sets `require_auth: true`.

The Python 3.7 installation used by the legacy project is no longer supported. Install a current Python release before running version 2.

## Quick start

Validate the existing legacy-style configuration:

```powershell
python scoring_engine.py --config config.json --check-config
```

Run one scoring round without the dashboard:

```powershell
python scoring_engine.py --config config.json --outdir out --once
```

Start continuous scoring and the Web UI:

```powershell
python scoring_engine.py --config config.json --outdir out --host 0.0.0.0 --port 8080
```

Open `http://127.0.0.1:8080`. The default interval comes from `interval_seconds` in the configuration.

For an installed command:

```powershell
python -m pip install .
eku-ccdc-scorer --config config.json --outdir out
```

Authenticated SSH checks require the optional extra:

```powershell
python -m pip install ".[ssh-auth]"
```

## Configuration

The current `config.json` remains valid. New configurations should use presets and group checker-specific fields under `options`:

```json
{
  "interval_seconds": 60,
  "timeout_seconds": 6,
  "max_workers": 24,
  "baseline_mode": "learn",
  "score_first_success": true,
  "services": [
    {
      "id": "t1-splunk",
      "name": "Splunk console",
      "team": "Blue Team 1",
      "preset": "splunk-webui",
      "host": "172.25.21.9",
      "weight": 20,
      "options": {
        "host_header": "splunk.allsafe.com",
        "sni": "splunk.allsafe.com"
      }
    }
  ]
}
```

Every service requires `id`, `team`, `host`, and either `preset` or `type`. Optional common fields are `name`, `port`, `weight`, `timeout`, and `enabled`.

### Team status and uptime matrices

The **Status** page presents the latest up/down state for each logical service across every team. The **Uptime** page presents the percentage of persisted checks that were available, with all-time and recent-round windows.

Use the same `matrix_key` for equivalent instances on different teams so they share a column. A team can have only one service in each matrix column:

```json
"services": [
  {"id": "t1-web", "name": "Web", "team": "Blue Team 1", "preset": "web-https", "host": "172.25.21.11", "options": {"matrix_key": "Web", "matrix_order": 1}},
  {"id": "t2-web", "name": "Web", "team": "Blue Team 2", "preset": "web-https", "host": "172.25.22.11", "options": {"matrix_key": "Web", "matrix_order": 1}}
]
```

`matrix_label` optionally changes the displayed column heading without changing the grouping key. When `matrix_key` is omitted, the service `name`—or `id` when no name exists—is used. Uptime measures protocol availability (`passed`) and does not treat a content-baseline mismatch as downtime.

See [config.example.json](config.example.json) for examples covering every requested service family.

### Built-in presets

Run `python scoring_engine.py --list-presets` to print the installed catalog.

| Family | Presets |
| --- | --- |
| Web | `web-http`, `web-https`, `splunk-webui`, `wazuh-webui` |
| Email | `email-smtp`, `email-submission`, `email-smtps`, `email-pop3`, `email-pop3s`, `email-imap`, `email-imaps` |
| File/remote | `ftp`, `ftps-explicit`, `ftps-implicit`, `ssh`, `rdp`, `smb` |
| Infrastructure | `dns`, `ldap`, `ldaps`, `tcp` |

Aliases such as `splunk`, `wazuh`, `smtp`, `https`, and `imap` are also accepted.

### Custom presets

Custom presets can extend built-ins. Nested options are merged, so an instance only needs to override what differs:

```json
{
  "presets": {
    "eku-wazuh": {
      "extends": "wazuh-webui",
      "port": 5601,
      "options": {
        "host_header": "wazuh.allsafe.com",
        "sni": "wazuh.allsafe.com",
        "expected_content": "Wazuh"
      }
    }
  },
  "services": [
    {"id": "t1-wazuh", "team": "Blue Team 1", "preset": "eku-wazuh", "host": "172.25.21.10"}
  ]
}
```

Circular inheritance and unknown preset names are rejected during startup.

### Credentials

Plaintext service credentials are supported and are the expected configuration style for this isolated competition environment:

```json
"options": {
  "username": "employee1",
  "password": "changeme1"
}
```

Environment-variable references remain available as an optional deployment convenience. An exact `${ENV:VARIABLE}` value is replaced at startup and rejected if the variable is unset:

```json
"options": {
  "username": "employee1",
  "password": "${ENV:CCDC_MAIL_PASSWORD}"
}
```

Optional PowerShell example:

```powershell
$env:CCDC_MAIL_PASSWORD = "competition-secret"
python scoring_engine.py --config config.json
```

Whether credentials are literal or environment-backed, the scoreboard API exposes service identity and status but never service `options`, so credentials and custom request headers are not returned to browsers.

### Common checker options

| Checker | Useful options |
| --- | --- |
| HTTP(S) | `path`, `method`, `expected_status`, `expected_content`, `expected_regex`, `host_header`, `sni`, `verify_cert`, `fingerprint_mode`, `body_regex`, `ignore_cookies` |
| DNS | `query_name`, `query_type`, `expected_answers` |
| SMTP/POP3/IMAP | `tls_mode` (`plain`, `starttls`, or `implicit`), `username`, `password`, `verify_cert` |
| FTP | `tls_mode`, `username`, `password`, `verify_cert`, `sni` |
| SSH | `require_auth`, `username`, `password`, `key_file`, `known_hosts` |
| LDAP | `tls_mode`, `bind_dn`, `password`, `verify_cert`, `sni` |
| TCP | `tls`, `send`, `send_encoding`, `read_bytes`, `expected_content`, `expected_regex` |

All service types also accept `matrix_key`, `matrix_label`, and numeric `matrix_order` options for the team comparison pages.

HTTP `expected_status` accepts one status, a list of statuses, or a two-number inclusive range. `fingerprint_mode` can be `status_only`, `status_ctype`, or `full`.

## Scoring and baselines

With `baseline_mode: "learn"`, the engine stores the first successful fingerprint for each service. Later rounds award the service weight only when the service is available and its fingerprint matches. A failed first check cannot become a baseline; the engine keeps waiting for the first successful response.

`score_first_success` controls whether the baseline-learning result earns points. Set `baseline_mode` to `disabled` for availability-only scoring.

To intentionally relearn content after rebuilding competition systems:

```powershell
python scoring_engine.py --config config.json --outdir out --reset-baselines
```

This deletes baselines from the selected SQLite database. It does not delete rounds or totals.

## Persistence and outputs

The output directory contains:

- `scoring.db` — authoritative SQLite rounds, results, cumulative totals, and baselines.
- `scores.csv` — append-only compatibility export.
- `round_details.jsonl` — detailed append-only round export.

SQLite makes scores survive restarts. The legacy `baseline.json` is left untouched and is not imported because version 2 uses newer protocol-specific fingerprint formats. Version 2 safely learns fresh baselines in SQLite. Legacy CSV history is also left intact but is not added to SQLite totals; begin a new output directory for each competition.

## HTTP API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/summary` | Standings, latest results, and engine state |
| `GET /api/v1/rounds?limit=20` | Recent per-team round history |
| `GET /api/v1/matrix/status` | Latest team-by-service up/down matrix |
| `GET /api/v1/matrix/uptime?rounds=25` | Team-by-service uptime; zero or omitted means all rounds |
| `GET /api/v1/presets` | Resolved non-secret preset catalog |
| `GET /api/v1/health` | Lightweight engine health |

The old `/api/totals`, `/api/status`, and `/api/rounds` paths remain available.

## Docker

Build the image and mount a directory containing `config.json`:

```powershell
docker build -t eku-ccdc-scorer .
docker run --rm -p 8080:8080 -v ${PWD}:/data eku-ccdc-scorer
```

Plaintext credentials can remain in the mounted configuration. Docker `--env` or `--env-file` options are also supported when environment-backed values are preferred.

## Development and verification

The test suite uses local simulated services; it does not need access to a competition network:

```powershell
python -m unittest discover -v
```

Tests cover configuration compatibility and validation, baseline scoring, SQLite restart behavior, Web APIs, HTTP content checks, SSH banners, LDAP binds, RDP negotiation, SMB2 negotiation, and customizable TCP exchanges.

See [docs/architecture.md](docs/architecture.md) for component boundaries and extension guidance.
