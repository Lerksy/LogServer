# AGENTS.md

## Project overview

LogServer is a dependency-free Python 3.11+ service for collecting MikroTik
logs. It accepts HTTP JSON, UDP syslog, TCP CEF, and TLS CEF; normalizes all
events into SQLite; streams them to a browser with SSE; and evaluates Telegram
alert rules with batching, retries, templates, and cached IP enrichment.

Keep the implementation modular. Put transport parsing, persistence, HTTP/API,
alerting, enrichment, and browser behavior in their existing modules instead of
growing a single catch-all file.

## Repository map

- `logserver/app.py` wires configuration, storage, alerting, and listeners.
- `logserver/config.py` owns environment-variable defaults and validation.
- `logserver/syslog.py` parses UDP syslog and framed TCP/TLS CEF.
- `logserver/http.py` implements the HTTP API, static routes, and SSE streams.
- `logserver/database.py` stores and queries normalized log records.
- `logserver/search.py` compiles the advanced search language to parameterized
  SQLite predicates.
- `logserver/alerts.py` owns alert rules, batching, Telegram delivery, and the
  persistent delivery queue.
- `logserver/message_template.py` implements conditional templates.
- `logserver/ipintel.py` and `logserver/ipcache.py` own external IP lookups and
  their persistent cache.
- `logserver/static/` contains the dependency-free HTML/CSS/JavaScript pages.
- `tests/` mirrors backend modules with `unittest` tests.
- `compose.yaml` is the production-style local deployment. Its `/data` mount is
  the external `logserver_log-data` Docker volume.

## Development conventions

- Use only the Python standard library unless a new dependency is genuinely
  necessary and explicitly reflected in `pyproject.toml` and the container.
- Preserve the current separation between validation, models, storage,
  services, protocol adapters, and presentation code.
- Use parameterized SQL. Never interpolate request or search values into SQL.
- Keep schema setup and compatible upgrades idempotent so an existing database
  can be opened safely after deployment.
- Store timestamps as normalized UTC ISO 8601 values. Convert to the configured
  `LOGSERVER_TIMEZONE` only for display and rendered notifications.
- Treat external input as untrusted: enforce body/frame limits, validate JSON,
  validate IP addresses before enrichment, and escape values for the selected
  Telegram parse mode.
- Do not let network calls (Telegram or IP intelligence) block ingestion or HTTP
  request handling. Preserve alert order and persistent retry semantics when
  changing notification delivery.
- The frontend uses plain HTML, CSS, and JavaScript with no build step. Keep
  settings that should survive reloads in the existing persistence mechanism,
  and preserve expanded/live-view state across SSE updates.
- When changing an API payload, update both its server handler and all browser
  callers, then add or update integration tests.

## Tests and local checks

Run the complete suite before handing off a change:

```bash
python3 -m unittest discover -v
```

Useful focused commands:

```bash
python3 -m unittest tests.test_syslog -v
python3 -m unittest tests.test_http -v
python3 -m unittest tests.test_alerts -v
python3 -m unittest tests.test_database -v
```

For parser, database, template, batching, retry, or search changes, add a
regression test that fails without the fix. HTTP behavior belongs in
`tests/test_http.py`; use temporary databases rather than the live volume.

To run outside Docker during development:

```bash
python3 -m logserver
```

The default development database is `data/logs.db` and is not the live Docker
database.

## Docker deployment and verification

Source is copied into the image, so changes require a rebuild:

```bash
docker compose up --build -d
docker compose ps
curl -fsS http://127.0.0.1:8080/api/health
docker compose logs --no-color --tail=100 logserver
```

Docker is available to the current user without `sudo`.

The expected listeners are:

- `8080/tcp`: UI, API, and SSE
- `5514/udp`: syslog/CEF
- `5514/tcp`: framed CEF
- `6514/tcp`: framed CEF over TLS

After listener changes, verify both Compose port mappings and actual host
sockets. After UI changes, check the relevant page in a browser when possible,
including live updates and narrow viewport behavior.

## Live-data safety

The authoritative database is `/data/logs.db` inside the container-backed
external volume `logserver_log-data`. The workspace `data/logs.db`, if present,
is only a pre-Docker snapshot.

- Never replace, copy over, delete, recreate, or prune the external volume as
  part of a normal code deployment.
- Do not run destructive SQL against the live database unless the user asks for
  that exact data change and the target has been verified first.
- Prefer read-only queries for diagnosis and statistics.
- Include `logs.db-wal` and `logs.db-shm` when reasoning about on-disk size or
  making a consistent offline copy. A SQLite backup is safer than copying an
  active database file directly.
- `docker compose down` is normally safe because the volume is external, but
  never run `docker volume rm logserver_log-data` or broad Docker prune commands.

## Documentation

Update `README.md` when adding a port, environment variable, API route, search
feature, RouterOS setup requirement, operator workflow, or user-visible alert
template syntax. Keep examples compatible with the deployed Docker setup.
