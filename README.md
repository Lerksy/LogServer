# MikroTik LogServer

A dependency-free Python log collector for MikroTik RouterOS. It accepts native
UDP syslog and JSON over HTTP, stores normalized events in SQLite, and serves a
live searchable web console.

## Why there are two listening ports

RouterOS's built-in remote logging action sends **syslog**, not HTTP requests.
The service therefore listens on:

- `8080/tcp` — web UI, HTTP ingestion API, and live event stream
- `5514/udp` — native RouterOS/syslog ingestion

Both transports write to the same SQLite database and appear immediately in the
same browser view. The HTTP endpoint is available for scripts, webhooks, or other
services, while UDP syslog is the direct RouterOS integration.

## Start it

Python 3.11 or newer is the only requirement.

```bash
python3 -m logserver
```

Then open <http://localhost:8080>. Data is stored in `data/logs.db`.

Configuration can be supplied through environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOGSERVER_DB` | `data/logs.db` | SQLite database path |
| `LOGSERVER_HTTP_HOST` | `0.0.0.0` | HTTP bind address |
| `LOGSERVER_HTTP_PORT` | `8080` | HTTP port |
| `LOGSERVER_SYSLOG_HOST` | `0.0.0.0` | UDP syslog bind address |
| `LOGSERVER_SYSLOG_PORT` | `5514` | UDP syslog port |
| `LOGSERVER_INGEST_TOKEN` | unset | Optional HTTP write token |
| `LOGSERVER_MAX_BODY_BYTES` | `1048576` | Maximum HTTP request size |

Equivalent command-line options are shown by `python3 -m logserver --help`.
Use `--no-syslog` when only the HTTP service is wanted.

### Docker Compose

Change the example ingest token in `compose.yaml`, then run:

```bash
docker compose up --build -d
```

The named `log-data` volume keeps the SQLite database across container updates.

## Configure RouterOS

Replace `192.0.2.10` with the LogServer machine's LAN address. In a RouterOS
terminal, create one remote action and direct the standard severity topics to it:

```routeros
/system logging action add name=logserver target=remote remote=192.0.2.10 remote-port=5514 remote-log-format=syslog syslog-time-format=bsd-syslog syslog-facility=local0
/system logging add topics=info action=logserver
/system logging add topics=warning action=logserver
/system logging add topics=error action=logserver
/system logging add topics=critical action=logserver
/system logging add topics=debug action=logserver
```

These rules copy matching logs to LogServer; they do not remove the router's
existing memory/disk logging rules. Permit UDP destination port `5514` between
the router and server, but do not expose an unauthenticated syslog port to the
public internet. Debug events can be high volume; omit the final rule if that is
not desirable. RouterOS syntax can vary slightly by release; use
`/system logging action print` and `/system logging print` to verify the result.
The current properties and topic list are documented in the official
[RouterOS logging manual](https://help.mikrotik.com/docs/spaces/ROS/pages/328094/Log).

## HTTP ingestion API

Send one log object or an array of up to 1,000 objects:

```bash
curl -X POST http://localhost:8080/api/logs \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer change-me' \
  -d '{
    "timestamp": "2026-09-20T21:15:00Z",
    "source": "router-1",
    "severity": "warning",
    "topics": ["firewall", "input"],
    "message": "connection dropped",
    "metadata": {"interface": "ether1"}
  }'
```

The token is required only when `LOGSERVER_INGEST_TOKEN` is set. It can also be
sent as `X-API-Key`. Read endpoints are intentionally unauthenticated for a
trusted LAN deployment:

- `GET /api/health`
- `GET /api/logs?q=...&minimum_severity=warning&limit=100&before_id=123`
- `GET /api/stream` (Server-Sent Events)

Put the service behind an authenticated HTTPS reverse proxy before exposing the
web console beyond a trusted network.

## Search language

Plain text searches message, topics, source, severity, and facility. Field
filters support `:`, `=`, `!=`, `>`, `>=`, `<`, and `<=`. Adjacent terms imply
`AND`.

```text
login failed
severity:error topic:firewall
(severity:error OR severity:critical) AND source:router-1
NOT message:"user logged out"
id>=1000 transport:syslog
time>=2026-09-20T00:00:00Z
```

Available fields: `id`, `time`, `event_at`, `received`, `received_at`, `source`,
`facility`, `severity` (or `level`), `topic` (or `topics`), `message`, and
`transport`.

The web console remembers its search query, minimum severity, and logs-per-page
setting in that browser's local storage.

## Tests

The suite uses only the standard library:

```bash
python3 -m unittest discover -v
```

The code is split into configuration, validation, syslog parsing, persistence,
search compilation, event broadcasting, HTTP delivery, and application startup
modules so each concern can be tested independently.
