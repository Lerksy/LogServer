# MikroTik LogServer

A dependency-free Python log collector for MikroTik RouterOS. It accepts UDP
syslog plus CEF over TCP or TLS, as well as JSON over HTTP, stores normalized
events in SQLite, and serves a live searchable web console.

## Listening ports

RouterOS's built-in remote logging action sends **syslog**, not HTTP requests.
The service listens on all of these transports simultaneously:

- `8080/tcp` — web UI, HTTP ingestion API, and live event stream
- `5514/udp` — native RouterOS syslog or CEF ingestion
- `5514/tcp` — newline-delimited CEF ingestion
- `6514/tcp` — newline-delimited CEF over TLS

All transports write to the same SQLite database and appear immediately in the
same browser view. Different routers can use different transports concurrently.

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
| `LOGSERVER_SYSLOG_TCP_PORT` | `5514` | TCP CEF port |
| `LOGSERVER_SYSLOG_TLS_PORT` | `6514` | TLS CEF port |
| `LOGSERVER_TLS_CERTFILE` | unset | TLS certificate path |
| `LOGSERVER_TLS_KEYFILE` | unset | TLS private-key path |
| `LOGSERVER_TLS_AUTO_GENERATE` | `false` | Generate a self-signed certificate when both paths do not exist |
| `LOGSERVER_MAX_SYSLOG_BYTES` | `262144` | Maximum framed CEF event size |
| `LOGSERVER_INGEST_TOKEN` | unset | Optional HTTP write token |
| `LOGSERVER_MAX_BODY_BYTES` | `1048576` | Maximum HTTP request size |

Equivalent command-line options are shown by `python3 -m logserver --help`.
Use `--no-udp`, `--no-tcp`, or `--no-tls` to disable individual listeners.
`--no-syslog` remains an alias for `--no-udp`.

### Docker Compose

Optionally export an HTTP ingest token, then start the detached service:

```bash
docker volume create logserver_log-data
export LOGSERVER_INGEST_TOKEN='change-me'
docker compose up --build -d
```

Leave the variable unset if HTTP ingestion should remain unauthenticated. The
external `logserver_log-data` volume keeps the SQLite database across container
updates and Compose teardown. It is not removed by `docker compose down
--volumes`. Deleting it requires the explicit destructive command `docker
volume rm logserver_log-data` and permanently removes the containerized database.

Compose enables all three RouterOS transports. On its first start, it generates
a self-signed TLS certificate in `/data/tls`; the certificate and private key
persist in the external data volume. Custom certificate paths can instead be
provided through `LOGSERVER_TLS_CERTFILE` and `LOGSERVER_TLS_KEYFILE` and mounted
into the container.

#### Updating and deploying source changes

Source files are copied into the Docker image, so editing them does not change
the running container until it is rebuilt. From the project directory:

```bash
# 1. Edit the Python, HTML, CSS, or JavaScript files.
python3 -m unittest discover -v

# 2. Build the changed image and replace the container in the background.
sudo docker compose up --build -d

# 3. Verify the deployment.
sudo docker compose ps
curl -fsS http://127.0.0.1:8080/api/health
sudo docker compose logs --no-color --tail=100
```

The container replacement keeps `logserver_log-data` attached, so logs,
Telegram credentials, and alert rules survive deployments. The live database
is in that Docker volume; the old workspace file `data/logs.db` is only a
pre-Docker snapshot and should not be copied over the volume during updates.

## Configure RouterOS

Replace `192.0.2.10` with the LogServer machine's LAN address. In a RouterOS
terminal, choose one transport for that router and direct the standard severity
topics to its action. Different routers may use different transports at the same
time. Do not configure several transports for the same rules unless duplicate
entries are intentional.

### UDP syslog

```routeros
/system logging action add name=logserver target=remote remote=192.0.2.10 remote-port=5514 remote-log-format=syslog syslog-time-format=bsd-syslog syslog-facility=local0 add-topics-string=yes
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
[RouterOS logging manual](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log/).

`add-topics-string=yes` is important: standard BSD syslog does not otherwise
carry RouterOS topic names. For an existing action, enable it with:

```routeros
/system logging action set [find where name=logserver] add-topics-string=yes
```

### Reliable TCP CEF

RouterOS 7.18 or newer can queue up to 1,000 entries in memory while the TCP
connection or networking is unavailable. This covers RouterOS entries produced
after its logging subsystem starts but before networking finishes initializing.
The queue is volatile and is lost if the router reboots again before delivery.

```routeros
/system logging action add name=logservertcp target=remote remote=192.0.2.10 remote-port=5514 remote-protocol=tcp remote-log-format=cef cef-event-delimiter="\r\n" syslog-time-format=iso8601
/system logging add topics=info action=logservertcp
/system logging add topics=warning action=logservertcp
/system logging add topics=error action=logservertcp
/system logging add topics=critical action=logservertcp
```

CEF carries the router identity, model, RouterOS version, topics, severity, and
structured event fields. LogServer preserves these fields in record metadata.

### TLS CEF

TLS uses the same CEF framing and in-memory recovery behavior on port 6514:

```routeros
/system logging action add name=logservertls target=remote remote=192.0.2.10 remote-port=6514 remote-protocol=tls remote-log-format=cef cef-event-delimiter="\r\n" syslog-time-format=iso8601 check-certificate=no
/system logging add topics=info action=logservertls
/system logging add topics=warning action=logservertls
/system logging add topics=error action=logservertls
/system logging add topics=critical action=logservertls
```

`check-certificate=no` encrypts the connection but does not authenticate the
server. For authentication, copy `/data/tls/server.crt` from the container,
import and trust it on the router, then enable `check-certificate=yes`; or use a
certificate issued by a CA the router already trusts.

Permit `5514/udp`, `5514/tcp`, and `6514/tcp` only from trusted router networks.

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

## Telegram alert management

Open <http://localhost:8080/manage> (or use **Manage alerts** in the live
console) to configure the Telegram destination and custom alert rules. The
management page opens separately from the live log view.

Create a bot with BotFather, add it to the intended chat, then save its bot
token and the target `chat_id`. The token and chat ID are stored in the same
SQLite database as the logs. The HTTP API never returns the saved token, but it
is not encrypted at rest, so protect the database file and its backups. Use the
**Send test** button after saving the settings. Telegram's accepted chat IDs and
formatting modes are described by the official
[Bot API `sendMessage` documentation](https://core.telegram.org/bots/api#sendmessage).

Each alert rule can combine:

- The normal LogServer query language, such as
  `topic:firewall AND severity:warning`.
- An optional Python regular expression applied to either the normalized
  message or the raw syslog packet.
- A message template using log fields and captured values.
- Plain text, Telegram HTML, or Telegram MarkdownV2 formatting.
- A batching window and a post-delivery cooldown.
- Up to 20 additional Telegram chat IDs that receive a copy of each batch.

The Telegram settings section defines the primary chat. A rule's **Additional
Telegram chat IDs** field accepts one destination per line, or a comma-separated
list. Every unique destination receives the same rendered batch through the
configured bot; duplicate entries and a repeated primary chat ID are sent only
once. The bot must already have permission to post in every listed chat. A
failure for one destination does not prevent attempts to the remaining chats,
and the rule reports which destination failed.

For example, regex `src=(?P<src_ip>\d+\.\d+\.\d+\.\d+)` exposes `{src_ip}`
to the template. Numbered captures are available as `{group1}`, `{group2}`, and
so on. Built-in fields include `{id}`, `{time}`, `{received_at}`, `{event_at}`,
`{source}`, `{facility}`, `{severity}`, `{topics}`, `{message}`, `{raw}`,
`{transport}`, and `{count}`. `{time}` uses the event timestamp supplied by the router and
falls back to LogServer's receipt timestamp when the event timestamp is absent.
It is formatted for messages as `21 Sep 2026 · 02:12:42`; the exact normalized
values remain available through `{event_at}` and `{received_at}`.
Captured and built-in values are escaped when HTML or MarkdownV2 formatting is
selected; markup written directly in the template remains active.

### IP enrichment

An alert can enrich one named regex capture through either
[ipapi.co](https://ipapi.co/api/) or [2ip.io](https://2ip.io/api-docs/). For
example, after capturing an address as `(?P<src_ip>...)`, enter `src_ip` in the
rule's **IP enrichment** field and select the provider. The following fields
then become available in the message template:

- `{ip_country}` — country name.
- `{ip_city}` — city name; omit it from the template when it is not useful.
- `{ip_company}` — network owner or organization.
- `{ip_abuse_count}` — number of 2ip.io abuse reports.
- `{ip_abuse_summary}` — unique abuse descriptions, or the reason they are
  unavailable.
- `{ip_abuse_last_seen}` — newest report timestamp returned by 2ip.io.

Successful responses are cached in SQLite for 30 days. Failed lookups are
cached for one hour, requests are spaced at least one second apart, and cache
keys include both the provider and IP address. Existing ipapi.co cache entries
are migrated automatically. Invalid, private, loopback, link-local, and other
non-public addresses are never sent to either external service. If a lookup is
unavailable, its fields render as `Unknown` and the alert is still delivered.

2ip.io geolocation currently works without a token, but its abuse endpoint
requires one. Store the token in **IP intelligence services** on the management
page; it is kept in SQLite and never returned by the HTTP API. Without a token,
2ip.io still supplies location and ASN data while `{ip_abuse_count}` renders as
`Unavailable` and `{ip_abuse_summary}` as `2ip token required`. ipapi.co does
not provide the abuse fields, so those fields are also marked unavailable when
that provider is selected. Changing or removing the 2ip.io token invalidates
its cached results so abuse data can be refreshed.

Each rule can send `en`, `ua`, `de`, or `ru` through 2ip.io's `lang` argument.
The language applies to its geolocation response, and each language has a
separate cache entry. Because the country filter evaluates the localized
country name, update an exact-name filter when changing language—for example,
`^Ukraine$` for English or `^Україна$` for Ukrainian. The language setting is
ignored when ipapi.co is selected.

Enabling enrichment sends the captured public IP address to the selected
provider. Geolocation is approximate and should not be treated as a precise
physical location.

Example body:

```text
• {src_ip}:{src_port} — {ip_country}, {ip_city} — {ip_company}
  Abuse reports: {ip_abuse_count} ({ip_abuse_summary})
```

To filter enriched entries before they are added to a batch, enter a
case-insensitive regular expression in **Country filter** and select either
**Keep matches** or **Exclude matches**. Match the full country name when an
exact filter is intended, for example:

```text
^(United Kingdom|Germany|France)$
```

Filtering is applied separately to every log entry after IP enrichment. The
batch header, body, footer, and `{count}` are then built only from the remaining
entries. If no entries remain, no Telegram message is sent. `Unknown` is the
country value used when enrichment fails, so it can be explicitly included or
excluded by the filter.

Use `[[body]]` and `[[/body]]` to make a compact batch with one header, a
repeated body, and one footer:

```text
🚨 <b>DVR connection attempts on {source}</b>
<blockquote expandable>
[[body]]
• <code>{src_ip}:{src_port}</code>
[[/body]]
</blockquote>
<i>{count} attempts in this batch</i>
```

Everything before `[[body]]` and after `[[/body]]` is rendered once using the
first matching log. The content between the markers is rendered for each match
and joined with a single newline. This lets an HTML `<blockquote expandable>`
open in the header and close in the footer. Select the HTML formatting mode for
Telegram tags. The closing marker is optional for backward compatibility;
without it, everything after `[[body]]` is the repeated body. Templates without
either marker retain the original behavior, where the entire template repeats
and entries are separated by a blank line. `{count}` is resolved when the batch
is sent and reports the number of repeated entries in that Telegram message.
Immediate, non-batched notifications use a count of `1`; automatically split
messages report the count for their individual chunk.

### Conditional message blocks

Templates can conditionally include text with `[[if ...]]`, optional
`[[else]]`, and `[[/if]]`. A bare field checks whether useful data is available;
empty values plus `Unknown` and `Unavailable` count as unavailable, while `0`
remains an available value:

```text
[[if ip_abuse_count]]
• Abuse reports: {ip_abuse_count}
• Summary: {ip_abuse_summary}
[[else]]
• Abuse information unavailable
[[/if]]
```

Conditions can use any field available to that rule and may be nested. Supported
forms are:

```text
[[if field]]                         available
[[if not field]]                     unavailable
[[if severity == error]]             equality
[[if ip_country != Ukraine]]         inequality
[[if ip_abuse_count > 0]]            numeric comparison
[[if message contains denied]]       substring
[[if ip_country matches ^(UA|PL)$]]  Python regular expression
```

The other numeric operators are `>=`, `<`, and `<=`. Conditional blocks must be
fully contained in the header, repeated body, or footer; they cannot open in one
batch section and close in another. Body conditions are evaluated separately for
each entry. Header and footer conditions use the first entry in the batch.

Consecutive matching logs are collected into one Telegram message. The batch
is sent when a nonmatching log arrives or no further match arrives during the
configured batch window. Set the window to `0` for immediate individual
messages. A batch is split automatically before Telegram's 4,096-character
message limit. The management page reports delivery errors and counts delivered
batches rather than individual log rows.

The management API and page intentionally have no built-in login, matching the
read-only live console's trusted-LAN model. Do not expose port `8080` directly
to the internet; use an authenticated HTTPS reverse proxy if remote access is
needed. The management endpoints are under `/api/admin/telegram`,
`/api/admin/ip-services`, and `/api/admin/rules`.

## Tests

The suite uses only the standard library:

```bash
python3 -m unittest discover -v
```

The code is split into configuration, validation, syslog parsing, persistence,
search compilation, event broadcasting, HTTP delivery, and application startup
modules so each concern can be tested independently.
