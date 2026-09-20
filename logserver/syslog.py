from __future__ import annotations

import re
import socketserver
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import LogInput, SEVERITIES_BY_URGENCY
from .service import LogService


SEVERITIES = SEVERITIES_BY_URGENCY
FACILITIES = (
    "kernel", "user", "mail", "daemon", "auth", "syslog", "printer", "news",
    "uucp", "clock", "authpriv", "ftp", "ntp", "audit", "alert", "clock2",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
)

_PRI = re.compile(r"^<(\d{1,3})>(.*)$", re.DOTALL)
_RFC5424 = re.compile(
    r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:-|(?:\[[^\]]*\])+)(?:\s+(.*))?$",
    re.DOTALL,
)
_RFC3164 = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$",
    re.DOTALL,
)


def parse_syslog(data: bytes, peer_ip: str, *, now: datetime | None = None) -> LogInput:
    raw = data.decode("utf-8", errors="replace").strip("\x00\r\n")
    body = raw
    priority = 13  # user.notice when no PRI is supplied
    match = _PRI.match(body)
    if match:
        priority = min(int(match.group(1)), 191)
        body = match.group(2)

    facility_number, severity_number = divmod(priority, 8)
    facility = FACILITIES[facility_number] if facility_number < len(FACILITIES) else f"facility-{facility_number}"
    severity = SEVERITIES[severity_number]
    source = peer_ip
    event_at: str | None = None
    message = body
    metadata: dict[str, Any] = {"peer_ip": peer_ip, "priority": priority}

    rfc5424 = _RFC5424.match(body)
    if rfc5424:
        version, timestamp, hostname, app_name, process_id, message_id, parsed_message = rfc5424.groups()
        source = peer_ip if hostname == "-" else hostname
        event_at = _iso_timestamp(timestamp)
        message = parsed_message or ""
        metadata.update(
            protocol="rfc5424",
            version=version,
            app=None if app_name == "-" else app_name,
            process_id=None if process_id == "-" else process_id,
            message_id=None if message_id == "-" else message_id,
        )
    else:
        rfc3164 = _RFC3164.match(body)
        if rfc3164:
            timestamp, hostname, message = rfc3164.groups()
            source = hostname
            event_at = _rfc3164_timestamp(timestamp, now=now)
            metadata["protocol"] = "rfc3164"
        else:
            metadata["protocol"] = "unknown"

    topics, message = _mikrotik_topics(message)
    return LogInput(
        message=message,
        source=source,
        severity=severity,
        facility=facility,
        topics=topics,
        event_at=event_at,
        raw=raw,
        transport="syslog-udp",
        metadata=metadata,
    )


def _iso_timestamp(value: str) -> str | None:
    if value == "-":
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _rfc3164_timestamp(value: str, *, now: datetime | None = None) -> str | None:
    current = now or datetime.now(timezone.utc)
    try:
        parsed = datetime.strptime(f"{current.year} {value}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    if parsed > current + timedelta(days=1):
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _mikrotik_topics(message: str) -> tuple[list[str], str]:
    head, separator, rest = message.partition(" ")
    candidates = head.split(",")
    known = set(SEVERITIES) | {
        "account", "async", "backup", "bfd", "caps", "certificate", "container",
        "dhcp", "dns", "event", "firewall", "gsm", "hotspot", "interface", "ipsec",
        "ism", "l2tp", "lte", "manager", "mpls", "ntp", "ospf", "ovpn", "packet",
        "ppp", "pppoe", "radius", "route", "script", "snmp", "sstp", "system",
        "telephony", "ups", "web-proxy", "wireguard", "wireless",
    }
    if separator and candidates and all(candidate.lower() in known for candidate in candidates):
        return [candidate.lower() for candidate in candidates], rest
    return [], message


class _SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        server = self.server
        assert isinstance(server, SyslogUDPServer)
        try:
            server.log_service.ingest(parse_syslog(data, self.client_address[0]))
        except Exception as exc:  # Keep malformed datagrams from stopping the UDP server.
            server.on_error(exc)


class SyslogUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], log_service: LogService):
        super().__init__(address, _SyslogHandler)
        self.log_service = log_service

    def on_error(self, error: Exception) -> None:
        print(f"Could not ingest syslog datagram: {error}")

    def start_in_thread(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="syslog-udp", daemon=True)
        thread.start()
        return thread
