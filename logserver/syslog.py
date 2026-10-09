from __future__ import annotations

import re
import ssl
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
MIKROTIK_TOPICS = set(SEVERITIES) | {
    "account", "acme-client", "amt", "async", "backup", "bfd", "bgp", "bridge",
    "calc", "caps", "certificate", "client", "clock", "container", "ddns", "dhcp",
    "discover", "disk", "dns", "dot1x", "dude", "e-mail", "event", "evpn", "fetch",
    "firewall", "gps", "gsm", "health", "hotspot", "igmp-proxy", "interface", "ipsec",
    "iscsi", "isdn", "isis", "kvm", "l2tp", "ldp", "lora", "lte", "manager", "mme",
    "mpls", "mqtt", "mvrp", "natpmp", "netwatch", "ntp", "ospf", "ovpn", "packet",
    "pim", "poe-in", "poe-out", "ppp", "pppoe", "pptp", "ptp", "queue", "radvd",
    "radius", "raw", "read", "rip", "route", "rpki", "rproxy", "rsvp", "script",
    "sertcp", "simulator", "smb", "snmp", "socksify", "ssh", "ssld", "sstp", "state",
    "store", "stp", "system", "telephony", "tftp", "timer", "tr069", "update", "upnp",
    "ups", "vpls", "vrrp", "watchdog", "web-proxy", "wiliot", "wireguard", "wireless",
    "write", "zerotier",
}

_PRI = re.compile(r"^<(\d{1,3})>(.*)$", re.DOTALL)
_RFC5424 = re.compile(
    r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:-|(?:\[[^\]]*\])+)(?:\s+(.*))?$",
    re.DOTALL,
)
_RFC3164 = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$",
    re.DOTALL,
)
_CEF_EXTENSION_KEY = re.compile(r"(?<!\\)(?:^| )([A-Za-z][A-Za-z0-9._-]*)=")
_CEF_BSD_PREFIX = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\S+)$"
)


def parse_syslog(
    data: bytes,
    peer_ip: str,
    *,
    now: datetime | None = None,
    transport: str = "syslog-udp",
) -> LogInput:
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
        transport=transport,
        metadata=metadata,
    )


def parse_remote_message(
    data: bytes,
    peer_ip: str,
    *,
    stream_transport: str = "udp",
    now: datetime | None = None,
) -> LogInput:
    decoded = data.decode("utf-8", errors="replace").strip("\x00\r\n")
    if "CEF:" in decoded:
        return parse_cef(data, peer_ip, now=now, transport=f"cef-{stream_transport}")
    return parse_syslog(data, peer_ip, now=now, transport=f"syslog-{stream_transport}")


def parse_cef(
    data: bytes,
    peer_ip: str,
    *,
    now: datetime | None = None,
    transport: str = "cef-tcp",
) -> LogInput:
    raw = data.decode("utf-8", errors="replace").strip("\x00\r\n")
    cef_start = raw.find("CEF:")
    if cef_start < 0:
        raise ValueError("CEF header is missing")
    prefix = raw[:cef_start].strip()
    parts = _split_cef_header(raw[cef_start:])
    if len(parts) != 8 or not parts[0].startswith("CEF:"):
        raise ValueError("Malformed CEF header")

    cef_version = parts[0][4:]
    vendor, product, device_version, signature_id, name, cef_severity = (
        _cef_unescape(value) for value in parts[1:7]
    )
    extension = parts[7]
    extensions = _parse_cef_extensions(extension)
    event_at, prefix_host = _cef_prefix(prefix, now=now)
    topics = [topic.strip().lower() for topic in name.split(",") if topic.strip()]
    source = extensions.get("dvchost") or prefix_host or extensions.get("dvc") or peer_ip
    message = extensions.get("msg", name)
    severity = _cef_normalized_severity(topics, cef_severity)

    metadata: dict[str, Any] = {
        "peer_ip": peer_ip,
        "protocol": "cef",
        "cef_version": cef_version,
        "vendor": vendor,
        "product": product,
        "device_version": device_version,
        "signature_id": signature_id,
        "cef_severity": cef_severity,
        "device_address": extensions.get("dvc"),
        "extensions": extensions,
    }
    return LogInput(
        message=message,
        source=source,
        severity=severity,
        topics=topics,
        event_at=event_at,
        raw=raw,
        transport=transport,
        metadata=metadata,
    )


def _split_cef_header(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "|" and len(parts) < 7:
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts


def _parse_cef_extensions(value: str) -> dict[str, str]:
    matches = list(_CEF_EXTENSION_KEY.finditer(value))
    extensions: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(value)
        extensions[match.group(1)] = _cef_unescape(value[match.end():end].rstrip())
    return extensions


def _cef_unescape(value: str) -> str:
    result: list[str] = []
    index = 0
    replacements = {"n": "\n", "r": "\r", "=": "=", "|": "|", "\\": "\\"}
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            result.append(replacements.get(value[index + 1], value[index + 1]))
            index += 2
        else:
            result.append(value[index])
            index += 1
    return "".join(result)


def _cef_prefix(value: str, *, now: datetime | None = None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    bsd = _CEF_BSD_PREFIX.match(value)
    if bsd:
        return _rfc3164_timestamp(bsd.group(1), now=now), bsd.group(2)
    timestamp, separator, hostname = value.partition(" ")
    if separator:
        return _iso_timestamp(timestamp), hostname.strip() or None
    return None, value


def _cef_normalized_severity(topics: list[str], value: str) -> str:
    # RouterOS can emit both error and critical for a login failure while its
    # automatic syslog priority remains error, so error intentionally wins.
    for severity in ("emergency", "alert", "error", "critical", "warning", "notice", "info", "debug"):
        if severity in topics:
            return severity
    normalized = value.strip().lower().replace("_", "-")
    named = {"very-high": "critical", "high": "error", "medium": "warning", "low": "info"}
    if normalized in named:
        return named[normalized]
    try:
        numeric = int(normalized)
    except ValueError:
        return "notice"
    if numeric >= 9:
        return "critical"
    if numeric >= 7:
        return "error"
    if numeric >= 4:
        return "warning"
    return "info"


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
    parsed = None
    for timestamp_format in ("%Y %b %d %H:%M:%S.%f", "%Y %b %d %H:%M:%S"):
        try:
            parsed = datetime.strptime(f"{current.year} {value}", timestamp_format).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            pass
    if parsed is None:
        return None
    if parsed > current + timedelta(days=1):
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _mikrotik_topics(message: str) -> tuple[list[str], str]:
    head, separator, rest = message.partition(" ")
    candidates = [candidate.lower() for candidate in head.split(",")]
    if separator and candidates and all(candidate in MIKROTIK_TOPICS for candidate in candidates):
        return candidates, rest
    return [], message


class _SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        server = self.server
        assert isinstance(server, SyslogUDPServer)
        try:
            server.log_service.ingest(parse_remote_message(data, self.client_address[0]))
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


class _CEFStreamHandler(socketserver.StreamRequestHandler):
    def setup(self) -> None:
        server = self.server
        assert isinstance(server, SyslogTCPServer)
        if server.ssl_context is not None:
            self.request = server.ssl_context.wrap_socket(self.request, server_side=True)
        super().setup()

    def handle(self) -> None:
        server = self.server
        assert isinstance(server, SyslogTCPServer)
        while True:
            data = self.rfile.readline(server.max_event_bytes + 1)
            if not data:
                return
            if len(data) > server.max_event_bytes:
                if not data.endswith(b"\n"):
                    self._discard_remainder()
                server.on_error(ValueError(f"CEF event exceeds {server.max_event_bytes} bytes"))
                continue
            if not data.strip(b"\x00\r\n"):
                continue
            try:
                item = parse_remote_message(
                    data,
                    self.client_address[0],
                    stream_transport=server.transport,
                )
                server.log_service.ingest(item)
            except Exception as exc:  # Keep one malformed event from closing the stream.
                server.on_error(exc)

    def _discard_remainder(self) -> None:
        while True:
            chunk = self.rfile.readline(65_536)
            if not chunk or chunk.endswith(b"\n"):
                return


class SyslogTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        log_service: LogService,
        *,
        transport: str = "tcp",
        ssl_context: ssl.SSLContext | None = None,
        max_event_bytes: int = 262_144,
    ):
        super().__init__(address, _CEFStreamHandler)
        self.log_service = log_service
        self.transport = transport
        self.ssl_context = ssl_context
        self.max_event_bytes = max_event_bytes

    def on_error(self, error: Exception) -> None:
        print(f"Could not ingest {self.transport.upper()} CEF event: {error}")

    def handle_error(self, request: object, client_address: tuple[str, int]) -> None:
        print(f"Could not establish {self.transport.upper()} syslog connection from {client_address[0]}")

    def start_in_thread(self) -> threading.Thread:
        thread = threading.Thread(
            target=self.serve_forever,
            name=f"syslog-{self.transport}",
            daemon=True,
        )
        thread.start()
        return thread
