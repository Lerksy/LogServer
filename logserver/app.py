from __future__ import annotations

import argparse
import signal
from dataclasses import replace
from pathlib import Path

from .alerts import AlertDispatcher, AlertRepository
from .config import Settings
from .database import LogDatabase
from .events import EventBroker
from .http import LogHTTPServer
from .service import LogService
from .syslog import SyslogTCPServer, SyslogUDPServer
from .tls import prepare_server_context


def build_parser() -> argparse.ArgumentParser:
    defaults = Settings.from_env()
    parser = argparse.ArgumentParser(description="Store and display MikroTik logs")
    parser.add_argument("--database", type=Path, default=defaults.database_path)
    parser.add_argument("--http-host", default=defaults.http_host)
    parser.add_argument("--http-port", type=int, default=defaults.http_port)
    parser.add_argument("--syslog-host", default=defaults.syslog_host)
    parser.add_argument("--syslog-port", type=int, default=defaults.syslog_port)
    parser.add_argument("--syslog-tcp-port", type=int, default=defaults.syslog_tcp_port)
    parser.add_argument("--syslog-tls-port", type=int, default=defaults.syslog_tls_port)
    parser.add_argument("--tls-certfile", type=Path, default=defaults.tls_certfile)
    parser.add_argument("--tls-keyfile", type=Path, default=defaults.tls_keyfile)
    parser.add_argument(
        "--no-syslog", "--no-udp", dest="no_udp", action="store_true",
        help="Disable the UDP syslog listener",
    )
    parser.add_argument("--no-tcp", action="store_true", help="Disable the TCP CEF listener")
    parser.add_argument("--no-tls", action="store_true", help="Disable the TLS CEF listener")
    return parser


def run(
    settings: Settings,
    *,
    enable_udp: bool = True,
    enable_tcp: bool = True,
    enable_tls: bool = True,
) -> None:
    database = LogDatabase(settings.database_path)
    database.initialize()
    alert_repository = AlertRepository(settings.database_path)
    alerts = AlertDispatcher(database, alert_repository)
    alerts.start()
    service = LogService(database, EventBroker(), alerts)
    http_server = LogHTTPServer((settings.http_host, settings.http_port), service, settings)
    servers: list[tuple[str, SyslogUDPServer | SyslogTCPServer]] = []
    if enable_udp:
        servers.append((
            f"UDP syslog on {settings.syslog_host}:{settings.syslog_port}",
            SyslogUDPServer((settings.syslog_host, settings.syslog_port), service),
        ))
    if enable_tcp:
        servers.append((
            f"TCP CEF on {settings.syslog_host}:{settings.syslog_tcp_port}",
            SyslogTCPServer(
                (settings.syslog_host, settings.syslog_tcp_port),
                service,
                max_event_bytes=settings.max_syslog_bytes,
            ),
        ))
    if enable_tls and settings.tls_certfile and settings.tls_keyfile:
        tls_context = prepare_server_context(
            settings.tls_certfile,
            settings.tls_keyfile,
            auto_generate=settings.tls_auto_generate,
        )
        servers.append((
            f"TLS CEF on {settings.syslog_host}:{settings.syslog_tls_port}",
            SyslogTCPServer(
                (settings.syslog_host, settings.syslog_tls_port),
                service,
                transport="tls",
                ssl_context=tls_context,
                max_event_bytes=settings.max_syslog_bytes,
            ),
        ))
    elif enable_tls and (settings.tls_certfile or settings.tls_keyfile):
        raise ValueError("Both TLS certificate and key paths must be configured")

    def stop(_signum: int, _frame: object) -> None:
        # serve_forever must be stopped from a different thread, so closing the
        # listening socket is left to the normal finally block on Ctrl-C.
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    for description, server in servers:
        server.start_in_thread()
        print(f"{description} listening")
    if enable_tls and not settings.tls_certfile and not settings.tls_keyfile:
        print("TLS CEF listener disabled: no certificate and key configured")
    print(f"Web UI and HTTP API listening on http://{settings.http_host}:{settings.http_port}")
    print(f"SQLite database: {settings.database_path}")
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping LogServer")
    finally:
        http_server.server_close()
        alerts.stop()
        for _description, server in servers:
            server.shutdown()
            server.server_close()


def main() -> None:
    args = build_parser().parse_args()
    settings = replace(
        Settings.from_env(),
        database_path=args.database,
        http_host=args.http_host,
        http_port=args.http_port,
        syslog_host=args.syslog_host,
        syslog_port=args.syslog_port,
        syslog_tcp_port=args.syslog_tcp_port,
        syslog_tls_port=args.syslog_tls_port,
        tls_certfile=args.tls_certfile,
        tls_keyfile=args.tls_keyfile,
    )
    run(
        settings,
        enable_udp=not args.no_udp,
        enable_tcp=not args.no_tcp,
        enable_tls=not args.no_tls,
    )


if __name__ == "__main__":
    main()
