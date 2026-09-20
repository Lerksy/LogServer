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
from .syslog import SyslogUDPServer


def build_parser() -> argparse.ArgumentParser:
    defaults = Settings.from_env()
    parser = argparse.ArgumentParser(description="Store and display MikroTik logs")
    parser.add_argument("--database", type=Path, default=defaults.database_path)
    parser.add_argument("--http-host", default=defaults.http_host)
    parser.add_argument("--http-port", type=int, default=defaults.http_port)
    parser.add_argument("--syslog-host", default=defaults.syslog_host)
    parser.add_argument("--syslog-port", type=int, default=defaults.syslog_port)
    parser.add_argument("--no-syslog", action="store_true", help="Disable the UDP syslog listener")
    return parser


def run(settings: Settings, *, enable_syslog: bool = True) -> None:
    database = LogDatabase(settings.database_path)
    database.initialize()
    alert_repository = AlertRepository(settings.database_path)
    alerts = AlertDispatcher(database, alert_repository)
    alerts.start()
    service = LogService(database, EventBroker(), alerts)
    http_server = LogHTTPServer((settings.http_host, settings.http_port), service, settings)
    syslog_server = SyslogUDPServer((settings.syslog_host, settings.syslog_port), service) if enable_syslog else None

    def stop(_signum: int, _frame: object) -> None:
        # serve_forever must be stopped from a different thread, so closing the
        # listening socket is left to the normal finally block on Ctrl-C.
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    if syslog_server:
        syslog_server.start_in_thread()
        print(f"UDP syslog listening on {settings.syslog_host}:{settings.syslog_port}")
    print(f"Web UI and HTTP API listening on http://{settings.http_host}:{settings.http_port}")
    print(f"SQLite database: {settings.database_path}")
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping LogServer")
    finally:
        http_server.server_close()
        alerts.stop()
        if syslog_server:
            syslog_server.shutdown()
            syslog_server.server_close()


def main() -> None:
    args = build_parser().parse_args()
    settings = replace(
        Settings.from_env(),
        database_path=args.database,
        http_host=args.http_host,
        http_port=args.http_port,
        syslog_host=args.syslog_host,
        syslog_port=args.syslog_port,
    )
    run(settings, enable_syslog=not args.no_syslog)


if __name__ == "__main__":
    main()
