from __future__ import annotations

import html
import json
import queue
import re
import sqlite3
import string
import threading
import time
import urllib.error
import urllib.request
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .database import LogDatabase
from .models import LogRecord, utc_now
from .search import SearchSyntaxError, compile_search


BUILTIN_TEMPLATE_FIELDS = {
    "id", "time", "received_at", "event_at", "source", "facility", "severity",
    "topics", "message", "raw", "transport",
}
PARSE_MODES = {"", "HTML", "MarkdownV2"}
REGEX_TARGETS = {"message", "raw"}
BATCH_BODY_MARKER = "[[body]]"
BATCH_BODY_END_MARKER = "[[/body]]"
MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


class AlertValidationError(ValueError):
    pass


class TelegramError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TelegramSettings:
    bot_token: str
    chat_id: str
    updated_at: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "bot_token_configured": bool(self.bot_token),
            "chat_id": self.chat_id,
            "updated_at": self.updated_at or None,
        }


@dataclass(frozen=True, slots=True)
class AlertRule:
    id: int
    name: str
    enabled: bool
    query: str
    regex: str
    regex_target: str
    template: str
    parse_mode: str
    cooldown_seconds: int
    batch_window_seconds: int
    created_at: str
    updated_at: str
    last_sent_at: str | None = None
    last_error: str | None = None
    sent_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AlertRepository:
    def __init__(self, database_path: Path | str):
        self.path = Path(database_path)

    def get_telegram_settings(self) -> TelegramSettings:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM telegram_settings WHERE id = 1").fetchone()
        assert row is not None
        return TelegramSettings(row["bot_token"], row["chat_id"], row["updated_at"])

    def update_telegram_settings(
        self,
        *,
        chat_id: str,
        bot_token: str | None = None,
        clear_token: bool = False,
    ) -> TelegramSettings:
        now = utc_now()
        with closing(self._connect()) as connection, connection:
            if clear_token:
                connection.execute(
                    "UPDATE telegram_settings SET bot_token = '', chat_id = ?, updated_at = ? WHERE id = 1",
                    (chat_id, now),
                )
            elif bot_token:
                connection.execute(
                    "UPDATE telegram_settings SET bot_token = ?, chat_id = ?, updated_at = ? WHERE id = 1",
                    (bot_token, chat_id, now),
                )
            else:
                connection.execute(
                    "UPDATE telegram_settings SET chat_id = ?, updated_at = ? WHERE id = 1",
                    (chat_id, now),
                )
        return self.get_telegram_settings()

    def list_rules(self, *, enabled_only: bool = False) -> list[AlertRule]:
        sql = "SELECT * FROM alert_rules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY id"
        with closing(self._connect()) as connection:
            rows = connection.execute(sql).fetchall()
        return [self._rule(row) for row in rows]

    def get_rule(self, rule_id: int) -> AlertRule | None:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
        return self._rule(row) if row else None

    def create_rule(self, values: dict[str, Any]) -> AlertRule:
        now = utc_now()
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO alert_rules (
                    name, enabled, query, regex, regex_target, template,
                    parse_mode, cooldown_seconds, batch_window_seconds, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["name"], int(values["enabled"]), values["query"], values["regex"],
                    values["regex_target"], values["template"], values["parse_mode"],
                    values["cooldown_seconds"], values["batch_window_seconds"], now, now,
                ),
            )
            rule_id = int(cursor.lastrowid)
        rule = self.get_rule(rule_id)
        assert rule is not None
        return rule

    def update_rule(self, rule_id: int, values: dict[str, Any]) -> AlertRule | None:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                UPDATE alert_rules SET
                    name = ?, enabled = ?, query = ?, regex = ?, regex_target = ?,
                    template = ?, parse_mode = ?, cooldown_seconds = ?, batch_window_seconds = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    values["name"], int(values["enabled"]), values["query"], values["regex"],
                    values["regex_target"], values["template"], values["parse_mode"],
                    values["cooldown_seconds"], values["batch_window_seconds"], utc_now(), rule_id,
                ),
            )
        return self.get_rule(rule_id) if cursor.rowcount else None

    def delete_rule(self, rule_id: int) -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
        return bool(cursor.rowcount)

    def record_success(self, rule_id: int) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                UPDATE alert_rules
                SET last_sent_at = ?, last_error = NULL, sent_count = sent_count + 1
                WHERE id = ?
                """,
                (utc_now(), rule_id),
            )

    def record_error(self, rule_id: int, error: str) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "UPDATE alert_rules SET last_error = ? WHERE id = ?",
                (error[:1000], rule_id),
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @staticmethod
    def _rule(row: sqlite3.Row) -> AlertRule:
        return AlertRule(
            id=row["id"], name=row["name"], enabled=bool(row["enabled"]), query=row["query"],
            regex=row["regex"], regex_target=row["regex_target"], template=row["template"],
            parse_mode=row["parse_mode"], cooldown_seconds=row["cooldown_seconds"],
            batch_window_seconds=row["batch_window_seconds"],
            created_at=row["created_at"], updated_at=row["updated_at"],
            last_sent_at=row["last_sent_at"], last_error=row["last_error"], sent_count=row["sent_count"],
        )


def validate_telegram_settings(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise AlertValidationError("settings must be a JSON object")
    chat_id = payload.get("chat_id", "")
    token = payload.get("bot_token")
    clear_token = payload.get("clear_token", False)
    if not isinstance(chat_id, str) or len(chat_id.strip()) > 255:
        raise AlertValidationError("chat_id must be a string of at most 255 characters")
    if token is not None and (not isinstance(token, str) or len(token.strip()) > 255):
        raise AlertValidationError("bot_token must be a string of at most 255 characters")
    if not isinstance(clear_token, bool):
        raise AlertValidationError("clear_token must be a boolean")
    return {"chat_id": chat_id.strip(), "bot_token": token.strip() if token else None, "clear_token": clear_token}


def validate_rule(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise AlertValidationError("rule must be a JSON object")
    name = payload.get("name", "")
    query = payload.get("query", "")
    pattern = payload.get("regex", "")
    target = payload.get("regex_target", "message")
    template = payload.get("template", "")
    parse_mode = payload.get("parse_mode", "")
    enabled = payload.get("enabled", True)
    cooldown = payload.get("cooldown_seconds", 0)
    batch_window = payload.get("batch_window_seconds", 2)

    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 100:
        raise AlertValidationError("name must be between 1 and 100 characters")
    if not isinstance(query, str) or len(query) > 2000:
        raise AlertValidationError("query must be a string of at most 2000 characters")
    try:
        compile_search(query)
    except SearchSyntaxError as exc:
        raise AlertValidationError(f"invalid query: {exc}") from exc
    if not isinstance(pattern, str) or len(pattern) > 4000:
        raise AlertValidationError("regex must be a string of at most 4000 characters")
    try:
        compiled = re.compile(pattern) if pattern else None
    except re.error as exc:
        raise AlertValidationError(f"invalid regex: {exc}") from exc
    if not isinstance(target, str) or target not in REGEX_TARGETS:
        raise AlertValidationError("regex_target must be 'message' or 'raw'")
    if not isinstance(template, str) or not template.strip() or len(template) > 4096:
        raise AlertValidationError("template must be between 1 and 4096 characters")
    if not isinstance(parse_mode, str) or parse_mode not in PARSE_MODES:
        raise AlertValidationError("parse_mode must be empty, HTML, or MarkdownV2")
    if not isinstance(enabled, bool):
        raise AlertValidationError("enabled must be a boolean")
    if isinstance(cooldown, bool) or not isinstance(cooldown, int) or cooldown < 0 or cooldown > 86400:
        raise AlertValidationError("cooldown_seconds must be an integer between 0 and 86400")
    if (
        isinstance(batch_window, bool)
        or not isinstance(batch_window, int)
        or batch_window < 0
        or batch_window > 60
    ):
        raise AlertValidationError("batch_window_seconds must be an integer between 0 and 60")
    _validate_template(template, compiled)
    return {
        "name": name.strip(), "enabled": enabled, "query": query.strip(), "regex": pattern,
        "regex_target": target, "template": template, "parse_mode": parse_mode,
        "cooldown_seconds": cooldown, "batch_window_seconds": batch_window,
    }


def _validate_template(template: str, pattern: re.Pattern[str] | None) -> None:
    marker_count = template.count(BATCH_BODY_MARKER)
    end_marker_count = template.count(BATCH_BODY_END_MARKER)
    if marker_count > 1:
        raise AlertValidationError(f"template may contain {BATCH_BODY_MARKER} only once")
    if end_marker_count > 1:
        raise AlertValidationError(f"template may contain {BATCH_BODY_END_MARKER} only once")
    if end_marker_count and not marker_count:
        raise AlertValidationError(f"{BATCH_BODY_END_MARKER} requires {BATCH_BODY_MARKER}")
    if marker_count and end_marker_count and template.index(BATCH_BODY_END_MARKER) < template.index(BATCH_BODY_MARKER):
        raise AlertValidationError(f"{BATCH_BODY_END_MARKER} must come after {BATCH_BODY_MARKER}")
    if marker_count:
        header, remainder = template.split(BATCH_BODY_MARKER, 1)
        body = remainder.split(BATCH_BODY_END_MARKER, 1)[0]
        if not header.strip() or not body.strip():
            raise AlertValidationError(
                f"template must have a non-empty header and body around {BATCH_BODY_MARKER}"
            )
    allowed = set(BUILTIN_TEMPLATE_FIELDS)
    if pattern:
        allowed.update(pattern.groupindex)
        allowed.update(f"group{index}" for index in range(1, pattern.groups + 1))
    try:
        parts = string.Formatter().parse(template)
        for _literal, field, format_spec, conversion in parts:
            if field is None:
                continue
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field) or field not in allowed:
                raise AlertValidationError(f"unknown or unsafe template field '{{{field}}}'")
            if format_spec or conversion:
                raise AlertValidationError("template conversions and format specifications are not supported")
    except ValueError as exc:
        raise AlertValidationError(f"invalid template: {exc}") from exc


class TelegramClient:
    def send(self, settings: TelegramSettings, text: str, parse_mode: str = "") -> None:
        if not settings.bot_token or not settings.chat_id:
            raise TelegramError("Telegram bot token and chat ID are not configured")
        payload: dict[str, Any] = {
            "chat_id": settings.chat_id,
            "text": text[:4096],
            "link_preview_options": {"is_disabled": True},
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{settings.bot_token}/sendMessage",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "MikroTik-LogServer/0.1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read()).get("description", str(exc))
            except (json.JSONDecodeError, AttributeError):
                detail = str(exc)
            raise TelegramError(f"Telegram API error: {detail}") from exc
        except (OSError, TimeoutError) as exc:
            raise TelegramError(f"Could not reach Telegram: {exc}") from exc
        if not result.get("ok"):
            raise TelegramError(f"Telegram API error: {result.get('description', 'unknown error')}")


@dataclass(slots=True)
class _PendingBatch:
    rule: AlertRule
    header: str
    bodies: list[str]
    footer: str
    separator: str
    deadline: float

    def text(self, extra_body: str | None = None) -> str:
        bodies = self.bodies if extra_body is None else [*self.bodies, extra_body]
        body = self.separator.join(bodies)
        return "\n".join(part for part in (self.header, body, self.footer) if part)


@dataclass(frozen=True, slots=True)
class _RenderedAlert:
    header: str
    body: str
    footer: str
    separator: str

    def text(self) -> str:
        return "\n".join(part for part in (self.header, self.body, self.footer) if part)


class AlertDispatcher:
    def __init__(
        self,
        database: LogDatabase,
        repository: AlertRepository,
        sender: Callable[[TelegramSettings, str, str], None] | None = None,
    ):
        self.database = database
        self.repository = repository
        client = TelegramClient()
        self.sender = sender or client.send
        self._queue: queue.Queue[LogRecord | None] = queue.Queue(maxsize=2000)
        self._thread: threading.Thread | None = None
        self._pending: dict[int, _PendingBatch] = {}

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="telegram-alerts", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None:
            return
        try:
            self._queue.put(None, timeout=1)
        except queue.Full:
            print("Telegram alert queue did not drain during shutdown")
        self._thread.join(timeout=3)
        self._thread = None

    def enqueue(self, record: LogRecord) -> None:
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            print("Telegram alert queue is full; dropping alert evaluation")

    def send_test(self) -> None:
        self.sender(self.repository.get_telegram_settings(), "✅ LogServer Telegram test", "")

    def process(self, record: LogRecord) -> None:
        active_rules = {rule.id: rule for rule in self.repository.list_rules(enabled_only=True)}
        for rule_id in tuple(self._pending):
            if rule_id not in active_rules:
                self._flush(rule_id)
        for rule in active_rules.values():
            try:
                if self._cooling_down(rule) or not self.database.matches(record.id, rule.query):
                    self._flush(rule.id)
                    continue
                context = self._context(record, rule)
                if context is None:
                    self._flush(rule.id)
                    continue
                rendered_context = {
                    key: _escape_template_value(str(value), rule.parse_mode) for key, value in context.items()
                }
                rendered = self._render(rule.template, rendered_context)
                self._append(rule, rendered)
            except Exception as exc:
                self.repository.record_error(rule.id, str(exc))

    def _run(self) -> None:
        while True:
            try:
                record = self._queue.get(timeout=0.25)
            except queue.Empty:
                self._flush_due()
                continue
            if record is None:
                self.flush_all()
                return
            self.process(record)
            self._flush_due()

    def flush_all(self) -> None:
        for rule_id in tuple(self._pending):
            self._flush(rule_id)

    def _append(self, rule: AlertRule, rendered: _RenderedAlert) -> None:
        if rule.batch_window_seconds == 0:
            self._send(rule, rendered.text())
            return
        batch = self._pending.get(rule.id)
        if batch and batch.rule.updated_at != rule.updated_at:
            self._flush(rule.id)
            batch = None
        if batch and len(batch.text(rendered.body)) > 4096:
            self._flush(rule.id)
            batch = None
        if batch is None:
            batch = _PendingBatch(
                rule,
                rendered.header,
                [],
                rendered.footer,
                rendered.separator,
                time.monotonic() + rule.batch_window_seconds,
            )
            self._pending[rule.id] = batch
        batch.bodies.append(rendered.body)
        batch.deadline = time.monotonic() + rule.batch_window_seconds

    def _flush_due(self) -> None:
        now = time.monotonic()
        for rule_id, batch in tuple(self._pending.items()):
            if batch.deadline <= now:
                self._flush(rule_id)

    def _flush(self, rule_id: int) -> None:
        batch = self._pending.pop(rule_id, None)
        if batch:
            self._send(batch.rule, batch.text())

    def _send(self, rule: AlertRule, text: str) -> None:
        try:
            self.sender(self.repository.get_telegram_settings(), text, rule.parse_mode)
            self.repository.record_success(rule.id)
        except Exception as exc:
            self.repository.record_error(rule.id, str(exc))

    @staticmethod
    def _render(template: str, context: dict[str, str]) -> _RenderedAlert:
        if BATCH_BODY_MARKER in template:
            header_template, remainder = template.split(BATCH_BODY_MARKER, 1)
            if BATCH_BODY_END_MARKER in remainder:
                body_template, footer_template = remainder.split(BATCH_BODY_END_MARKER, 1)
            else:
                body_template, footer_template = remainder, ""
            header = header_template.strip().format_map(context)
            body = body_template.strip().format_map(context)
            footer = footer_template.strip().format_map(context)
            if not header or not body:
                raise TelegramError("Rendered batch header and body must not be empty")
            return _RenderedAlert(header, body, footer, "\n")
        text = template.format_map(context)
        if not text:
            raise TelegramError("Rendered message is empty")
        return _RenderedAlert("", text, "", "\n\n")

    @staticmethod
    def _cooling_down(rule: AlertRule) -> bool:
        if not rule.last_sent_at or not rule.cooldown_seconds:
            return False
        try:
            last_sent = datetime.fromisoformat(rule.last_sent_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        return datetime.now(timezone.utc) < last_sent + timedelta(seconds=rule.cooldown_seconds)

    @staticmethod
    def _context(record: LogRecord, rule: AlertRule) -> dict[str, Any] | None:
        context: dict[str, Any] = {
            "id": record.id, "time": _format_alert_time(record.event_at or record.received_at),
            "received_at": record.received_at, "event_at": record.event_at or "",
            "source": record.source, "facility": record.facility or "", "severity": record.severity,
            "topics": ",".join(record.topics), "message": record.message, "raw": record.raw or "",
            "transport": record.transport,
        }
        if rule.regex:
            value = record.message if rule.regex_target == "message" else (record.raw or "")
            match = re.search(rule.regex, value)
            if not match:
                return None
            context.update({key: value or "" for key, value in match.groupdict().items()})
            context.update({f"group{index}": value or "" for index, value in enumerate(match.groups(), 1)})
        return context


def _escape_template_value(value: str, parse_mode: str) -> str:
    if parse_mode == "HTML":
        return html.escape(value)
    if parse_mode == "MarkdownV2":
        return re.sub(r"([_\*\[\]()~`>#+\-=|{}.!\\])", r"\\\1", value)
    return value


def _format_alert_time(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return (
        f"{parsed.day:02d} {MONTH_NAMES[parsed.month - 1]} {parsed.year}"
        f" · {parsed.hour:02d}:{parsed.minute:02d}:{parsed.second:02d}"
    )
