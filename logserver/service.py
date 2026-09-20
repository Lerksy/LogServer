from __future__ import annotations

from .database import LogDatabase
from .events import EventBroker
from .models import LogInput, LogRecord
from .alerts import AlertDispatcher


class LogService:
    def __init__(self, database: LogDatabase, broker: EventBroker, alerts: AlertDispatcher | None = None):
        self.database = database
        self.broker = broker
        self.alerts = alerts

    def ingest(self, item: LogInput) -> LogRecord:
        record = self.database.insert(item)
        self.broker.publish(record)
        if self.alerts:
            self.alerts.enqueue(record)
        return record

    def ingest_many(self, items: list[LogInput]) -> list[LogRecord]:
        records = self.database.insert_many(items)
        for record in records:
            self.broker.publish(record)
            if self.alerts:
                self.alerts.enqueue(record)
        return records
