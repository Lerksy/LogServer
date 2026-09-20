from __future__ import annotations

from .database import LogDatabase
from .events import EventBroker
from .models import LogInput, LogRecord


class LogService:
    def __init__(self, database: LogDatabase, broker: EventBroker):
        self.database = database
        self.broker = broker

    def ingest(self, item: LogInput) -> LogRecord:
        record = self.database.insert(item)
        self.broker.publish(record)
        return record

    def ingest_many(self, items: list[LogInput]) -> list[LogRecord]:
        records = self.database.insert_many(items)
        for record in records:
            self.broker.publish(record)
        return records
