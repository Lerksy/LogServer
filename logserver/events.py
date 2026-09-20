from __future__ import annotations

import queue
import threading
from contextlib import contextmanager
from collections.abc import Iterator

from .models import LogRecord


class EventBroker:
    def __init__(self, queue_size: int = 1000):
        self._queue_size = queue_size
        self._subscribers: set[queue.Queue[LogRecord]] = set()
        self._lock = threading.Lock()

    @contextmanager
    def subscribe(self) -> Iterator[queue.Queue[LogRecord]]:
        subscriber: queue.Queue[LogRecord] = queue.Queue(self._queue_size)
        with self._lock:
            self._subscribers.add(subscriber)
        try:
            yield subscriber
        finally:
            with self._lock:
                self._subscribers.discard(subscriber)

    def publish(self, record: LogRecord) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(record)
            except queue.Full:
                try:
                    subscriber.get_nowait()
                    subscriber.put_nowait(record)
                except (queue.Empty, queue.Full):
                    pass

