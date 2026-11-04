"""Thread-safe fan-out of events to Server-Sent-Events subscribers.
The detector runs in worker threads; SSE clients live on the asyncio loop."""
from __future__ import annotations
import asyncio
import threading


class Hub:
    def __init__(self):
        self._subs: list = []
        self._lock = threading.Lock()

    def subscribe(self):
        sub = (asyncio.get_running_loop(), asyncio.Queue())
        with self._lock:
            self._subs.append(sub)
        return sub

    def unsubscribe(self, sub) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def publish(self, event: dict) -> None:
        with self._lock:
            subs = list(self._subs)
        for loop, q in subs:
            try:
                loop.call_soon_threadsafe(q.put_nowait, event)
            except RuntimeError:
                pass