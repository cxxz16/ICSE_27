from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Optional


class MetricsCollector:
    def __init__(self) -> None:
        self._timings: dict[str, float] = {}
        self._counts: dict[str, int] = {}
        self._events: list[dict] = []
        self._t_perf_start = time.perf_counter()
        self._t_wall_start = time.time()
        self._lock = Lock()

    def add_time(self, key: str, seconds: float) -> None:
        with self._lock:
            self._timings[key] = self._timings.get(key, 0.0) + float(seconds)
            self._counts[key + "::n"] = self._counts.get(key + "::n", 0) + 1

    def inc_count(self, key: str, n: int = 1) -> None:
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + int(n)

    def add_event(self, kind: str, **fields) -> None:
        with self._lock:
            ev = {"ts": time.time(), "kind": kind}
            ev.update(fields)
            self._events.append(ev)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "started_at_wall": self._t_wall_start,
                "elapsed_total_sec": round(time.perf_counter() - self._t_perf_start, 3),
                "timings_sec": {k: round(v, 3) for k, v in self._timings.items()},
                "counts": dict(self._counts),
                "events": list(self._events),
            }

    def dump(self, path: Path | str) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.snapshot(), indent=2, ensure_ascii=False))
        return p


collector = MetricsCollector()


@contextmanager
def Timer(key: str):
    t0 = time.perf_counter()
    try:
        yield
    finally:
        collector.add_time(key, time.perf_counter() - t0)


def dump_to_env_or(path: Optional[Path | str] = None) -> Optional[Path]:
    target = os.environ.get("VIPER_METRICS_PATH") or (str(path) if path else None)
    if not target:
        return None
    return collector.dump(target)
