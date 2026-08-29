"""Burn-in + live simulation driver, shared by web and CLI modes."""
from __future__ import annotations

import json
from pathlib import Path

from .engine import AegisEngine, fmt_ts
from .models import Event
from .simulator import DAY, LIVE_START, Simulator

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def build_baselines(days: int = 14, seed: int = 7) -> dict:
    """Fast-forward `days` of normal traffic and learn behavioural baselines."""
    sim = Simulator(start_ts=0.0, live=False, seed=seed)
    engine = AegisEngine()
    engine.start_learning()
    step = 6 * 3600  # 6-hour chunks
    for day in range(days):
        for _ in range(4):
            events = sim.advance(sim.t + step)
            engine.ingest(events, learning=True)
        engine.builder.end_day()
    baselines = engine.builder.finalize()
    DATA_DIR.mkdir(exist_ok=True)
    (DATA_DIR / "baselines.json").write_text(json.dumps(baselines))
    return baselines


class LiveLoop:
    """Drives the live night-of scenario in accelerated simulated time."""

    def __init__(self, baselines: dict, auto_recover: bool = False, seed: int = 7):
        self.sim = Simulator(start_ts=LIVE_START, live=True, seed=seed)
        self.engine = AegisEngine(baselines, auto_recover=auto_recover)
        self.now = LIVE_START
        # Smart-home context: house empty / household asleep at demo start
        self.engine.ingest([Event(LIVE_START, "context", "home",
                                  {"presence": "empty"})])
        self.on_incident = None    # callback(incident)

    def step(self, sim_seconds: float) -> None:
        self.now += sim_seconds
        events = self.sim.advance(self.now)
        self.engine.ingest(events)
        before = {i["id"] for i in self.engine.incidents}
        self.engine.tick(self.now)
        if self.on_incident:
            for inc in self.engine.incidents:
                if inc["id"] not in before:
                    self.on_incident(inc)

    def snapshot(self) -> dict:
        return self.engine.snapshot(self.now)
