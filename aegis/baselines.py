"""Behavioural baseline builder.

During the burn-in phase the engine learns, per device:
  - domains it normally queries (and how often)
  - remote networks (ASNs, IP /24 prefixes) it normally contacts
  - LAN peers it normally talks to
  - connection rate and upload volume, per hour-of-day, with variance
  - the hours of day it is normally active

Everything is stored as plain JSON: on the CM5 this is the "persistent
local security intelligence" kept on the 32 GB eMMC — no cloud needed.
"""
from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

DOMAIN_KNOWN_MIN = 5     # queries over burn-in to count as "known"
ASN_KNOWN_MIN = 3
PREFIX_KNOWN_MIN = 3
PEER_KNOWN_MIN = 2


class BaselineBuilder:
    def __init__(self) -> None:
        self.domains: dict[str, Counter] = defaultdict(Counter)
        self.asns: dict[str, Counter] = defaultdict(Counter)
        self.prefixes: dict[str, Counter] = defaultdict(Counter)
        self.peers: dict[str, Counter] = defaultdict(Counter)
        # per-day accumulators
        self._day_conns: dict[str, list[int]] = defaultdict(lambda: [0] * 24)
        self._day_bytes: dict[str, list[int]] = defaultdict(lambda: [0] * 24)
        # history across days
        self.hist_conns: dict[str, list[list[int]]] = defaultdict(list)
        self.hist_bytes: dict[str, list[list[int]]] = defaultdict(list)

    def add(self, ev) -> None:
        d = ev.device
        if ev.kind == "dns":
            self.domains[d][ev.data.get("domain", "")] += 1
        elif ev.kind == "conn":
            hour = int((ev.ts % 86_400) // 3600)
            self._day_conns[d][hour] += 1
            self._day_bytes[d][hour] += int(ev.data.get("bytes_up", 0))
            if ev.data.get("internal"):
                self.peers[d][ev.data.get("dst", "")] += 1
            else:
                asn = ev.data.get("asn", "")
                if asn and asn != "-":
                    self.asns[d][asn] += 1
                dst = ev.data.get("dst", "")
                parts = dst.split(".")
                if len(parts) == 4:
                    self.prefixes[d][".".join(parts[:3])] += 1

    def end_day(self) -> None:
        for d, row in self._day_conns.items():
            self.hist_conns[d].append(list(row))
        for d, row in self._day_bytes.items():
            self.hist_bytes[d].append(list(row))
        self._day_conns = defaultdict(lambda: [0] * 24)
        self._day_bytes = defaultdict(lambda: [0] * 24)

    def finalize(self) -> dict:
        baselines: dict = {}
        devices = set(self.domains) | set(self.hist_conns)
        for d in devices:
            hist_c = self.hist_conns.get(d, [])
            hist_b = self.hist_bytes.get(d, [])
            hour_mean_c, hour_std_c, hour_mean_b, hour_std_b = [], [], [], []
            for h in range(24):
                cvals = [row[h] for row in hist_c] or [0]
                bvals = [row[h] for row in hist_b] or [0]
                hour_mean_c.append(statistics.mean(cvals))
                hour_std_c.append(statistics.pstdev(cvals))
                hour_mean_b.append(statistics.mean(bvals))
                hour_std_b.append(statistics.pstdev(bvals))
            total_c = sum(hour_mean_c) or 1.0
            baselines[d] = {
                "domains": sorted(
                    [dom for dom, c in self.domains[d].items()
                     if c >= DOMAIN_KNOWN_MIN]),
                "asns": sorted(
                    [a for a, c in self.asns[d].items() if c >= ASN_KNOWN_MIN]),
                "prefixes": sorted(
                    [p for p, c in self.prefixes[d].items()
                     if c >= PREFIX_KNOWN_MIN]),
                "peers": sorted(
                    [p for p, c in self.peers[d].items() if c >= PEER_KNOWN_MIN]),
                "hour_conns_mean": hour_mean_c,
                "hour_conns_std": hour_std_c,
                "hour_bytes_mean": hour_mean_b,
                "hour_bytes_std": hour_std_b,
                "hour_share": [m / total_c for m in hour_mean_c],
                "daily_conns": total_c,
            }
        return baselines

    def save(self, baselines: dict, path: str | Path) -> None:
        Path(path).write_text(json.dumps(baselines, indent=0))

    @staticmethod
    def load(path: str | Path) -> dict:
        return json.loads(Path(path).read_text())
