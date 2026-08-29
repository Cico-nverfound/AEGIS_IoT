"""Simulated home-network traffic generator.

Runs on a simulated clock (accelerated time). In `live` mode it plays three
scripted attack scenarios on night of day 15:

  02:43  camera-01  -> compromised IoT camera: DGA + C2 beaconing + exfil
  03:00  unknown-01 -> rogue device joins, DNS burst, outbound to shady ASN
  03:12  bulb-02    -> internal port scan / lateral movement (worm-style)
  03:30  nas-01     -> scheduled encrypted backup (BENIGN, must NOT alert)
"""
from __future__ import annotations

import heapq
import random
import string

from .devices import (
    ATTACK_ASN, ATTACK_ASN_NAME, ATTACK_PREFIX, CATALOG, SUBNET,
    INFRA_ASNS, INTERNAL_PEERS, hourly_rate,
)
from .models import Event

DAY = 86_400

# Live demo starts here: day 15, 02:42:30
LIVE_START = 15 * DAY + 2 * 3600 + 42 * 60 + 30

ATTACK_CAM = 15 * DAY + 2 * 3600 + 43 * 60 + 11   # 02:43:11
ATTACK_ROGUE = 15 * DAY + 3 * 3600                 # 03:00:00
ATTACK_SCAN = 15 * DAY + 3 * 3600 + 12 * 60        # 03:12:00
NAS_BACKUP = 15 * DAY + 3 * 3600 + 30 * 60         # 03:30:00
CAM_BEACON_STOP = 15 * DAY + 3 * 3600 + 20 * 60    # malware gives up at 03:20


def _dga_domain(rng: random.Random) -> str:
    tlds = [".top", ".xyz", ".club", ".info", ".net"]
    length = rng.randint(9, 13)
    label = "".join(rng.choice(string.ascii_lowercase + string.digits)
                    for _ in range(length))
    return label + rng.choice(tlds)


def _shady_ip(rng: random.Random) -> str:
    return f"{ATTACK_PREFIX}.{rng.randint(2, 250)}"


class Simulator:
    def __init__(self, start_ts: float = 0.0, live: bool = False, seed: int = 7):
        self.live = live
        self.t = start_ts
        self.rng = random.Random(seed)
        self.next_ts: dict[str, float] = {}
        self.specials: list[tuple[float, int, callable]] = []
        self._sid = 0

        for dev in CATALOG:
            rate = hourly_rate(dev["cls"], self._hour(start_ts))
            self.next_ts[dev["id"]] = start_ts + max(
                5.0, self.rng.expovariate(max(rate, 0.5) / 3600.0))

        # Scheduled nightly NAS backups (also during burn-in, every 03:30)
        first_night = int(start_ts // DAY)
        for day in range(first_night, first_night + (3 if live else 16)):
            heapq.heappush(self.specials,
                           (day * DAY + 3 * 3600 + 30 * 60, self._sid,
                            self._nas_backup))

        if live:
            heapq.heappush(self.specials, (ATTACK_CAM, self._sid, self._cam_strike))
            heapq.heappush(self.specials, (ATTACK_ROGUE, self._sid, self._rogue))
            heapq.heappush(self.specials, (ATTACK_SCAN, self._sid, self._scan))

    # --- helpers ------------------------------------------------------------

    def _hour(self, ts: float) -> int:
        return int((ts % DAY) // 3600)

    def _schedule(self, ts: float, fn) -> None:
        self._sid += 1
        heapq.heappush(self.specials, (ts, self._sid, fn))

    def _pick_domain(self, dev: dict):
        domains = dev["domains"]
        total = sum(w for *_, w in domains)
        r = self.rng.uniform(0, total)
        for domain, asn, prefix, w in domains:
            r -= w
            if r <= 0:
                return domain, asn, prefix
        return domains[0][0], domains[0][1], domains[0][2]

    # --- normal traffic -----------------------------------------------------

    def _gen_normal(self, dev: dict, ts: float) -> list[Event]:
        events: list[Event] = []
        # A small share of traffic stays on the LAN (NAS, printer, casting)
        if dev["cls"] in ("phone", "laptop", "tv") and self.rng.random() < 0.06:
            peer_ip = self.rng.choice(list(INTERNAL_PEERS))
            events.append(Event(ts, "conn", dev["id"], {
                "dst": peer_ip, "port": self.rng.choice([445, 9100, 554, 8008]),
                "proto": "tcp", "asn": "-", "asn_name": "local",
                "domain": INTERNAL_PEERS[peer_ip], "internal": True,
                "bytes_up": self.rng.randint(5_000, 60_000),
                "bytes_down": self.rng.randint(10_000, 200_000),
            }))
            return events

        domain, asn, prefix = self._pick_domain(dev)
        ip = f"{prefix}.{self.rng.randint(2, 250)}"
        port = self.rng.choice(dev["ports"])
        events.append(Event(ts, "dns", dev["id"], {"domain": domain}))
        jitter = 0.3 + self.rng.random() * 0.8
        events.append(Event(ts + jitter, "conn", dev["id"], {
            "dst": ip, "port": port, "proto": "tcp", "asn": asn,
            "asn_name": "infra" if asn in INFRA_ASNS else f"{asn}",
            "domain": domain, "internal": False,
            "bytes_up": max(500, int(dev["bytes_up"] * self.rng.uniform(0.4, 1.8))),
            "bytes_down": max(500, int(dev["bytes_down"] * self.rng.uniform(0.4, 1.8))),
        }))
        return events

    # --- scheduled scenarios ------------------------------------------------

    def _nas_backup(self) -> list[Event]:
        """Scheduled encrypted off-site backup: heavy, nightly, known endpoint."""
        dev = next(d for d in CATALOG if d["id"] == "nas-01")
        events = []
        t = self.t
        for i in range(28):
            ts = t + i * self.rng.uniform(28, 42)
            events.append(Event(ts, "dns", "nas-01",
                                {"domain": "vault.nasvault.io"}))
            events.append(Event(ts + 0.5, "conn", "nas-01", {
                "dst": f"104.248.50.{self.rng.randint(2, 20)}",
                "port": 443, "proto": "tcp", "asn": "AS64999",
                "asn_name": "AS64999", "domain": "vault.nasvault.io",
                "internal": False,
                "bytes_up": self.rng.randint(35_000_000, 65_000_000),
                "bytes_down": self.rng.randint(500_000, 2_000_000),
            }))
        return events

    def _cam_strike(self) -> list[Event]:
        """IoT camera compromise: initial burst then periodic C2 beaconing."""
        events = []
        t = self.t
        # Initial burst: 6 DGA lookups in ~12 seconds, 3 exfil connections
        for i in range(6):
            ts = t + i * self.rng.uniform(1.2, 2.6)
            dom = _dga_domain(self.rng)
            events.append(Event(ts, "dns", "camera-01", {"domain": dom}))
        for i in range(3):
            ts = t + 3 + i * self.rng.uniform(2.0, 4.0)
            events.append(Event(ts, "conn", "camera-01", {
                "dst": _shady_ip(self.rng), "port": 443, "proto": "tcp",
                "asn": ATTACK_ASN, "asn_name": ATTACK_ASN_NAME,
                "domain": _dga_domain(self.rng), "internal": False,
                "bytes_up": self.rng.randint(8_000_000, 18_000_000),
                "bytes_down": self.rng.randint(20_000, 80_000),
            }))
        # Periodic beaconing every ~45 s until CAM_BEACON_STOP
        self._schedule_beacon(t + 40)
        return events

    def _schedule_beacon(self, ts: float) -> None:
        if ts >= CAM_BEACON_STOP:
            return
        def beacon():
            events = [
                Event(ts, "dns", "camera-01", {"domain": _dga_domain(self.rng)}),
                Event(ts + 0.6, "conn", "camera-01", {
                    "dst": _shady_ip(self.rng), "port": 443, "proto": "tcp",
                    "asn": ATTACK_ASN, "asn_name": ATTACK_ASN_NAME,
                    "domain": _dga_domain(self.rng), "internal": False,
                    "bytes_up": self.rng.randint(5_000_000, 12_000_000),
                    "bytes_down": self.rng.randint(10_000, 50_000),
                }),
            ]
            self._schedule_beacon(ts + self.rng.uniform(38, 54))
            return events
        self._schedule(ts, beacon)

    def _rogue(self) -> list[Event]:
        """Unknown device associates at 3 AM and starts a DNS burst."""
        mac = "de:ad:be:ef:%02x:%02x" % (
            self.rng.randint(0, 255), self.rng.randint(0, 255))
        events = [Event(self.t, "join", "unknown-01", {
            "name": "Unknown device", "mac": mac, "vendor": "unknown",
            "dtype": "unknown", "ip": f"{SUBNET}.47",
        })]
        for i in range(18):
            ts = self.t + 2 + i * self.rng.uniform(3.5, 7.0)
            dom = _dga_domain(self.rng) if i < 12 else self.rng.choice(
                ["free-cracked-appz.xyz", "anon-proxy.io", "mega-deals.top"])
            events.append(Event(ts, "dns", "unknown-01", {"domain": dom}))
        for i in range(6):
            ts = self.t + 12 + i * self.rng.uniform(8, 16)
            events.append(Event(ts, "conn", "unknown-01", {
                "dst": _shady_ip(self.rng),
                "port": self.rng.choice([443, 8080]), "proto": "tcp",
                "asn": ATTACK_ASN, "asn_name": ATTACK_ASN_NAME,
                "domain": "anon-proxy.io", "internal": False,
                "bytes_up": self.rng.randint(200_000, 1_500_000),
                "bytes_down": self.rng.randint(100_000, 900_000),
            }))
        return events

    def _scan(self) -> list[Event]:
        """Compromised bulb scans the local subnet (worm propagation)."""
        events = []
        hosts = self.rng.sample(range(2, 60), 14)
        ports = [23, 2323, 80, 445]
        for i, host in enumerate(hosts):
            ts = self.t + i * self.rng.uniform(2.0, 3.5)
            events.append(Event(ts, "conn", "bulb-02", {
                "dst": f"{SUBNET}.{host}",
                "port": self.rng.choice(ports), "proto": "tcp",
                "asn": "-", "asn_name": "local", "domain": f"{SUBNET}.{host}",
                "internal": True,
                "bytes_up": self.rng.randint(200, 1_200),
                "bytes_down": self.rng.randint(0, 300),
            }))
        return events

    # --- main advance -------------------------------------------------------

    def advance(self, until: float) -> list[Event]:
        """Return all events with ts <= until, in chronological order."""
        out: list[Event] = []

        while self.specials and self.specials[0][0] <= until:
            ts, _, fn = heapq.heappop(self.specials)
            self.t = max(self.t, ts)
            out.extend(fn())

        for dev in CATALOG:
            did = dev["id"]
            t = self.next_ts.get(did, until + 1)
            while t <= until:
                out.extend(self._gen_normal(dev, t))
                rate = hourly_rate(dev["cls"], self._hour(t))
                t += max(15.0, self.rng.expovariate(max(rate, 0.3) / 3600.0))
            self.next_ts[did] = t

        out.sort(key=lambda e: e.ts)
        self.t = until
        return out
