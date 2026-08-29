"""AEGIS core engine — the observe/understand/decide/act/learn loop."""
from __future__ import annotations

import time

from .analyst import LocalAnalyst
from .baselines import BaselineBuilder
from .detectors import detect
from .devices import CATALOG, INFRA_ASNS
from .models import DeviceState, Event, IncidentStatus, Signal
from .risk import decide, score_risk, confidence as conf_score

WINDOW = 300
QUARANTINE_AUTO_MS = 600          # sim-seconds before "user approves restore"


def fmt_ts(ts: float) -> str:
    t = int(ts)
    h = (t % 86_400) // 3600
    m = (t % 3600) // 60
    s = t % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


class AegisEngine:
    def __init__(self, baselines: dict | None = None, auto_recover: bool = False):
        self.baselines = baselines or {}
        self.auto_recover = auto_recover
        self.builder: BaselineBuilder | None = None   # set during burn-in
        self.analyst = LocalAnalyst()

        self.devices: dict[str, dict] = {}
        for d in CATALOG:
            self.devices[d["id"]] = {
                "id": d["id"], "name": d["name"], "dtype": d["dtype"],
                "cls": d["cls"], "mac": d["mac"], "ip": d["ip"],
                "known": True, "state": DeviceState.NORMAL,
                "first_seen": None, "last_seen": None, "quarantined_at": None,
            }

        self.windows: dict[str, list[Event]] = {d["id"]: [] for d in CATALOG}
        self.incidents: list[dict] = []
        self.open_by_device: dict[str, dict] = {}
        self.feed: list[dict] = []
        self.notifications: list[dict] = []
        self.blocklist: set[str] = set()          # exact IPs
        self.block_prefixes: set[str] = set()     # /24 prefixes
        self.blocked_total = 0
        self.presence = "occupied"
        self._incident_seq = 0

    # --- feed / notifications ----------------------------------------------

    def _feed(self, ts: float, level: str, line: str) -> None:
        self.feed.append({"ts": ts, "t": fmt_ts(ts), "level": level, "line": line})
        if len(self.feed) > 120:
            self.feed = self.feed[-120:]

    def _notify(self, ts: float, level: str, title: str, body: str,
                device: str = "") -> None:
        self.notifications.insert(0, {"ts": ts, "t": fmt_ts(ts), "level": level,
                                      "title": title, "body": body,
                                      "device": device, "id": len(self.notifications)})
        self.notifications = self.notifications[:10]

    # --- ingestion -----------------------------------------------------------

    def start_learning(self) -> None:
        self.builder = BaselineBuilder()

    def ingest(self, events: list[Event], learning: bool = False) -> None:
        for ev in events:
            if learning:
                self.builder.add(ev)
                continue

            if ev.kind == "context":
                self.presence = ev.data.get("presence", self.presence)
                self._feed(ev.ts, "dim", f"CONTEXT  home presence: {self.presence}")
                continue

            dev = self._device_for(ev.device)
            if ev.kind == "join":
                dev["name"] = ev.data.get("name", dev["name"])
                dev["mac"] = ev.data.get("mac", dev["mac"])
                dev["ip"] = ev.data.get("ip", dev["ip"])
                dev["dtype"] = ev.data.get("dtype", dev["dtype"])
            if dev["first_seen"] is None:
                dev["first_seen"] = ev.ts
                if not dev["known"]:
                    self._feed(ev.ts, "warn",
                               f"NEW DEVICE  {dev['name']} [{ev.data.get('mac','?')}] "
                               f"joined on {dev['ip']} (vendor: {ev.data.get('vendor','?')})")
                    self._notify(ev.ts, "warn", "Unknown device joined the network",
                                 f"{dev['name']} ({ev.data.get('mac','?')}) appeared on "
                                 f"{dev['ip']}. It is not enrolled in this household.",
                                 dev["id"])

            if ev.kind in ("dns", "conn"):
                if dev["state"] == DeviceState.QUARANTINED:
                    self._enforce_block(ev, dev, "device quarantined")
                    continue
                if ev.kind == "conn":
                    dst = ev.data.get("dst", "")
                    prefix = ".".join(dst.split(".")[:3])
                    if dst in self.blocklist or prefix in self.block_prefixes:
                        self._enforce_block(ev, dev, "destination blocklisted")
                        continue
                self.windows.setdefault(dev["id"], []).append(ev)
                dev["last_seen"] = ev.ts
                self._feed_event(ev, dev)

    def _enforce_block(self, ev: Event, dev: dict, reason: str) -> None:
        self.blocked_total += 1
        dst = ev.data.get("domain") or ev.data.get("dst", "?")
        self._feed(ev.ts, "block", f"BLOCKED  {dev['id']} ✗ {dst}  ({reason})")
        inc = self.open_by_device.get(dev["id"])
        if inc:
            inc["blocked"] = inc.get("blocked", 0) + 1

    def _feed_event(self, ev: Event, dev: dict) -> None:
        if ev.kind == "dns":
            self._feed(ev.ts, "dim",
                       f"DNS   {ev.device:<11} → {ev.data.get('domain')}")
        elif ev.kind == "conn":
            d = ev.data
            if d.get("internal"):
                self._feed(ev.ts, "lan",
                           f"LAN   {ev.device:<11} → {d.get('dst')}:{d.get('port')}")
            else:
                kb = max(1, int(d.get("bytes_up", 0)) // 1024)
                self._feed(ev.ts, "net",
                           f"CONN  {ev.device:<11} → {d.get('dst')}:{d.get('port')} "
                           f"({d.get('asn_name', d.get('asn','?'))}) {kb} KB up")

    def _device_for(self, device_id: str) -> dict:
        if device_id not in self.devices:
            self.devices[device_id] = {
                "id": device_id, "name": "Unknown device", "dtype": "unknown",
                "cls": "unknown", "mac": "??", "ip": "?.?.?.?",
                "known": False, "state": DeviceState.NORMAL,
                "first_seen": None, "last_seen": None, "quarantined_at": None,
            }
            self.windows[device_id] = []
        return self.devices[device_id]

    # --- evaluation tick -----------------------------------------------------

    def tick(self, now: float) -> None:
        hour = int((now % 86_400) // 3600)
        night = hour in range(0, 6)
        # Smart-home context: presence sensor (household asleep / away at night)
        self.presence = "empty" if night else "occupied"

        for did, win in list(self.windows.items()):
            dev = self.devices[did]
            win[:] = [e for e in win if e.ts >= now - WINDOW]

            if dev["state"] == DeviceState.QUARANTINED:
                inc = self.open_by_device.get(did)
                if inc and self.auto_recover and inc["action"] == "quarantine" \
                        and now - dev["quarantined_at"] > QUARANTINE_AUTO_MS:
                    self.act("restore", did, now,
                             note="Homeowner tapped RESTORE on the mobile alert")
                continue

            signals = detect(dev, win, self.baselines.get(did), night, self.presence)

            # New-device signal (registration event, not window-based)
            if not dev["known"] and dev["first_seen"] and now - dev["first_seen"] < WINDOW:
                w = 18.0 + (8.0 if night else 0.0) + (6.0 if self.presence == "empty" else 0.0)
                signals.append(Signal(
                    "new_device", "Unknown, unenrolled device",
                    f"A device that is not part of the household enrolled itself "
                    f"on the network ({dev['ip']}, MAC vendor unknown).",
                    w, "not enrolled"))

            if not signals:
                if dev["state"] == DeviceState.MONITORED and did not in self.open_by_device:
                    dev["state"] = DeviceState.NORMAL
                continue

            risk = score_risk(signals, dev["cls"], hour, self.presence)
            conf = conf_score(signals)
            action = decide(risk)
            if action == "allow":
                continue

            inc = self.open_by_device.get(did)
            if inc is None:
                self._open_incident(dev, signals, risk, conf, action, hour, now)
            else:
                inc["risk"] = max(inc["risk"], risk)
                inc["updated"] = now

        # Containment: response enforced + no further anomaly for ~45 sim-sec
        for inc in self.incidents:
            if inc["status"] == IncidentStatus.OPEN and now - inc["updated"] > 45:
                inc["status"] = IncidentStatus.CONTAINED
                inc["timeline"].append(
                    {"ts": now, "t": fmt_ts(now),
                     "label": "Network stable — threat contained", "level": "ok"})

    def _open_incident(self, dev: dict, signals, risk: int, conf: int,
                       action: str, hour: int, now: float) -> None:
        self._incident_seq += 1
        assessment = self.analyst.assess(dev, signals, risk, conf,
                                         hour, self.presence)
        inc = {
            "id": f"INC-{self._incident_seq:03d}",
            "device": dev["id"], "device_name": dev["name"],
            "started": now, "updated": now,
            "status": IncidentStatus.OPEN,
            "risk": risk, "confidence": conf,
            "action": action, "blocked": 0,
            "timeline": [
                {"ts": now, "t": fmt_ts(now), "label": "Behavioural anomaly detected", "level": "warn"},
                {"ts": now + 1, "t": fmt_ts(now + 1), "label": "Events correlated across telemetry", "level": "warn"},
                {"ts": now + 2, "t": fmt_ts(now + 2),
                 "label": f"Risk assessed at {risk}% — confidence {conf}%", "level": "danger"},
            ],
            **{k: assessment[k] for k in
               ("title", "classification", "narrative", "recommendation", "evidence")},
        }

        if action == "quarantine":
            dev["state"] = DeviceState.QUARANTINED
            dev["quarantined_at"] = now
            inc["timeline"].append(
                {"ts": now + 3, "t": fmt_ts(now + 3),
                 "label": f"Device isolated — moved to quarantine VLAN", "level": "danger"})
            self._feed(now, "danger",
                       f"QUARANTINE  {dev['id']} isolated from the network "
                       f"(risk {risk}%)")
            self._notify(now, "danger", f"Threat contained: {dev['name']}",
                         f"{assessment['classification']}. The device was "
                         f"automatically isolated. Risk {risk}%, confidence {conf}%.",
                         dev["id"])
        elif action == "block":
            dev["state"] = DeviceState.MONITORED
            known_pfx = set(self.baselines.get(did, {}).get("prefixes", []))
            for e in self.windows.get(dev["id"], []):
                if e.kind == "conn" and not e.data.get("internal"):
                    dst = e.data.get("dst", "")
                    pfx = ".".join(dst.split(".")[:3])
                    # never blocklist networks already part of the baseline
                    if pfx not in known_pfx:
                        self.blocklist.add(dst)
                        self.block_prefixes.add(pfx)
            inc["timeline"].append(
                {"ts": now + 3, "t": fmt_ts(now + 3),
                 "label": "Suspicious destinations blocked — enhanced monitoring",
                 "level": "warn"})
            self._feed(now, "warn", f"RESPONSE  suspicious destinations for "
                                    f"{dev['id']} blocked (risk {risk}%)")
            self._notify(now, "warn", f"Suspicious behaviour: {dev['name']}",
                         f"{assessment['classification']}. Suspicious destinations "
                         f"were blocked. Risk {risk}%.", dev["id"])
        else:
            dev["state"] = DeviceState.MONITORED
            self._notify(now, "warn", f"Unusual behaviour: {dev['name']}",
                         assessment["classification"], dev["id"])

        self.incidents.append(inc)
        self.open_by_device[dev["id"]] = inc

    # --- user / policy actions -----------------------------------------------

    def act(self, action: str, device_id: str, now: float | None = None,
            note: str = "") -> dict:
        now = now if now is not None else self._now()
        dev = self.devices.get(device_id)
        if not dev:
            return {"ok": False, "error": "unknown device"}
        inc = self.open_by_device.get(device_id)

        if action == "isolate":
            dev["state"] = DeviceState.QUARANTINED
            dev["quarantined_at"] = now
            if inc:
                inc["action"] = "quarantine"
                inc["timeline"].append({"ts": now, "t": fmt_ts(now),
                                        "label": "Manually isolated by homeowner",
                                        "level": "danger"})
            self._feed(now, "danger", f"QUARANTINE  {device_id} isolated manually")

        elif action == "restore":
            dev["state"] = DeviceState.NORMAL
            dev["quarantined_at"] = None
            self.windows[device_id] = []
            if inc:
                inc["status"] = IncidentStatus.RESOLVED
                inc["updated"] = now
                inc["timeline"].append({"ts": now, "t": fmt_ts(now),
                    "label": (note or "Device restored by homeowner")
                             + " — incident learned, behavioural model updated",
                    "level": "ok"})
                self.open_by_device.pop(device_id, None)
            self._feed(now, "ok", f"RESTORE  {device_id} back online; "
                                  f"incident recorded for learning")
            self._notify(now, "ok", f"{dev['name']} restored",
                         "The device is back on the network. The incident has "
                         "been stored locally and folded into its behaviour model.",
                         device_id)

        return {"ok": True}

    def _now(self) -> float:
        return time.time()

    # --- snapshot for the dashboard ------------------------------------------

    def snapshot(self, now: float) -> dict:
        states = list(self.devices.values())
        quarantined = [d for d in states if d["state"] == DeviceState.QUARANTINED]
        monitored = [d for d in states if d["state"] == DeviceState.MONITORED]
        open_inc = [i for i in self.incidents if i["status"] != IncidentStatus.RESOLVED]

        health = max(45, 100 - 10 * len(open_inc) - 5 * len(quarantined)
                     - 2 * len(monitored))

        dev_rows = []
        for d in states:
            recent = [e for e in self.windows.get(d["id"], [])
                      if e.kind == "conn" and e.ts >= now - 60]
            dev_rows.append({
                "id": d["id"], "name": d["name"], "dtype": d["dtype"],
                "ip": d["ip"], "mac": d["mac"], "state": d["state"],
                "known": d["known"],
                "cpm": round(len(recent), 1),
                "last": fmt_ts(d["last_seen"]) if d["last_seen"] else "—",
            })
        dev_rows.sort(key=lambda x: (x["state"] != "quarantined",
                                     x["state"] != "monitored", x["id"]))

        return {
            "clock": fmt_ts(now),
            "day": int(now // 86_400) + 1,
            "presence": self.presence,
            "health": health,
            "counts": {
                "devices": len(states),
                "normal": len(states) - len(quarantined) - len(monitored),
                "monitored": len(monitored),
                "quarantined": len(quarantined),
                "incidents": len(open_inc),
                "blocked": self.blocked_total,
            },
            "devices": dev_rows,
            "incidents": open_inc + [i for i in reversed(self.incidents)
                                     if i["status"] == IncidentStatus.RESOLVED][:5],
            "feed": list(reversed(self.feed[-70:])),
            "notifications": self.notifications[:6],
        }
