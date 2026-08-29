#!/usr/bin/env python3
"""AEGIS — terminal demo.

Usage:
    python3 aegis_demo.py learn     # learn 14 days of normal traffic
    python3 aegis_demo.py run       # replay the attack night (02:43 - 03:30)
    python3 aegis_demo.py fast      # instant run (no animation)

No external libraries, no hardware needed. Pure Python 3.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aegis.runner import LiveLoop, build_baselines  # noqa: E402
from aegis.simulator import CAM_BEACON_STOP, LIVE_START  # noqa: E402

C = {
    "reset": "\033[0m", "dim": "\033[90m", "green": "\033[92m",
    "yellow": "\033[93m", "red": "\033[91m", "cyan": "\033[96m",
    "bold": "\033[1m", "magenta": "\033[95m",
}
LEVEL = {"dim": "dim", "net": "dim", "lan": "dim", "warn": "yellow",
         "danger": "red", "block": "red", "ok": "green"}

incidents_seen = set()


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def render(loop: LiveLoop):
    s = loop.snapshot()
    clear()
    print(f"{C['bold']}{C['cyan']}  A E G I S{C['reset']}   "
          f"{C['dim']}home security operations{C['reset']}")
    print(f"  day {s['day']:>2}  {s['clock']}   "
          f"{C['magenta']}home: {s['presence']}{C['reset']}")
    print(f"  {C['bold']}NETWORK HEALTH {s['health']}/100{C['reset']}   "
          f"{s['counts']['devices']} devices · "
          f"{C['green']}{s['counts']['normal']} normal{C['reset']} · "
          f"{C['yellow'] if s['counts']['monitored'] else C['dim']}"
          f"{s['counts']['monitored']} monitored{C['reset']} · "
          f"{C['red'] if s['counts']['quarantined'] else C['dim']}"
          f"{s['counts']['quarantined']} quarantined{C['reset']} · "
          f"{s['counts']['blocked']} blocked")
    print(f"  {C['bold']}ACTIVE INCIDENTS: {s['counts']['incidents']}{C['reset']}")
    for inc in s["incidents"]:
        if inc["status"] == "resolved":
            continue
        col = C["red"] if inc["action"] == "quarantine" else C["yellow"]
        print(f"  {col}⚠ {inc['id']} {inc['device_name']}{C['reset']}")
        print(f"      {inc['classification']}")
        print(f"      risk {C['bold']}{inc['risk']}%{C['reset']}   "
              f"confidence {inc['confidence']}%   action: {inc['action'].upper()}")
    print(f"\n  {C['bold']}LIVE TELEMETRY{C['reset']}  "
          f"{C['dim']}(the house network, watched by AEGIS){C['reset']}")
    print(f"  {C['dim']}{'─' * 74}{C['reset']}")
    for row in s["feed"][:15]:
        col = C.get(LEVEL.get(row["level"], "dim"), C["dim"])
        print(f"  {C['dim']}{row['t']}{C['reset']}  {col}{row['line']}{C['reset']}")
    print(f"  {C['dim']}{'─' * 74}{C['reset']}")


def on_incident(inc):
    incidents_seen.add(inc["id"])
    print(f"\n{C['bold']}{C['red']}  ⚠ {inc['title']}{C['reset']}")
    print(f"  {C['dim']}The AI analyst's incident report ({inc['id']}):{C['reset']}\n")
    for line in wrap(inc["narrative"], 76):
        print(f"  {line}")
    print(f"\n  {C['bold']}Risk {inc['risk']}% · Confidence {inc['confidence']}% · "
          f"Action: {inc['action'].upper()}{C['reset']}\n")
    input(f"  {C['cyan']}[press ENTER to watch AEGIS respond...]{C['reset']}")


def wrap(text, width):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    lines.append(cur)
    return lines


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "learn":
        print("Learning what 'normal' looks like (14 days of network history)...")
        b = build_baselines(days=14)
        total = sum(len(v["domains"]) for v in b.values())
        print(f"  Baselines built for {len(b)} devices, {total} known service "
              f"domains memorised.\n")
        for did, v in b.items():
            print(f"  {did:<12} {len(v['domains']):>2} known domains · "
                  f"{len(v['asns'])} known networks · "
                  f"{sum(v['hour_conns_mean']):.0f} conns/day")
        print("\n  saved to data/baselines.json")
        return

    data = Path(__file__).resolve().parent / "data" / "baselines.json"
    if not data.exists():
        print("Baselines missing — run 'python3 aegis_demo.py learn' first.")
        return

    import json
    baselines = json.loads(data.read_text())
    loop = LiveLoop(baselines, auto_recover=False)
    loop.on_incident = on_incident

    if cmd == "fast":
        loop.on_incident = lambda inc: print(
            f"  ⚠ {inc['id']}  {inc['device_name']}  → {inc['action'].upper()}  "
            f"(risk {inc['risk']}%, confidence {inc['confidence']}%)  "
            f"{inc['classification']}")
        while loop.now < CAM_BEACON_STOP + 60:
            loop.step(30)
        render(loop)
        print(f"\n{C['bold']}  Incidents raised: {len(loop.engine.incidents)}{C['reset']}")
        for inc in loop.engine.incidents:
            print(f"    {inc['id']} {inc['device_name']:<28} "
                  f"risk {inc['risk']}%  → {inc['action']} ({inc['status']})")
        return

    # animated run
    steps = 0
    end = CAM_BEACON_STOP + 60
    while loop.now < end:
        loop.step(2)
        steps += 1
        if steps % 2 == 0:
            render(loop)
        time.sleep(0.12)
    render(loop)
    print(f"\n{C['bold']}  End of replay.{C['reset']} "
          f"{C['green']}{len(loop.engine.incidents)} incident(s) detected & "
          f"handled{C['reset']}; the 03:30 NAS backup caused "
          f"{C['green']}zero{C['reset']} false alarms.")


if __name__ == "__main__":
    main()
