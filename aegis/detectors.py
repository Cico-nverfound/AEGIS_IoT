"""Deterministic anomaly detectors.

Each detector inspects the recent telemetry window of one device against its
learned baseline and returns zero or more `Signal`s — pieces of evidence.
No machine-learning black boxes here: every signal carries the measured
value that triggered it, so every decision is explainable.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict

from .devices import INFRA_ASNS, NOVELTY_MIN, NOVELTY_TOLERANCE
from .models import Signal

WINDOW = 300          # seconds of telemetry analysed per evaluation
RATE_WINDOW = 120     # window used for rate statistics
SENSITIVE_PORTS = {23, 2323, 445, 139, 1433, 3389, 37777}


def _shannon_entropy(label: str) -> float:
    if not label:
        return 0.0
    counts = Counter(label)
    n = len(label)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _prefix(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def detect(dev: dict, events: list, base: dict | None, night: bool,
           presence: str) -> list[Signal]:
    """Return evidence signals for one device's recent event window."""
    signals: list[Signal] = []
    cls = dev.get("cls", "unknown")
    now = max((e.ts for e in events), default=0.0)
    hour = int((now % 86_400) // 3600)

    dns = [e for e in events if e.kind == "dns" and e.ts >= now - WINDOW]
    conns = [e for e in events if e.kind == "conn" and e.ts >= now - WINDOW]
    ext = [e for e in conns if not e.data.get("internal")]
    lan = [e for e in conns if e.data.get("internal")]

    # Devices with no baseline (brand new / unknown) are treated strictly.
    if base is None:
        base = {"domains": [], "asns": [], "prefixes": [], "peers": [],
                "hour_conns_mean": [0.0] * 24, "hour_conns_std": [0.0] * 24,
                "hour_bytes_mean": [0.0] * 24, "hour_bytes_std": [0.0] * 24,
                "hour_share": [0.0] * 24}

    known_domains = set(base["domains"])
    known_asns = set(base["asns"])
    known_prefixes = set(base["prefixes"])
    known_peers = set(base["peers"])
    has_baseline = base is not None
    unknown_device = not has_baseline

    # --- 1. Novel domains / possible DGA -----------------------------------
    domains = [e.data.get("domain", "") for e in dns]
    novel = [d for d in domains if d and d not in known_domains]
    novel_set = sorted(set(novel))
    tol = NOVELTY_TOLERANCE.get(cls, 0.1)
    n_min = NOVELTY_MIN.get(cls, 3)
    if len(novel_set) >= n_min:
        ratio = len(novel_set) / max(1, len(set(domains)))
        weight = (8.0 + 18.0 * (1.0 - tol))
        if len(novel_set) >= n_min * 2:
            weight += 4
        signals.append(Signal(
            "novel_domains",
            "Burst of previously unseen domains",
            f"{len(novel_set)} new domains in 5 minutes "
            f"({ratio:.0%} of queries) — this device contacts "
            f"{len(known_domains)} known services and rarely explores new ones.",
            weight, f"+{len(novel_set)} new domains"))
        entropies = [_shannon_entropy(d.split(".")[0]) for d in novel_set]
        if entropies and statistics_mean(entropies) > 3.4 and len(novel_set) >= 4:
            signals.append(Signal(
                "dga",
                "High-entropy domain names (DGA pattern)",
                "New domains have randomised labels with average name entropy "
                f"{statistics_mean(entropies):.1f}, typical of domain-generation "
                "algorithms used by malware to locate C2 servers.",
                12.0, f"entropy {statistics_mean(entropies):.1f}"))

    # --- 2. Beaconing to a new network -------------------------------------
    # Grouped by /24: real C2 infrastructure rotates IPs inside one network.
    groups: dict[str, list[float]] = defaultdict(list)
    group_ips: dict[str, set] = defaultdict(set)
    for e in ext:
        dst = e.data.get("dst", "")
        pfx = _prefix(dst)
        if pfx not in known_prefixes:
            groups[pfx].append(e.ts)
            group_ips[pfx].add(dst)
    for pfx, times in groups.items():
        times = sorted(times)
        if len(times) < 4:
            continue
        iats = [b - a for a, b in zip(times, times[1:])]
        mean_iat = statistics_mean(iats)
        cv = (statistics_pstdev(iats) / mean_iat) if mean_iat else 9.0
        if 15 <= mean_iat <= 600 and cv < 0.5:
            signals.append(Signal(
                "beaconing",
                "Periodic beaconing to an unknown network",
                f"{len(times)} repeated connections into {pfx}.0/24 "
                f"({len(group_ips[pfx])} rotating IPs) every ~{mean_iat:.0f}s "
                f"(timing jitter {cv * 100:.0f}%). Machine-like regularity "
                "toward a never-before-seen network is the classic "
                "command-and-control beacon pattern.",
                24.0, f"every ~{mean_iat:.0f}s"))

    # --- 3. Upload volume anomaly ------------------------------------------
    bytes_up = sum(int(e.data.get("bytes_up", 0)) for e in ext
                   if e.ts >= now - WINDOW)
    h = hour
    mean_b5 = max(1.0, base["hour_bytes_mean"][h] / 12.0)
    std_b5 = max(mean_b5 * 0.3, base["hour_bytes_std"][h] / 12.0)
    z_b = (bytes_up - mean_b5) / (std_b5 + 1.0)
    ratio_b = bytes_up / mean_b5
    # A volume/rate surge only matters when something else is unknown:
    # a scheduled backup to the *known* vault endpoint is not an anomaly.
    has_novelty = unknown_device or bool(signals)
    if ratio_b >= 3.0 and z_b >= 3.0 and has_novelty:
        signals.append(Signal(
            "volume_spike",
            "Outbound traffic far above baseline",
            f"{bytes_up / 1_000_000:.1f} MB uploaded in 5 minutes vs a "
            f"baseline of {mean_b5 / 1_000_000:.2f} MB "
            f"({(ratio_b - 1) * 100:+.0f}%, {z_b:.1f}σ). "
            "Possible data exfiltration or unauthorised streaming.",
            12.0, f"{(ratio_b - 1) * 100:+.0f}% uploads"))

    # --- 4. Connection-rate anomaly ----------------------------------------
    recent = [e for e in ext if e.ts >= now - RATE_WINDOW]
    rate_per_min = len(recent) / (RATE_WINDOW / 60.0)
    expected = max(0.05, base["hour_conns_mean"][h] / 60.0)
    std_rate = max(0.05, base["hour_conns_std"][h] / 60.0)
    z_r = (rate_per_min - expected) / (std_rate + 0.05)
    if rate_per_min >= expected * 3 and z_r >= 3 and (unknown_device or signals):
        signals.append(Signal(
            "rate_spike",
            "Connection rate far above baseline",
            f"{rate_per_min:.1f} outbound connections/min vs "
            f"{expected:.2f} expected at this hour ({z_r:.1f}σ).",
            8.0, f"{rate_per_min / max(expected, 0.01):.1f}x rate"))

    # --- 5. New remote network (ASN) ---------------------------------------
    new_asns = sorted({e.data.get("asn", "") for e in ext
                       if e.data.get("asn") and e.data["asn"] != "-"
                       and e.data["asn"] not in known_asns
                       and e.data["asn"] not in INFRA_ASNS})
    if new_asns:
        signals.append(Signal(
            "new_asn",
            "Traffic to a never-seen network",
            f"Connections to {', '.join(new_asns)} — an autonomous system "
            "this device has never communicated with during the learning "
            "period, and not part of common cloud/CDN infrastructure.",
            8.0, ", ".join(new_asns)))

    # --- 6. Activity at unusual hours --------------------------------------
    share = base["hour_share"][h]
    if share < 0.008 and len(conns) >= 4:
        weight = 5.0 if cls in ("camera", "bulb", "plug", "sensor",
                                "appliance", "unknown") else 3.0
        signals.append(Signal(
            "unusual_hour",
            "Activity outside normal hours",
            f"Active at {hour:02d}:xx — a timeslot containing less than "
            f"{share * 100:.1f}% of this device's historical traffic.",
            weight, f"{hour:02d}:00 slot"))

    # --- 7. Lateral movement / internal scanning ---------------------------
    new_peers = sorted({e.data.get("dst", "") for e in lan
                        if e.data.get("dst") not in known_peers})
    hit_ports = {e.data.get("port") for e in lan
                 if e.data.get("port") in SENSITIVE_PORTS}
    if len(new_peers) >= 5 and hit_ports:
        signals.append(Signal(
            "lateral_movement",
            "Lateral movement across the LAN",
            f"Connections to {len(new_peers)} different internal hosts on "
            f"admin/Telnet ports ({', '.join(map(str, sorted(hit_ports)))}). "
            "An IoT device probing the local subnet is the classic worm/"
            "bot-propagation pattern (Mirai-style).",
            42.0, f"{len(new_peers)} LAN hosts probed"))
        if len(new_peers) >= 10:
            signals.append(Signal(
                "port_scan",
                "Internal port scan in progress",
                f"Connection sweep across {len(new_peers)} local addresses "
                "in under a minute — automated scanning behaviour.",
                14.0, f"{len(new_peers)} hosts swept"))

    return signals


# tiny local helpers (avoid importing statistics twice at module top for hot loop)
def statistics_mean(xs):
    return sum(xs) / len(xs)


def statistics_pstdev(xs):
    if len(xs) < 2:
        return 0.0
    m = statistics_mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))
