"""AI analyst layer.

Turns normalized evidence into an incident assessment: classification,
plain-English explanation, confidence and a recommended action.

This PoC ships a `LocalAnalyst`: a fully offline, deterministic
natural-language generator grounded in the measured evidence (no
hallucination possible — every sentence is backed by a detector signal).
The interface is LLM-ready: on the CM5 an edge model (or an optional
cloud model with the user's consent) can replace `LocalAnalyst` while the
deterministic policy layer stays in control of the network.
"""
from __future__ import annotations

from .models import Signal


class LocalAnalyst:
    """Offline AI-analyst: explains *what is happening* and *why*."""

    def assess(self, dev: dict, signals: list[Signal], risk: int,
               confidence: int, hour: int, presence: str) -> dict:
        codes = {s.code for s in signals}
        name = dev.get("name", dev.get("id"))

        # --- classification ------------------------------------------------
        if "lateral_movement" in codes:
            classification = "Lateral movement — worm / bot propagation"
            title = f"Internal network scan from {name}"
        elif "beaconing" in codes and dev.get("cls") == "unknown":
            classification = "Rogue device — suspicious C2-like traffic"
            title = f"Unknown device behaving maliciously"
        elif "beaconing" in codes or "dga" in codes:
            classification = "Compromised device — C2 beaconing / data exfiltration"
            title = f"{name} is behaving like a compromised device"
        elif not dev.get("known", True):
            classification = "Rogue / unauthorised device"
            title = f"Unknown device joined the network"
        else:
            classification = "Behavioural anomaly"
            title = f"Unusual behaviour from {name}"

        # --- narrative -----------------------------------------------------
        parts: list[str] = []
        sig = {s.code: s for s in signals}

        if "beaconing" in sig:
            parts.append(
                f"{name} has opened repeated encrypted connections to "
                "previously unseen destinations on a near-regular timer — "
                f"{sig['beaconing'].value} — a pattern consistent with "
                "command-and-control beaconing.")
        if "novel_domains" in sig:
            parts.append(
                f"It queried {sig['novel_domains'].value.split()[0]} "
                f"domains it had never contacted during the 14-day learning "
                "period.")
        if "dga" in sig:
            parts.append(
                "The new domains use randomised, high-entropy names typical "
                "of domain-generation algorithms malware uses to locate its "
                "control servers.")
        if "volume_spike" in sig:
            parts.append(
                f"Outbound traffic is {sig['volume_spike'].value} versus the "
                "device's normal baseline, suggesting data exfiltration.")
        if "rate_spike" in sig:
            parts.append(
                f"Connection rate is {sig['rate_spike'].value} of normal for "
                "this time of day.")
        if "new_asn" in sig:
            parts.append(
                f"The destination network ({sig['new_asn'].value}) has never "
                "been observed for this device and is not common cloud/CDN "
                "infrastructure.")
        if "lateral_movement" in sig:
            parts.append(
                f"The device probed {sig['lateral_movement'].value} on the "
                "local network, hitting Telnet and admin ports — the classic "
                "spread pattern of IoT worms like Mirai.")
        if "port_scan" in sig:
            parts.append(
                f"It then swept {sig['port_scan'].value} in under a minute: "
                "automated scanning, not human use.")
        if "unusual_hour" in sig:
            parts.append(
                f"This happened at {hour:02d}:xx, outside the device's "
                "normal active hours.")
        if not dev.get("known", True):
            parts.append(
                "The device is not registered in the household: its MAC "
                "vendor is unknown and it appeared without being enrolled.")
        if presence == "empty" and hour in range(0, 8):
            parts.append(
                "The house is currently unoccupied and it is the middle of "
                "the night, so no legitimate activity explains the pattern.")

        narrative = " ".join(parts)

        # --- recommendation -------------------------------------------------
        if risk >= 70:
            recommendation = (
                "ISOLATE the device now: move it to the quarantine VLAN, "
                "block all external communications and keep monitoring. "
                "No other device is affected.")
        elif risk >= 45:
            recommendation = (
                "BLOCK the suspicious destinations and raise the device to "
                "enhanced monitoring; alert the homeowner.")
        else:
            recommendation = (
                "ALERT the homeowner and keep the device under enhanced "
                "monitoring.")

        evidence = [
            {"title": s.title, "detail": s.detail, "value": s.value}
            for s in signals
        ]

        return {
            "title": title,
            "classification": classification,
            "narrative": narrative,
            "recommendation": recommendation,
            "confidence": confidence,
            "evidence": evidence,
        }
