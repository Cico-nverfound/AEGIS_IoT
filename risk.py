"""Risk scoring and response policy.

The AI layer never touches the network. Detectors produce evidence, the
risk engine turns evidence into a score under a deterministic, auditable
policy, and the response engine executes.  "AI proposes. Policy decides.
The system acts."
"""
from __future__ import annotations

from .devices import STRICT_CLASSES

NIGHT_HOURS = set(range(0, 6))

# Policy thresholds (risk score 0-99)
THRESHOLD_QUARANTINE = 70
THRESHOLD_BLOCK = 45
THRESHOLD_ALERT = 25


def score_risk(signals, cls: str, hour: int, presence: str) -> int:
    base = sum(s.weight for s in signals)
    mult = 1.0
    if hour in NIGHT_HOURS:
        mult *= 1.12          # 00:00-05:59
    if presence == "empty":
        mult *= 1.06          # nobody home
    if cls in STRICT_CLASSES:
        mult *= 1.05          # IoT devices have near-zero behavioural slack
    return min(99, round(base * mult))


def confidence(signals) -> int:
    codes = {s.code for s in signals}
    score = 60 + 7 * len(signals)
    if "beaconing" in codes:
        score += 8
    if "dga" in codes:
        score += 4
    if "lateral_movement" in codes:
        score += 4
    return min(94, score)


def decide(risk: int) -> str:
    if risk >= THRESHOLD_QUARANTINE:
        return "quarantine"
    if risk >= THRESHOLD_BLOCK:
        return "block"
    if risk >= THRESHOLD_ALERT:
        return "alert"
    return "allow"
