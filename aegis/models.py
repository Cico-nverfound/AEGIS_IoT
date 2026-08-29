"""Core data models for AEGIS."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# --- Device / incident states ----------------------------------------------

class DeviceState:
    NORMAL = "normal"
    MONITORED = "monitored"
    QUARANTINED = "quarantined"


class IncidentStatus:
    OPEN = "open"            # detected, response in progress
    CONTAINED = "contained"  # response enforced, network stable
    RESOLVED = "resolved"    # user / policy restored the device


# --- Events -----------------------------------------------------------------

@dataclass
class Event:
    """A single telemetry event flowing through the engine.

    Kinds:
      dns      : DNS query            data: domain
      conn     : network connection   data: dst, port, proto, asn, asn_name,
                                       domain, bytes_up, bytes_down, internal
      join     : device joined network data: name, mac, vendor, dtype
      context  : home context         data: presence (occupied|empty)
      blocked  : response enforced    data: dst, reason
      note     : system note
    """
    ts: float
    kind: str
    device: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = {"ts": self.ts, "kind": self.kind, "device": self.device}
        out.update(self.data)
        return out


@dataclass
class Signal:
    """A single piece of evidence produced by a detector."""
    code: str
    title: str
    detail: str
    weight: float
    value: str = ""          # short measured value for the UI

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
            "weight": round(self.weight, 1),
            "value": self.value,
        }
