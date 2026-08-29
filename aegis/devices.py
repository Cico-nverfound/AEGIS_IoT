"""Device catalog for the simulated home network.

Each device has a behavioural profile: the destinations it normally talks
to, typical traffic volumes and ports. These profiles drive the traffic
simulator and become the ground truth the baselines are learned from.
"""
from __future__ import annotations

# Well-known infrastructure ASNs. Connections to these are never treated as
# "new destination network" anomalies on their own (reduces false positives).
INFRA_ASNS = {
    "AS15169": "Google",
    "AS16509": "Amazon AWS",
    "AS13335": "Cloudflare",
    "AS20940": "Akamai",
    "AS54113": "Fastly",
    "AS8075":  "Microsoft",
    "AS714":   "Apple",
    "AS32934": "Meta",
}

# Attacker infrastructure used by the simulated scenarios.
ATTACK_ASN = "AS66613"
ATTACK_ASN_NAME = "SHADYNET-1 (unknown)"
ATTACK_PREFIX = "45.155.20"

# Device classes with strict behavioural expectations (IoT).
STRICT_CLASSES = {"camera", "bulb", "plug", "sensor", "appliance", "unknown"}

# How tolerant the novel-domain detector is per class (fraction of new
# domains considered unsurprising) and minimum burst size to react.
NOVELTY_TOLERANCE = {
    "phone":    0.85,
    "laptop":   0.80,
    "tv":       0.40,
    "speaker":  0.45,
    "printer":  0.50,
    "console":  0.60,
    "nas":      0.10,
    "camera":   0.08,
    "bulb":     0.05,
    "plug":     0.05,
    "sensor":   0.05,
    "unknown":  0.00,
}
NOVELTY_MIN = {
    "phone": 12, "laptop": 10, "tv": 6, "speaker": 6, "printer": 6,
    "console": 8, "nas": 3, "camera": 3, "bulb": 3, "plug": 3,
    "sensor": 3, "unknown": 3,
}

# Internal network
SUBNET = "10.0.0"

# Device catalog: (profile fields)
# domains: list of (domain, asn, ip /24 prefix, weight)
CATALOG = [
    {
        "id": "camera-01", "name": "SecureView Cam · Entrance",
        "dtype": "IP camera", "cls": "camera",
        "mac": "b8:27:eb:c5:01:31", "ip": f"{SUBNET}.31",
        "domains": [
            ("relay.secureview-cam.net", "AS64214", "185.63.9", 10),
            ("api.secureview-cam.net",   "AS64214", "185.63.9", 6),
            ("time.secureview-cam.net",  "AS64214", "185.63.9", 2),
            ("pool.ntp.org",             "AS15169", "216.239.35", 2),
        ],
        "ports": [443, 123], "bytes_up": 90_000, "bytes_down": 250_000,
    },
    {
        "id": "camera-02", "name": "SecureView Cam · Patio",
        "dtype": "IP camera", "cls": "camera",
        "mac": "b8:27:eb:c5:01:32", "ip": f"{SUBNET}.32",
        "domains": [
            ("relay.secureview-cam.net", "AS64214", "185.63.10", 10),
            ("api.secureview-cam.net",   "AS64214", "185.63.10", 6),
            ("pool.ntp.org",             "AS15169", "216.239.35", 2),
        ],
        "ports": [443, 123], "bytes_up": 85_000, "bytes_down": 240_000,
    },
    {
        "id": "tv-01", "name": "Samsung TV · Living Room",
        "dtype": "smart TV", "cls": "tv",
        "mac": "74:45:ce:4a:90:50", "ip": f"{SUBNET}.50",
        "domains": [
            ("api.samsungcloud.com",  "AS134214", "211.114.0", 6),
            ("samsungads.com",        "AS134214", "211.114.0", 4),
            ("netflix.com",           "AS40027",  "52.12.10", 8),
            ("youtube.com",           "AS15169",  "142.250.4", 8),
            ("disney-plus.net",       "AS16509",  "54.230.1", 4),
            ("akamaihd.net",          "AS20940",  "23.45.6", 5),
        ],
        "ports": [443, 80], "bytes_up": 40_000, "bytes_down": 5_000_000,
    },
    {
        "id": "phone-01", "name": "Pixel Phone",
        "dtype": "smartphone", "cls": "phone",
        "mac": "74:45:ce:11:22:21", "ip": f"{SUBNET}.21",
        "domains": [
            ("android.googleapis.com", "AS15169", "142.250.9", 10),
            ("google.com",             "AS15169", "142.250.10", 10),
            ("whatsapp.net",           "AS32934", "157.240.0", 8),
            ("instagram.com",          "AS32934", "157.240.1", 6),
            ("telegram.org",           "AS62041", "149.154.1", 6),
            ("spotify.com",            "AS29518", "35.186.2", 5),
            ("tiktokv.com",            "AS138699","161.117.0", 4),
            ("apple.com",              "AS714",   "17.253.0", 2),
            ("cloudflare.com",         "AS13335", "104.16.0", 2),
        ],
        "ports": [443, 5228], "bytes_up": 120_000, "bytes_down": 900_000,
    },
    {
        "id": "laptop-01", "name": "Work Laptop",
        "dtype": "laptop", "cls": "laptop",
        "mac": "f0:18:98:33:44:22", "ip": f"{SUBNET}.22",
        "domains": [
            ("github.com",          "AS36459",  "140.82.1", 8),
            ("slack.com",           "AS16509",  "52.9.0", 6),
            ("office365.com",       "AS8075",   "40.96.0", 8),
            ("zoom.us",             "AS16509",  "3.235.0", 4),
            ("googleapis.com",      "AS15169",  "142.250.1", 6),
            ("npmjs.org",           "AS13335",  "104.16.1", 3),
        ],
        "ports": [443, 22], "bytes_up": 200_000, "bytes_down": 1_500_000,
    },
    {
        "id": "nas-01", "name": "Home NAS",
        "dtype": "NAS server", "cls": "nas",
        "mac": "00:11:32:77:88:10", "ip": f"{SUBNET}.10",
        "domains": [
            # Nightly encrypted backup at 03:30 (learned schedule in baseline)
            ("vault.nasvault.io",  "AS64999", "104.248.50", 20),
            ("update.nasvendor.com", "AS64998", "45.33.2", 1),
        ],
        "ports": [443], "bytes_up": 50_000_000, "bytes_down": 2_000_000,
    },
    {
        "id": "speaker-01", "name": "Smart Speaker",
        "dtype": "smart speaker", "cls": "speaker",
        "mac": "f0:81:1f:55:66:23", "ip": f"{SUBNET}.23",
        "domains": [
            ("api.amazonalexa.com",  "AS16509", "52.20.10", 10),
            ("avs-alexa.amazon.com", "AS16509", "52.20.10", 8),
            ("pool.ntp.org",         "AS15169", "216.239.35", 2),
        ],
        "ports": [443, 8883], "bytes_up": 30_000, "bytes_down": 120_000,
    },
    {
        "id": "bulb-01", "name": "TinyLight Bulb · Living",
        "dtype": "smart bulb", "cls": "bulb",
        "mac": "9c:8e:cd:99:01:61", "ip": f"{SUBNET}.61",
        "domains": [
            ("api.tinylight.io",  "AS64501", "51.222.7", 6),
            ("mqtt.tinylight.io", "AS64501", "51.222.7", 10),
        ],
        "ports": [8883, 443], "bytes_up": 2_000, "bytes_down": 1_000,
    },
    {
        "id": "bulb-02", "name": "TinyLight Bulb · Bedroom",
        "dtype": "smart bulb", "cls": "bulb",
        "mac": "9c:8e:cd:99:02:62", "ip": f"{SUBNET}.62",
        "domains": [
            ("api.tinylight.io",  "AS64501", "51.222.8", 6),
            ("mqtt.tinylight.io", "AS64501", "51.222.8", 10),
        ],
        "ports": [8883, 443], "bytes_up": 2_000, "bytes_down": 1_000,
    },
    {
        "id": "plug-01", "name": "Smart Plug · Coffee",
        "dtype": "smart plug", "cls": "plug",
        "mac": "9c:8e:cd:ab:03:63", "ip": f"{SUBNET}.63",
        "domains": [
            ("api.smartplug.co",  "AS64502", "167.99.8", 6),
            ("mqtt.smartplug.co", "AS64502", "167.99.8", 10),
        ],
        "ports": [8883, 443], "bytes_up": 3_000, "bytes_down": 1_500,
    },
    {
        "id": "console-01", "name": "Game Console",
        "dtype": "game console", "cls": "console",
        "mac": "e0:5f:45:cc:04:70", "ip": f"{SUBNET}.70",
        "domains": [
            ("xboxlive.com",    "AS8075",  "20.42.0", 10),
            ("steamserver.net", "AS32590", "205.185.0", 8),
            ("epicgames.com",   "AS16509", "3.238.0", 4),
        ],
        "ports": [443, 3074], "bytes_up": 150_000, "bytes_down": 2_000_000,
    },
    {
        "id": "printer-01", "name": "Laser Printer",
        "dtype": "printer", "cls": "printer",
        "mac": "8c:85:90:dd:05:40", "ip": f"{SUBNET}.40",
        "domains": [
            ("support.hp.com", "AS16509", "15.220.0", 3),
            ("pool.ntp.org",   "AS15169", "216.239.35", 1),
        ],
        "ports": [443, 9100], "bytes_up": 5_000, "bytes_down": 20_000,
    },
    {
        "id": "sensor-01", "name": "Climate Thermostat",
        "dtype": "thermostat", "cls": "sensor",
        "mac": "9c:8e:cd:ef:06:80", "ip": f"{SUBNET}.80",
        "domains": [
            ("api.climato.io",  "AS64503", "159.65.9", 6),
            ("mqtt.climato.io", "AS64503", "159.65.9", 10),
        ],
        "ports": [8883, 443], "bytes_up": 1_500, "bytes_down": 1_000,
    },
]

CATALOG_BY_ID = {d["id"]: d for d in CATALOG}

# Local peers that legitimate devices sometimes talk to (baseline LAN traffic).
INTERNAL_PEERS = {
    f"{SUBNET}.10": "nas-01",
    f"{SUBNET}.40": "printer-01",
    f"{SUBNET}.31": "camera-01",
    f"{SUBNET}.32": "camera-02",
    f"{SUBNET}.50": "tv-01",
}


def hourly_rate(cls: str, hour: int) -> float:
    """Mean events per hour for a device class at a given hour-of-day."""
    night = hour < 7
    evening = 18 <= hour < 24
    work = 9 <= hour < 18
    table = {
        "camera":  12.0,                                  # 24/7 keep-alives
        "sensor":  3.0,                                   # periodic telemetry
        "phone":   2.0 if night else 22.0,
        "laptop":  1.5 if night else (26.0 if work else 8.0),
        "tv":      0.4 if night else (3.0 if work else (26.0 if evening else 6.0)),
        "speaker": 0.8 if night else 8.0,
        "bulb":    0.3 if not evening else 7.0,
        "plug":    0.3 if not evening else 5.0,
        "nas":     0.2,                                   # backups scheduled
        "console": 0.4 if not evening else (18.0 if evening else 1.0),
        "printer": 0.2 if (night or not work) else 3.0,
    }
    return table.get(cls, 2.0)
