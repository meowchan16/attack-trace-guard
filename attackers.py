"""
Simulated attacker pool for Stage 8 demo.
Each entry provides IP, label, city, country, flag, and coordinates (lat, lon).
Uses reserved documentation IP ranges (RFC 5737: 203.0.113.x, 198.51.100.x, 192.0.2.x).
"""

import random
from typing import Any, Dict, List, Optional

ATTACKERS: List[Dict[str, Any]] = [
    {
        "ip": "203.0.113.99",
        "label": "Lagos NG",
        "city": "Lagos",
        "country": "Nigeria",
        "flag": "🇳🇬",
        "lat": 6.5244,
        "lon": 3.3792,
    },
    {
        "ip": "198.51.100.23",
        "label": "Moscow RU",
        "city": "Moscow",
        "country": "Russia",
        "flag": "🇷🇺",
        "lat": 55.7558,
        "lon": 37.6176,
    },
    {
        "ip": "192.0.2.77",
        "label": "Sao Paulo BR",
        "city": "São Paulo",
        "country": "Brazil",
        "flag": "🇧🇷",
        "lat": -23.5505,
        "lon": -46.6333,
    },
    {
        "ip": "203.0.113.45",
        "label": "Hanoi VN",
        "city": "Hanoi",
        "country": "Vietnam",
        "flag": "🇻🇳",
        "lat": 21.0278,
        "lon": 105.8342,
    },
    {
        "ip": "198.51.100.8",
        "label": "Frankfurt DE",
        "city": "Frankfurt",
        "country": "Germany",
        "flag": "🇩🇪",
        "lat": 50.1109,
        "lon": 8.6821,
    },
    {
        "ip": "192.0.2.150",
        "label": "Seoul KR",
        "city": "Seoul",
        "country": "South Korea",
        "flag": "🇰🇷",
        "lat": 37.5665,
        "lon": 126.9780,
    },
    {
        "ip": "203.0.113.12",
        "label": "Toronto CA",
        "city": "Toronto",
        "country": "Canada",
        "flag": "🇨🇦",
        "lat": 43.6532,
        "lon": -79.3832,
    },
    {
        "ip": "198.51.100.200",
        "label": "Mumbai IN",
        "city": "Mumbai",
        "country": "India",
        "flag": "🇮🇳",
        "lat": 19.0760,
        "lon": 72.8777,
    },
]

# Lookup map by IP
ATTACKER_MAP: Dict[str, Dict[str, Any]] = {a["ip"]: a for a in ATTACKERS}
ATTACKER_POOL = ATTACKERS

AGENCY_HQ = {
    "city": "London",
    "country": "United Kingdom",
    "lat": 51.5074,
    "lon": -0.1278,
}


def get_attacker(ip: str) -> Dict[str, Any]:
    """Retrieve simulated profile for an IP, or return a default profile if unrecognized."""
    if ip in ATTACKER_MAP:
        return ATTACKER_MAP[ip]
    return {
        "ip": ip,
        "label": f"Unknown ({ip})",
        "city": "Geneva",
        "country": "Switzerland",
        "flag": "🌐",
        "lat": 46.2044,
        "lon": 6.1432,
    }


def get_random_attacker() -> Dict[str, Any]:
    """Select a single random attacker profile from the pool."""
    return random.choice(ATTACKERS)


def get_botnet_attackers(count: int = 5) -> List[Dict[str, Any]]:
    """Select multiple distinct attacker profiles for a coordinated botnet attack."""
    k = min(count, len(ATTACKERS))
    return random.sample(ATTACKERS, k)
