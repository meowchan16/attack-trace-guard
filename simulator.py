"""
Traffic simulator for the Boutique Cybersecurity Agency Dashboard.

Generates:
- Normal background estate traffic (Gaussian size distribution, ports 80/443/22/53, flags ACK/PSH).
- Coordinated SYN attack packets (port 80, flag SYN, distinct payload sizes).
- A rolling 5-second in-memory inspection window (pruned by timestamp).
- Blocklist enforcement dropping denied traffic before entry into window.
- Real-time 1-second summary telemetry dictionaries.
"""

from collections import deque
from datetime import datetime, timezone
import random
import time
from typing import Any, Deque, Dict, Optional, Set


def normal_packet(ts: Optional[float] = None) -> Dict[str, Any]:
    """
    Generate a single benign internal network packet.
    - Source IP: 192.168.1.2 to 192.168.1.50
    - Destination Port: random choice from [80, 443, 22, 53]
    - Size: Gaussian mean 500, standard deviation 120, clamped to 40..1500 bytes
    - Flags: ACK or PSH
    - is_attack: False
    """
    now_ts = ts if ts is not None else time.time()
    iso_ts = datetime.fromtimestamp(now_ts, timezone.utc).isoformat()
    host = random.randint(2, 50)
    src_ip = f"192.168.1.{host}"
    dst_port = random.choice([80, 443, 22, 53])

    # Gaussian distribution clamped between 40 and 1500 bytes
    raw_size = random.gauss(500, 120)
    size = int(max(40, min(1500, round(raw_size))))

    flags = random.choice(["ACK", "PSH"])

    return {
        "ts": iso_ts,
        "_time": now_ts,
        "src_ip": src_ip,
        "dst_port": dst_port,
        "size": size,
        "flags": flags,
        "is_attack": False,
    }


def attack_packet(attacker_ip: str = "203.0.113.99", ts: Optional[float] = None) -> Dict[str, Any]:
    """
    Generate an adversarial probe packet.
    - Destination Port: 80
    - Flags: SYN
    - Size: mostly 40 bytes with occasional distinctive sizes (1337 or 9000 bytes)
    - is_attack: True
    """
    now_ts = ts if ts is not None else time.time()
    iso_ts = datetime.fromtimestamp(now_ts, timezone.utc).isoformat()

    # Mostly 40 bytes (standard TCP SYN), occasionally 1337 or 9000 bytes
    rand_val = random.random()
    if rand_val < 0.08:
        size = 1337
    elif rand_val < 0.15:
        size = 9000
    else:
        size = 40

    return {
        "ts": iso_ts,
        "_time": now_ts,
        "src_ip": attacker_ip,
        "dst_port": 80,
        "size": size,
        "flags": "SYN",
        "is_attack": True,
    }


class Simulator:
    """
    Simulates network ingress traffic with an in-memory rolling window,
    IP blocklist, and optional attack state.
    """

    def __init__(self, window_seconds: float = 5.0):
        self.window_seconds = window_seconds
        self.window: Deque[Dict[str, Any]] = deque()
        self.blocklist: Set[str] = set()
        self.attack_active: bool = False
        self._attack_until: Optional[float] = None

    def start_attack(self, duration: float = 8.0) -> None:
        """Activate simulated attack for a designated duration in seconds."""
        self.attack_active = True
        self._attack_until = time.time() + duration

    def stop_attack(self) -> None:
        """Deactivate simulated attack immediately."""
        self.attack_active = False
        self._attack_until = None

    def block_ip(self, ip: str) -> None:
        """Add an IP to the blocklist and remove any buffered packets from it."""
        self.blocklist.add(ip)
        self.clear_attack_traffic(ip)

    def unblock_ip(self, ip: str) -> None:
        """Remove an IP from the blocklist."""
        self.blocklist.discard(ip)

    def unblock_all(self) -> None:
        """Clear all IPs from the blocklist."""
        self.blocklist.clear()

    def clear_attack_traffic(self, ip: Optional[str] = None) -> None:
        """Remove attack packets (or packets from a specific IP) from the rolling window."""
        if ip is not None:
            self.window = deque([p for p in self.window if p.get("src_ip") != ip])
        else:
            self.window = deque([p for p in self.window if not p.get("is_attack", False)])

    def prune_window(self, current_time: float) -> None:
        """Remove all packets older than window_seconds (5.0s) from the rolling deque."""
        cutoff = current_time - self.window_seconds
        while self.window and self.window[0]["_time"] < cutoff:
            self.window.popleft()

    def tick(self, now: Optional[float] = None) -> Dict[str, Any]:
        """
        Execute one 1-second simulation step:
        - Checks and expires attack state if timer elapsed
        - Generates normal traffic (3 to 7 packets)
        - Generates attack traffic (~40 packets) if attack_active
        - Filters blocked packets
        - Appends accepted packets to the rolling window
        - Prunes packets older than 5 seconds
        - Returns a telemetry summary dictionary
        """
        current_time = now if now is not None else time.time()
        iso_ts = datetime.fromtimestamp(current_time, timezone.utc).isoformat()

        # Check attack timer expiration
        if self.attack_active and self._attack_until is not None:
            if current_time >= self._attack_until:
                self.stop_attack()

        # 1. Generate packet batch for this tick
        batch = []
        normal_count = random.randint(3, 7)
        for _ in range(normal_count):
            batch.append(normal_packet(ts=current_time))

        if self.attack_active:
            attack_count = random.randint(38, 42)
            for _ in range(attack_count):
                batch.append(attack_packet(ts=current_time))

        # 2. Process batch against blocklist
        accepted_count = 0
        blocked_count = 0
        accepted_sizes = []

        for pkt in batch:
            if pkt["src_ip"] in self.blocklist:
                blocked_count += 1
            else:
                accepted_count += 1
                accepted_sizes.append(pkt["size"])
                self.window.append(pkt)

        # 3. Prune packets older than 5 seconds from rolling window
        self.prune_window(current_time)

        # 4. Compute telemetry metrics
        avg_size = round(sum(accepted_sizes) / accepted_count, 1) if accepted_count > 0 else 0.0

        return {
            "type": "traffic",
            "ts": iso_ts,
            "packets": accepted_count,
            "blocked": blocked_count,
            "avg_size": avg_size,
        }
