"""
Unit tests for simulator.py.

Validates:
1. normal_packet fields are valid and sizes stay strictly within 40-1500 bytes.
2. attack_packet is a SYN to port 80 from the attacker IP with is_attack=True.
3. Blocked IPs are dropped by tick() and recorded in telemetry.
4. The rolling window never keeps packets older than 5 seconds.
5. tick() returns a summary dict with the expected keys.
"""

import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from simulator import normal_packet, attack_packet, Simulator


def test_normal_packet_validity():
    """Verify normal_packet structure, ranges, and types over multiple samples."""
    for _ in range(100):
        pkt = normal_packet()
        assert "ts" in pkt
        assert "src_ip" in pkt
        assert "dst_port" in pkt
        assert "size" in pkt
        assert "flags" in pkt
        assert pkt["is_attack"] is False

        # Destination port must be one of the specified standard service ports
        assert pkt["dst_port"] in [80, 443, 22, 53]

        # Flags must be ACK or PSH
        assert pkt["flags"] in ["ACK", "PSH"]

        # Size must be strictly clamped between 40 and 1500 bytes
        assert 40 <= pkt["size"] <= 1500
        assert isinstance(pkt["size"], int)

        # Source IP must be within 192.168.1.2 to 192.168.1.50
        assert pkt["src_ip"].startswith("192.168.1.")
        host_num = int(pkt["src_ip"].split(".")[-1])
        assert 2 <= host_num <= 50


def test_attack_packet_structure():
    """Verify attack_packet is a SYN to port 80 with is_attack=True and distinct sizes."""
    attacker_ip = "203.0.113.99"
    seen_sizes = set()

    for _ in range(100):
        pkt = attack_packet(attacker_ip=attacker_ip)
        assert pkt["src_ip"] == attacker_ip
        assert pkt["dst_port"] == 80
        assert pkt["flags"] == "SYN"
        assert pkt["is_attack"] is True
        assert pkt["size"] in [40, 1337, 9000]
        seen_sizes.add(pkt["size"])

    # Over 100 packets, 40 should be predominant
    assert 40 in seen_sizes


def test_blocked_ips_are_dropped():
    """Verify that packets from blocked IPs are dropped by tick() and counted as blocked."""
    sim = Simulator()
    attacker_ip = "203.0.113.99"
    sim.block_ip(attacker_ip)

    # Enable attack state so attack packets from attacker_ip are generated
    sim.attack_active = True
    summary = sim.tick()

    assert summary["blocked"] > 0
    # Confirm no packets in the rolling window belong to the blocked IP
    for pkt in sim.window:
        assert pkt["src_ip"] != attacker_ip


def test_rolling_window_pruning():
    """Verify the rolling window retains only packets from the last 5 seconds."""
    sim = Simulator(window_seconds=5.0)

    # Tick at t = 100.0
    sim.tick(now=100.0)
    assert len(sim.window) > 0
    for pkt in sim.window:
        assert pkt["_time"] == 100.0

    # Tick at t = 103.0 (t=100 packets are 3 seconds old, still retained)
    sim.tick(now=103.0)
    times = {pkt["_time"] for pkt in sim.window}
    assert 100.0 in times
    assert 103.0 in times

    # Tick at t = 106.0 (t=100 packets are now 6 seconds old > 5.0s, must be pruned)
    sim.tick(now=106.0)
    times_after = {pkt["_time"] for pkt in sim.window}
    assert 100.0 not in times_after, "Packets older than 5 seconds were not pruned"
    assert 103.0 in times_after
    assert 106.0 in times_after


def test_tick_summary_keys():
    """Verify tick() returns a summary dict containing the required telemetry keys."""
    sim = Simulator()
    summary = sim.tick()

    assert isinstance(summary, dict)
    assert summary["type"] == "traffic"
    assert "ts" in summary
    assert "packets" in summary and isinstance(summary["packets"], int)
    assert "blocked" in summary and isinstance(summary["blocked"], int)
    assert "avg_size" in summary and isinstance(summary["avg_size"], (int, float))
    assert summary["packets"] >= 3  # Normal packets range 3 to 7
    assert summary["blocked"] == 0  # Blocklist is empty


def test_block_ip_and_unblock_all():
    """Verify after block_ip packets are dropped, and unblock_all lets them through again."""
    sim = Simulator()
    attacker_ip = "203.0.113.99"
    sim.attack_active = True

    # 1. Block attacker IP -> packets from that IP are dropped
    sim.block_ip(attacker_ip)
    summary_blocked = sim.tick()
    assert summary_blocked["blocked"] > 0
    assert not any(p["src_ip"] == attacker_ip for p in sim.window)

    # 2. Unblock all -> packets from attacker IP pass through into window again
    sim.unblock_all()
    summary_unblocked = sim.tick()
    assert summary_unblocked["blocked"] == 0
    assert any(p["src_ip"] == attacker_ip for p in sim.window)

