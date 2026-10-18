"""
Unit tests for Module 4 Forward-Chaining Logic Engine (modules/logic.py).

Validates:
1. A flood of 40 SYN packets from one IP to port 80 within 1 second returns attack_type 'DDoS' with a non-empty proof_trace.
2. Normal traffic (random IPs, mixed ports, ACK/PSH) returns None.
3. One IP hitting 10 different ports within 5 seconds returns 'port_scan'.
4. One IP sending 12 packets to port 22 within 5 seconds returns 'brute_force'.
5. 10 SYN packets in one second does NOT trigger DDoS (below threshold of 15).
6. The engine terminates and derives 'malicious(X)' after 'ddos(X)'.
"""

import sys
import time
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.logic import detect, forward_chain, RULES, derive_base_facts
from simulator import normal_packet, attack_packet


def test_ddos_detection_and_proof_trace():
    """A flood of 40 SYN packets from one IP to port 80 within 1s returns 'DDoS' with proof trace."""
    now = 1000.0
    packets = []
    attacker_ip = "203.0.113.99"

    for _ in range(40):
        packets.append({
            "_time": now - 0.2,
            "src_ip": attacker_ip,
            "dst_port": 80,
            "flags": "SYN",
            "size": 40,
            "is_attack": True,
        })

    result = detect(packets, now=now)
    assert result is not None
    assert result["attack_type"] == "DDoS"
    assert result["src_ip"] == attacker_ip
    assert "proof_trace" in result
    assert isinstance(result["proof_trace"], list)
    assert len(result["proof_trace"]) >= 4

    # Verify proof trace components
    trace_text = "\n".join(result["proof_trace"])
    assert "SYN packets from 203.0.113.99" in trace_text
    assert "target port 80" in trace_text
    assert "=> DDoS" in trace_text
    assert "DDoS => malicious" in trace_text


def test_normal_traffic_returns_none():
    """Normal baseline traffic (ACK/PSH across internal IPs) returns None."""
    now = 1000.0
    packets = [normal_packet(ts=now - (i * 0.1)) for i in range(25)]

    result = detect(packets, now=now)
    assert result is None, f"Expected None for normal traffic, got {result}"


def test_port_scan_detection():
    """One IP hitting 10 different ports within 5 seconds triggers port_scan."""
    now = 1000.0
    scanner_ip = "198.51.100.42"
    packets = []

    for port in range(1001, 1011):  # 10 distinct destination ports
        packets.append({
            "_time": now - 1.5,
            "src_ip": scanner_ip,
            "dst_port": port,
            "flags": "SYN",
            "size": 40,
            "is_attack": True,
        })

    result = detect(packets, now=now)
    assert result is not None
    assert result["attack_type"] == "port_scan"
    assert result["src_ip"] == scanner_ip
    assert any("port scan" in line for line in result["proof_trace"])


def test_brute_force_detection():
    """One IP sending 12 connection attempts to port 22 within 5 seconds triggers brute_force."""
    now = 1000.0
    attacker_ip = "198.51.100.77"
    packets = []

    for i in range(12):  # 12 packets to port 22
        packets.append({
            "_time": now - (i * 0.3),
            "src_ip": attacker_ip,
            "dst_port": 22,
            "flags": "ACK",
            "size": 250,
            "is_attack": True,
        })

    result = detect(packets, now=now)
    assert result is not None
    assert result["attack_type"] == "brute_force"
    assert result["src_ip"] == attacker_ip
    assert any("brute force" in line for line in result["proof_trace"])


def test_below_threshold_syn_does_not_trigger_ddos():
    """10 SYN packets within 1 second does NOT trigger DDoS (threshold is > 15)."""
    now = 1000.0
    ip = "203.0.113.50"
    packets = []

    for _ in range(10):  # 10 packets <= 15
        packets.append({
            "_time": now - 0.5,
            "src_ip": ip,
            "dst_port": 80,
            "flags": "SYN",
            "size": 40,
            "is_attack": False,
        })

    result = detect(packets, now=now)
    assert result is None


def test_engine_terminates_and_derives_malicious():
    """The forward-chaining engine terminates at a fixed point and derives malicious(X) after ddos(X)."""
    base_facts = {
        ("high_syn_rate", "203.0.113.99"),
        ("single_target_port", "203.0.113.99", 80),
    }

    known_facts, derivations = forward_chain(base_facts, RULES)

    # Must contain ddos
    assert ("ddos", "203.0.113.99") in known_facts
    # Must also derive malicious via the ddos(X) -> malicious(X) rule
    assert ("malicious", "203.0.113.99") in known_facts

    # Verify order: ddos was derived before malicious
    conclusions = [d["conclusion"] for d in derivations]
    ddos_idx = conclusions.index(("ddos", "203.0.113.99"))
    malicious_idx = conclusions.index(("malicious", "203.0.113.99"))
    assert ddos_idx < malicious_idx
