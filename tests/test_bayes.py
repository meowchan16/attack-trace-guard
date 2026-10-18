"""
Unit tests for Module 5 Naive Bayes Engine (modules/bayes.py).

Validates:
1. Hand-calculated example: unusual size + SYN + high rate yields posterior ~0.95 (within 0.01),
   with intermediate steps ~0.61 and ~0.90.
2. Normal packet (size 500, ACK, low rate) yields a posterior below prior (< 0.05).
3. Posterior is always strictly within [0.0, 1.0].
4. Monotonicity: More malicious evidence never lowers probability compared with less.
5. Prior sensitivity: Increasing/decreasing prior shifts posterior in the expected direction.
6. explain() returns one step per feature and last step posterior equals probability_malicious().
"""

import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.bayes import explain, probability_malicious, most_suspicious, DEFAULT_PRIOR


def test_hand_calculated_worked_example():
    """Unusual size + SYN + high rate yields posterior ~0.95 with steps ~0.61 and ~0.90."""
    attack_pkt = {
        "size": 40,      # unusual (< 60)
        "flags": "SYN",  # SYN present
        "src_ip": "203.0.113.99"
    }
    src_rate = 40.0      # high (> 15)

    exp = explain(attack_pkt, src_rate=src_rate, prior=0.05)

    assert exp["prior"] == 0.05
    steps = exp["steps"]
    assert len(steps) == 3

    # Step 1: Size
    assert steps[0]["feature"] == "size"
    assert steps[0]["likelihood_ratio"] == 30.0
    assert abs(steps[0]["posterior"] - 0.61) <= 0.01

    # Step 2: SYN
    assert steps[1]["feature"] == "syn"
    assert steps[1]["likelihood_ratio"] == 6.0
    assert abs(steps[1]["posterior"] - 0.90) <= 0.01

    # Step 3: Rate
    assert steps[2]["feature"] == "rate"
    assert steps[2]["likelihood_ratio"] == 2.0
    assert abs(steps[2]["posterior"] - 0.95) <= 0.01

    # Overall posterior
    assert abs(exp["posterior"] - 0.95) <= 0.01


def test_normal_packet_posterior_below_prior():
    """Normal packet (size 500, ACK, low rate) yields posterior < 0.05."""
    normal_pkt = {
        "size": 500,
        "flags": "ACK",
        "src_ip": "192.168.1.10"
    }
    src_rate = 5.0  # low (<= 15)

    post = probability_malicious(normal_pkt, src_rate=src_rate, prior=DEFAULT_PRIOR)
    assert post < DEFAULT_PRIOR
    assert post >= 0.0


def test_posterior_bounds():
    """Posterior probability must always remain strictly between 0 and 1."""
    test_cases = [
        ({"size": 40, "flags": "SYN"}, 50.0),
        ({"size": 500, "flags": "ACK"}, 2.0),
        ({"size": 9000, "flags": "PSH"}, 10.0),
        ({"size": 1337, "flags": "SYN"}, 100.0),
    ]

    for pkt, rate in test_cases:
        p = probability_malicious(pkt, rate)
        assert 0.0 <= p <= 1.0


def test_monotonicity_of_evidence():
    """Adding malicious features never lowers the posterior probability."""
    # 0 malicious features (typical size, ACK, low rate)
    p0 = probability_malicious({"size": 500, "flags": "ACK"}, src_rate=5.0)

    # 1 malicious feature (high rate only)
    p1 = probability_malicious({"size": 500, "flags": "ACK"}, src_rate=30.0)

    # 2 malicious features (high rate + SYN)
    p2 = probability_malicious({"size": 500, "flags": "SYN"}, src_rate=30.0)

    # 3 malicious features (high rate + SYN + unusual size)
    p3 = probability_malicious({"size": 40, "flags": "SYN"}, src_rate=30.0)

    assert p0 <= p1 <= p2 <= p3


def test_prior_sensitivity():
    """Varying the prior shifts the posterior in the same direction."""
    pkt = {"size": 40, "flags": "SYN"}
    rate = 40.0

    low_prior = 0.01
    mid_prior = 0.05
    high_prior = 0.20

    p_low = probability_malicious(pkt, rate, prior=low_prior)
    p_mid = probability_malicious(pkt, rate, prior=mid_prior)
    p_high = probability_malicious(pkt, rate, prior=high_prior)

    assert p_low < p_mid < p_high


def test_explain_matches_probability_malicious():
    """explain() returns one step per feature and last step posterior equals probability_malicious()."""
    pkt = {"size": 1337, "flags": "SYN"}
    rate = 25.0

    exp = explain(pkt, rate)
    assert len(exp["steps"]) == 3
    assert exp["steps"][-1]["posterior"] == exp["posterior"]
    assert exp["posterior"] == probability_malicious(pkt, rate)


def test_most_suspicious_packet_selection():
    """most_suspicious selects the packet with highest threat score, prioritizing unusual sizes."""
    window = [
        {"size": 500, "flags": "ACK", "src_ip": "203.0.113.99"},
        {"size": 40, "flags": "SYN", "src_ip": "203.0.113.99"},
        {"size": 1337, "flags": "SYN", "src_ip": "203.0.113.99"},
        {"size": 500, "flags": "ACK", "src_ip": "192.168.1.5"},
    ]

    selected = most_suspicious(window, "203.0.113.99", src_rate=40.0)
    assert selected is not None
    assert selected["size"] == 1337
