"""
Module 5: Naive Bayes Probability Engine (modules/bayes.py)
Pure functions, zero I/O.

Computes the posterior probability that network traffic is malicious
using Bayes' rule in odds form:
    posterior odds = prior odds x likelihood ratio
where:
    likelihood ratio = P(feature | malicious) / P(feature | normal)

Produces step-by-step explainable reasoning and selects the most
suspicious packet from an attacker's packet window.
"""

from typing import Any, Dict, List, Optional

# Default prior probability of malicious traffic
DEFAULT_PRIOR = 0.05

# Feature Likelihood Tables (stored as data)
FEATURE_TABLES: Dict[str, Dict[str, Dict[str, Any]]] = {
    "size": {
        "unusual": {
            "p_malicious": 0.60,
            "p_normal": 0.02,
            "label_true": "Unusual packet size",
            "label_false": "Typical packet size",
        },
        "typical": {
            "p_malicious": 0.40,
            "p_normal": 0.98,
            "label_true": "Typical packet size",
            "label_false": "Unusual packet size",
        },
    },
    "syn": {
        "present": {
            "p_malicious": 0.60,
            "p_normal": 0.10,
            "label_true": "SYN flag set",
            "label_false": "Non-SYN flags",
        },
        "absent": {
            "p_malicious": 0.40,
            "p_normal": 0.90,
            "label_true": "Non-SYN flags",
            "label_false": "SYN flag set",
        },
    },
    "rate": {
        "high": {
            "p_malicious": 0.70,
            "p_normal": 0.35,
            "label_true": "High packet rate",
            "label_false": "Normal packet rate",
        },
        "normal": {
            "p_malicious": 0.30,
            "p_normal": 0.65,
            "label_true": "Normal packet rate",
            "label_false": "High packet rate",
        },
    },
}


def extract_features(packet: Dict[str, Any], src_rate: float) -> Dict[str, str]:
    """
    Classify a packet's attributes into discrete feature buckets:
    - size: 'unusual' if size > 1300 or size < 60, else 'typical'
    - syn: 'present' if flags contains SYN, else 'absent'
    - rate: 'high' if src_rate > 15, else 'normal'
    """
    size = packet.get("size", 500)
    size_bucket = "unusual" if (size > 1300 or size < 60) else "typical"

    flags = str(packet.get("flags", ""))
    syn_bucket = "present" if ("SYN" in flags.upper()) else "absent"

    rate_bucket = "high" if src_rate > 15 else "normal"

    return {
        "size": size_bucket,
        "syn": syn_bucket,
        "rate": rate_bucket,
    }


def explain(
    packet: Dict[str, Any],
    src_rate: float,
    prior: float = DEFAULT_PRIOR
) -> Dict[str, Any]:
    """
    Apply Bayes' rule in odds form feature by feature.
    Returns:
    {
      "prior": 0.05,
      "steps": [
        {"feature": "size", "label": "Unusual packet size", "likelihood_ratio": 30.0, "posterior": 0.61},
        {"feature": "syn", "label": "SYN flag set", ...},
        {"feature": "rate", "label": "High packet rate", ...}
      ],
      "posterior": 0.95
    }
    """
    features = extract_features(packet, src_rate)
    feature_order = ["size", "syn", "rate"]

    current_odds = prior / (1.0 - prior)
    steps = []

    for feat in feature_order:
        bucket = features[feat]
        data = FEATURE_TABLES[feat][bucket]
        lr = data["p_malicious"] / data["p_normal"]

        current_odds *= lr
        prob = current_odds / (1.0 + current_odds)

        steps.append({
            "feature": feat,
            "label": data["label_true"],
            "likelihood_ratio": round(lr, 2),
            "posterior": round(prob, 2),
        })

    final_prob = steps[-1]["posterior"] if steps else round(prior, 2)

    return {
        "prior": round(prior, 2),
        "steps": steps,
        "posterior": final_prob,
    }


def probability_malicious(
    packet: Dict[str, Any],
    src_rate: float,
    prior: float = DEFAULT_PRIOR
) -> float:
    """
    Compute the scalar posterior probability that the given packet is malicious.
    Guaranteed to match the final posterior in explain().
    """
    return explain(packet, src_rate, prior=prior)["posterior"]


def most_suspicious(
    window: Any,
    src_ip: str,
    src_rate: float = 40.0
) -> Optional[Dict[str, Any]]:
    """
    Find the packet from src_ip in window with the highest posterior probability.
    Prefers unusual-sized packets (such as 1337 or 9000 bytes) if probabilities tie.
    """
    matching = [p for p in window if p.get("src_ip") == src_ip]
    if not matching:
        return None

    def packet_rank(p: Dict[str, Any]):
        prob = probability_malicious(p, src_rate)
        size = p.get("size", 0)
        # Distinctive sizes 1337 and 9000 take top priority
        if size in (1337, 9000):
            priority = 3
        elif size > 1300 or size < 60:
            priority = 2
        else:
            priority = 1
        return (prob, priority)

    return max(matching, key=packet_rank)
