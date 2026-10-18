"""
Module 4: Logic Engine (Forward-Chaining Knowledge Base)
Pure functions, zero I/O.

Derives facts from packet telemetry and applies Horn-clause rules to infer
cybersecurity incidents (DDoS, Port Scan, Brute Force) with an explainable
plain-English proof trace.
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Set, Tuple


# ============================================================================
# Step 2: Knowledge Base Rules (Horn Clauses Stored as Data)
# ============================================================================

RULES = [
    {
        "name": "ddos_detection",
        "premises": [
            ("high_syn_rate", "?X"),
            ("single_target_port", "?X", "?P"),
        ],
        "conclusion": ("ddos", "?X"),
        "attack_type": "DDoS",
        "rule_text": "Rule: high SYN rate + single target port => DDoS",
        "conclusion_template": "Conclusion: {X} is performing a DDoS attack",
    },
    {
        "name": "port_scan_detection",
        "premises": [
            ("many_ports", "?X"),
        ],
        "conclusion": ("port_scan", "?X"),
        "attack_type": "port_scan",
        "rule_text": "Rule: many destination ports => port scan",
        "conclusion_template": "Conclusion: {X} is performing a port scan",
    },
    {
        "name": "brute_force_detection",
        "premises": [
            ("many_ssh_attempts", "?X"),
        ],
        "conclusion": ("brute_force", "?X"),
        "attack_type": "brute_force",
        "rule_text": "Rule: many SSH attempts => brute force",
        "conclusion_template": "Conclusion: {X} is performing a brute force attack",
    },
    {
        "name": "ddos_malicious",
        "premises": [
            ("ddos", "?X"),
        ],
        "conclusion": ("malicious", "?X"),
        "rule_text": "Rule: DDoS => malicious",
        "conclusion_template": "Conclusion: {X} is confirmed malicious",
    },
    {
        "name": "port_scan_malicious",
        "premises": [
            ("port_scan", "?X"),
        ],
        "conclusion": ("malicious", "?X"),
        "rule_text": "Rule: port scan => malicious",
        "conclusion_template": "Conclusion: {X} is confirmed malicious",
    },
    {
        "name": "brute_force_malicious",
        "premises": [
            ("brute_force", "?X"),
        ],
        "conclusion": ("malicious", "?X"),
        "rule_text": "Rule: brute force => malicious",
        "conclusion_template": "Conclusion: {X} is confirmed malicious",
    },
]


# ============================================================================
# Step 1: Base Fact Derivation from Packet Window
# ============================================================================

def _parse_pkt_time(pkt: Dict[str, Any], default_now: float) -> float:
    """Safely extract or compute a numeric timestamp float from a packet."""
    if "_time" in pkt and isinstance(pkt["_time"], (int, float)):
        return float(pkt["_time"])
    if "ts" in pkt:
        try:
            if isinstance(pkt["ts"], (int, float)):
                return float(pkt["ts"])
            return datetime.fromisoformat(str(pkt["ts"])).timestamp()
        except Exception:
            pass
    return default_now


def derive_base_facts(
    window: List[Dict[str, Any]],
    now: float
) -> Tuple[Set[Tuple], Dict[Tuple, str]]:
    """
    Examine the packet window and derive base facts for each source IP.
    Returns:
    - facts: set of fact tuples
    - evidence: dictionary mapping fact tuple -> plain-English observation string
    """
    facts: Set[Tuple] = set()
    evidence: Dict[Tuple, str] = {}

    if not window:
        return facts, evidence

    # Group packets by source IP
    ip_packets = defaultdict(list)
    for pkt in window:
        ip = pkt.get("src_ip")
        if ip:
            t = _parse_pkt_time(pkt, now)
            ip_packets[ip].append({**pkt, "_time": t})

    for ip, pkts in ip_packets.items():
        # Packets within the last 5.0 seconds
        pkts_5s = [p for p in pkts if (now - 5.0) <= p["_time"] <= (now + 0.05)]
        # Packets within the last 1.0 second
        pkts_1s = [p for p in pkts if (now - 1.0) <= p["_time"] <= (now + 0.05)]

        # 1. high_syn_rate(IP): more than 15 SYN packets within the last 1 second
        syn_1s = [p for p in pkts_1s if p.get("flags") == "SYN"]
        if len(syn_1s) > 15:
            fact = ("high_syn_rate", ip)
            facts.add(fact)
            evidence[fact] = f"Observed: {len(syn_1s)} SYN packets from {ip} in the last second"

        # 2. single_target_port(IP, PORT): at least 90% of IP's packets go to one port
        if pkts:
            port_counts = Counter(p.get("dst_port") for p in pkts if p.get("dst_port") is not None)
            if port_counts:
                most_common_port, count = port_counts.most_common(1)[0]
                ratio = count / len(pkts)
                if ratio >= 0.90:
                    fact = ("single_target_port", ip, most_common_port)
                    facts.add(fact)
                    pct = int(round(ratio * 100))
                    evidence[fact] = f"Observed: {pct}% of its packets target port {most_common_port}"

        # 3. many_ports(IP): more than 8 distinct destination ports within 5 seconds
        distinct_ports = {p.get("dst_port") for p in pkts_5s if p.get("dst_port") is not None}
        if len(distinct_ports) > 8:
            fact = ("many_ports", ip)
            facts.add(fact)
            evidence[fact] = f"Observed: {len(distinct_ports)} distinct destination ports targeted within 5 seconds"

        # 4. many_ssh_attempts(IP): more than 10 packets to port 22 within 5 seconds
        ssh_pkts = [p for p in pkts_5s if p.get("dst_port") == 22]
        if len(ssh_pkts) > 10:
            fact = ("many_ssh_attempts", ip)
            facts.add(fact)
            evidence[fact] = f"Observed: {len(ssh_pkts)} connection attempts to port 22 (SSH) within 5 seconds"

    return facts, evidence


# ============================================================================
# Step 3: Forward-Chaining Inference Engine
# ============================================================================

def _match_premises(
    premises: List[Tuple],
    facts: Set[Tuple],
    bindings: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Recursively find all variable substitution environments where all premises
    match facts in the knowledge base.
    """
    if not premises:
        return [bindings]

    first, *rest = premises
    results = []

    for fact in facts:
        if len(first) != len(fact):
            continue
        if first[0] != fact[0]:
            continue

        # Attempt to bind variables
        new_bindings = dict(bindings)
        match = True
        for p_elem, f_elem in zip(first[1:], fact[1:]):
            if isinstance(p_elem, str) and p_elem.startswith("?"):
                var = p_elem[1:]
                if var in new_bindings:
                    if new_bindings[var] != f_elem:
                        match = False
                        break
                else:
                    new_bindings[var] = f_elem
            else:
                if p_elem != f_elem:
                    match = False
                    break

        if match:
            sub_results = _match_premises(rest, facts, new_bindings)
            results.extend(sub_results)

    return results


def _instantiate_tuple(template: Tuple, bindings: Dict[str, Any]) -> Tuple:
    """Substitute bound variables into a fact tuple."""
    instantiated = [template[0]]
    for item in template[1:]:
        if isinstance(item, str) and item.startswith("?"):
            var = item[1:]
            instantiated.append(bindings.get(var, item))
        else:
            instantiated.append(item)
    return tuple(instantiated)


def forward_chain(
    base_facts: Set[Tuple],
    rules: List[Dict[str, Any]]
) -> Tuple[Set[Tuple], List[Dict[str, Any]]]:
    """
    Repeatedly apply rules to the knowledge base until no new facts appear (fixed point).
    Records derivations with the rule and premises that produced each new fact.
    """
    known_facts = set(base_facts)
    derivations: List[Dict[str, Any]] = []

    while True:
        new_fact_derived = False

        for rule in rules:
            matches = _match_premises(rule["premises"], known_facts, {})
            for env in matches:
                conclusion = _instantiate_tuple(rule["conclusion"], env)
                if conclusion not in known_facts:
                    known_facts.add(conclusion)
                    new_fact_derived = True
                    # Record provenance
                    instantiated_premises = [
                        _instantiate_tuple(p, env) for p in rule["premises"]
                    ]
                    derivations.append({
                        "rule": rule,
                        "conclusion": conclusion,
                        "premises": instantiated_premises,
                        "bindings": env,
                    })

        if not new_fact_derived:
            break

    return known_facts, derivations


# ============================================================================
# Main Detection Interface
# ============================================================================

def detect(
    window: Any,
    now: Optional[float] = None
) -> Optional[Dict[str, Any]]:
    """
    Inspect the rolling packet window using forward chaining.
    Returns:
    - Dict with attack_type, src_ip, rule_fired, and plain-English proof_trace if detected.
    - None for benign/normal traffic.
    """
    current_time = now if now is not None else time.time()
    packet_list = list(window) if window else []

    # Step 1: Derive base facts from packets
    base_facts, evidence = derive_base_facts(packet_list, current_time)
    if not base_facts:
        return None

    # Step 2 & 3: Run forward chaining
    known_facts, derivations = forward_chain(base_facts, RULES)

    # Check for primary attack classifications: ddos, port_scan, brute_force
    detected_attack = None
    for deriv in derivations:
        c_name = deriv["conclusion"][0]
        if c_name in ("ddos", "port_scan", "brute_force"):
            detected_attack = deriv
            break

    if not detected_attack:
        return None

    rule = detected_attack["rule"]
    attack_type = rule.get("attack_type", "DDoS")
    src_ip = detected_attack["bindings"].get("X", "unknown")

    # Build plain-English proof trace
    proof_trace: List[str] = []

    # 1. Base premise observations
    for prem in detected_attack["premises"]:
        if prem in evidence:
            proof_trace.append(evidence[prem])

    # 2. Rule fired
    proof_trace.append(rule.get("rule_text", ""))

    # 3. Intermediate conclusion
    c_text = rule.get("conclusion_template", "Conclusion: Attack detected").format(**detected_attack["bindings"])
    proof_trace.append(c_text)

    # 4. Check if malicious(X) was derived subsequently
    for deriv in derivations:
        if deriv["conclusion"] == ("malicious", src_ip):
            m_rule_text = deriv["rule"].get("rule_text", "Rule: Attack => malicious")
            proof_trace.append(m_rule_text)
            break

    return {
        "attack_type": attack_type,
        "src_ip": src_ip,
        "rule_fired": rule.get("rule_text", rule["name"]),
        "proof_trace": proof_trace,
    }
