"""
Unit tests for Module 6: STRIPS-style Automated Defense Planner
"""

import pytest
from modules.planner import make_plan, ACTIONS, Action, DEFAULT_INITIAL_STATE, DEFAULT_GOAL


def test_ddos_plan_structure():
    """
    Test that the default DDoS containment plan has exactly 3 steps in the expected order:
    1. identify_source_ip
    2. add_firewall_rule
    3. verify_block
    """
    incident = {"src_ip": "203.0.113.99", "attack_type": "DDoS"}
    plan = make_plan(incident)

    assert "steps" in plan
    steps = plan["steps"]
    assert len(steps) == 3

    assert steps[0]["n"] == 1
    assert steps[0]["action"] == "identify_source_ip"

    assert steps[1]["n"] == 2
    assert steps[1]["action"] == "add_firewall_rule"

    assert steps[2]["n"] == 3
    assert steps[2]["action"] == "verify_block"


def test_plan_preconditions_and_goal_reachability():
    """
    Replay the generated plan step by step:
    - Assert each step's preconditions are a subset of the active state at that point.
    - Assert that applying the entire sequence yields a state satisfying the goal.
    """
    incident = {"src_ip": "203.0.113.99"}
    plan = make_plan(incident)

    # Map action names to Action objects
    action_map = {a.name: a for a in ACTIONS}

    current_state = set(DEFAULT_INITIAL_STATE)
    goal = set(DEFAULT_GOAL)

    for step in plan["steps"]:
        action_name = step["action"]
        action = action_map[action_name]

        # Verify preconditions hold before action execution
        assert action.preconditions.issubset(current_state), (
            f"Preconditions {action.preconditions} not satisfied in state {current_state} for {action_name}"
        )

        # Apply transition
        current_state = (current_state - action.delete_effects) | action.add_effects

    # Final state must satisfy goal
    assert goal.issubset(current_state), f"Goal {goal} not satisfied in final state {current_state}"


def test_distractor_actions_excluded():
    """
    Verify that distractor actions (rate_limit_port and notify_admin) are pruned by BFS
    because they are not on the shortest path to satisfy the goal.
    """
    incident = {"src_ip": "203.0.113.99"}
    plan = make_plan(incident)

    action_names = [step["action"] for step in plan["steps"]]

    assert "rate_limit_port" not in action_names
    assert "notify_admin" not in action_names


def test_impossible_goal_returns_empty_plan():
    """
    An unreachable goal must return steps=[] without raising an error or looping indefinitely.
    """
    incident = {"src_ip": "203.0.113.99"}
    unreachable_goal = {"impossible_state_never_reached"}

    plan = make_plan(incident, goal=unreachable_goal)

    assert plan["steps"] == []
    assert plan["states_explored"] > 0
    assert "impossible_state_never_reached" in plan["goal"]


def test_ip_address_appears_in_descriptions():
    """
    Verify that the attacking IP address (e.g. 198.51.100.77) is injected into step descriptions.
    """
    custom_ip = "198.51.100.77"
    plan = make_plan({"src_ip": custom_ip})

    step1_desc = plan["steps"][0]["description"]
    step2_desc = plan["steps"][1]["description"]

    assert custom_ip in step1_desc
    assert custom_ip in step2_desc


def test_already_satisfied_goal():
    """
    If the initial state already contains the goal, 0 steps should be returned.
    """
    initial = {"attack_detected", "threat_blocked", "block_verified"}
    plan = make_plan(initial=initial)

    assert plan["steps"] == []
    assert plan["states_explored"] == 1


def test_states_explored_counter():
    """
    Verify states_explored is a valid positive integer.
    """
    plan = make_plan()
    assert isinstance(plan["states_explored"], int)
    assert plan["states_explored"] >= 3
