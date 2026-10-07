"""Planner v2: exactness of the risk model, optimality of the search and plan quality guarantees.

The risk evaluator is checked against a deliberately naive reference (copy the graph, apply the
actions, run networkx Dijkstra for every entry/jewel pair). The search is checked against brute
force over every subset of actions.
"""

from __future__ import annotations

import itertools
import math
import random

import networkx as nx
import pytest

from evonhi_core.graph.contract import Capability, CapabilityKind, Guard, GuardStatus
from evonhi_core.graph_builder import build_attack_graph
from evonhi_core.models import (
    ClusterModel,
    CrownJewelSpec,
    Metadata,
    PolicyRule,
    RemediationAction,
    Role,
    RoleBinding,
    ScenarioConfig,
    Secret,
    SubjectRef,
    Workload,
)
from evonhi_core.planning import PlannerConfig, RiskModel, assess_risk, plan_remediation
from evonhi_core.planning.model import requirement_effort
from evonhi_core.planning.risk import ComponentEvaluator
from evonhi_core.planning.surface import AttackSurface
from evonhi_core.providers.aws.provider import AwsProvider
from tests import aws_scenario

RELATIONS = ["uses_token", "granted_permission", "read_secret", "spawn_workload_as", "mounted_secret"]


# --------------------------------------------------------------------------- #
# Fixtures: random instances and a naive reference
# --------------------------------------------------------------------------- #


def random_instance(seed: int, components: int = 1, mids: int = 6, density: float = 0.3, guards: bool = False):
    rng = random.Random(seed)
    graph = nx.DiGraph()
    actions: list[RemediationAction] = []
    for c in range(components):
        entries = [f"c{c}:entry{i}" for i in range(2)]
        middle = [f"c{c}:sa{i}" for i in range(mids)]
        jewels = [f"c{c}:jewel{i}" for i in range(2)]
        for n in entries:
            graph.add_node(n, kind="workload", name=n, public=True)
        for n in middle:
            graph.add_node(n, kind="serviceaccount", name=n)
        for n in jewels:
            graph.add_node(n, kind="secret", name=n, crown_jewel=True, criticality=rng.randint(5, 10))
        candidates = (
            [(e, m) for e in entries for m in middle]
            + [(a, b) for a in middle for b in middle if a != b]
            + [(m, j) for m in middle for j in jewels]
        )
        for u, v in candidates:
            if rng.random() < density:
                attrs = {"relation": rng.choice(RELATIONS)}
                if guards and rng.random() < 0.2:
                    attrs["guard"] = Guard(
                        required=[Capability(CapabilityKind.NETWORK_POSITION, "10.0.0.0/8")],
                        static_status=GuardStatus.CONDITIONAL.value,
                    )
                graph.add_edge(u, v, **attrs)
    for u, v in sorted(graph.edges()):
        if rng.random() < 0.6:
            actions.append(
                RemediationAction(f"cut::{u}->{v}", f"cut {u}->{v}", "", rng.randint(1, 5), round(rng.uniform(0, 5), 2), "edge_removal", target_edges=[(u, v)])
            )
        elif rng.random() < 0.3:
            actions.append(
                RemediationAction(
                    f"guard::{u}->{v}", f"guard {u}->{v}", "", rng.randint(1, 3), round(rng.uniform(0, 2), 2), "guard_modification",
                    target_edges=[(u, v)], effect_kind="modify_guard",
                    guard_delta={"add_required": "network_position", "value": "10.0.0.0/8"},
                )
            )
    for n in sorted(graph.nodes()):
        if graph.nodes[n]["kind"] == "serviceaccount" and rng.random() < 0.3:
            actions.append(RemediationAction(f"drop::{n}", f"drop {n}", "", rng.randint(2, 6), round(rng.uniform(0, 5), 2), "node_removal", target_nodes=[n], effect_kind="remove_node"))
    return graph, actions


def reference_risk(graph: nx.DiGraph, actions, selected: set[str], model: RiskModel = RiskModel()) -> tuple[float, int]:
    g = graph.copy()
    added: dict[tuple[str, str], list[Capability]] = {}
    for action in actions:
        if action.action_id not in selected:
            continue
        if action.effect_kind == "modify_guard":
            cap = Capability(CapabilityKind(action.guard_delta["add_required"]), action.guard_delta["value"])
            for edge in action.target_edges:
                added.setdefault(tuple(edge), []).append(cap)
            continue
        for u, v in action.target_edges:
            if g.has_edge(u, v):
                g.remove_edge(u, v)
        for n in action.target_nodes:
            if g.has_node(n):
                g.remove_edges_from(list(g.in_edges(n)) + list(g.out_edges(n)))

    def weight(u, v, attrs):
        guard = attrs.get("guard")
        required = set(guard.required) if isinstance(guard, Guard) else set()
        required |= set(added.get((u, v), []))
        return model.relation_effort.get(attrs.get("relation", ""), model.default_effort) + requirement_effort(model, required)

    entries = [n for n, a in g.nodes(data=True) if a.get("kind") == "workload" and a.get("public")]
    jewels = [n for n, a in g.nodes(data=True) if a.get("crown_jewel")]
    risk, exposures = 0.0, 0
    for jewel in jewels:
        survive = 1.0
        for entry in entries:
            try:
                effort = nx.dijkstra_path_length(g, entry, jewel, weight=weight)
            except nx.NetworkXNoPath:
                continue
            if effort > model.max_effort:
                continue
            exposures += 1
            survive *= 1.0 - model.entry_compromise_likelihood * math.exp(-effort / model.effort_scale)
        risk += g.nodes[jewel]["criticality"] * (1.0 - survive)
    return risk, exposures


def evaluator_for(graph, actions):
    surface = AttackSurface(graph, ("workload",), RiskModel())
    effects = surface.compile_actions(actions)
    return ComponentEvaluator(surface, surface.jewels, surface.entries, {e.index: e for e in effects if e.edges}), actions


def brute_force_best(graph, actions, budget: int) -> float:
    evaluator, _ = evaluator_for(graph, actions)
    usable = sorted(evaluator.effects)
    best = evaluator.baseline.risk
    for r in range(1, len(usable) + 1):
        for combo in itertools.combinations(usable, r):
            if sum(actions[i].cost for i in combo) <= budget:
                best = min(best, evaluator.evaluate(frozenset(combo)).risk)
    return best


# --------------------------------------------------------------------------- #
# Risk model exactness
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("seed", range(12))
def test_evaluator_matches_naive_reference_under_random_selections(seed):
    graph, actions = random_instance(seed, components=2, guards=True)
    evaluator, _ = evaluator_for(graph, actions)
    rng = random.Random(seed)
    for _ in range(25):
        chosen = {a.action_id for a in actions if rng.random() < 0.2}
        idx = frozenset(i for i, a in enumerate(actions) if a.action_id in chosen and i in evaluator.effects)
        expected_risk, expected_exposures = reference_risk(graph, actions, chosen)
        result = evaluator.evaluate(idx)
        assert result.risk == pytest.approx(expected_risk, abs=1e-9)
        assert result.exposures == expected_exposures


def test_no_path_cap_every_exposure_is_counted():
    """v1 stopped after max_paths in alphabetical order of entries; v2 sees every exposure."""
    model = ClusterModel()
    for n in range(120):
        ns = f"ns{n:03d}"
        model.secrets.append(Secret(Metadata("db", ns)))
        model.workloads.append(Workload(Metadata("web", ns), "Deployment", "web", public=True))
        model.roles.append(Role(Metadata("reader", ns), [PolicyRule(["secrets"], ["get"], [""])]))
        model.role_bindings.append(RoleBinding(Metadata("rb", ns), "Role", "reader", [SubjectRef("ServiceAccount", "web", ns)]))
    jewels = [CrownJewelSpec("secret", "db", f"ns{n:03d}") for n in range(120)]
    graph = build_attack_graph(model, ScenarioConfig(crown_jewels=jewels))
    result = assess_risk(graph)
    assert result.baseline_exposures == 120
    assert result.jewels_exposed == 120
    assert all(value > 0 for value in result.risk_by_jewel.values())


# --------------------------------------------------------------------------- #
# Search optimality
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("seed", range(8))
@pytest.mark.parametrize("budget", [3, 6, 12])
def test_decomposed_exact_search_is_optimal(seed, budget):
    graph, actions = random_instance(seed, components=3, mids=3, density=0.35)
    result = plan_remediation(graph, actions, budget=budget)
    expected = brute_force_best(graph, actions, budget)
    best = min((p.risk_after for p in result.plans), default=result.baseline_risk)
    assert best == pytest.approx(expected, abs=1e-6)
    assert result.diagnostics.optimality == "exact"


def _memetic_instances(count: int):
    """First ``count`` single-component instances with 12..16 effective actions (beyond the exact
    limit we force to 0, small enough for brute force)."""
    found, seed = [], 100
    while len(found) < count:
        graph, actions = random_instance(seed, components=1, mids=6, density=0.3)
        evaluator, _ = evaluator_for(graph, actions)
        if 12 <= len(evaluator.effects) <= 16:
            found.append(seed)
        seed += 1
    return found


@pytest.mark.parametrize("instance_seed", _memetic_instances(6))
def test_memetic_search_matches_brute_force(instance_seed):
    seed = instance_seed
    graph, actions = random_instance(instance_seed, components=1, mids=6, density=0.3)
    budget = 8
    config = PlannerConfig(exact_action_limit=0, exact_subset_limit=0, seed=seed)  # force the evolutionary path
    result = plan_remediation(graph, actions, budget=budget, config=config)
    expected = brute_force_best(graph, actions, budget)
    best = min((p.risk_after for p in result.plans), default=result.baseline_risk)
    assert best == pytest.approx(expected, abs=1e-6)
    assert result.diagnostics.optimality == "heuristic"


# --------------------------------------------------------------------------- #
# Plan quality guarantees
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("seed", range(6))
def test_plans_respect_budget_have_no_redundant_actions_and_monotone_steps(seed):
    graph, actions = random_instance(seed, components=2, guards=True)
    budget = 10
    result = plan_remediation(graph, actions, budget=budget)
    by_id = {a.action_id: a for a in actions}
    for plan in result.plans:
        assert plan.cost <= budget
        assert plan.cost == sum(by_id[a].cost for a in plan.selected_actions)
        risk, _ = reference_risk(graph, actions, set(plan.selected_actions))
        assert plan.risk_after == pytest.approx(risk, abs=1e-5)
        for action_id in plan.selected_actions:
            without, _ = reference_risk(graph, actions, set(plan.selected_actions) - {action_id})
            assert without > risk + 1e-9, f"{action_id} is redundant in {plan.strategy}"
        afters = [step.risk_after for step in plan.steps]
        assert afters == sorted(afters, reverse=True)
        assert afters[-1] == pytest.approx(plan.risk_after, abs=1e-5)


def test_planner_is_deterministic():
    graph, actions = random_instance(7, components=1, mids=8, density=0.35)
    config = PlannerConfig(exact_action_limit=0, exact_subset_limit=0)
    first = plan_remediation(graph, actions, budget=9, config=config)
    second = plan_remediation(graph, actions, budget=9, config=config)
    assert [(p.strategy, p.selected_actions) for p in first.plans] == [(p.strategy, p.selected_actions) for p in second.plans]


def test_budget_curve_is_monotone():
    graph, actions = random_instance(3, components=3)
    curve = plan_remediation(graph, actions).pareto_front
    assert [p.cost for p in curve] == sorted(p.cost for p in curve)
    assert [p.risk_after for p in curve] == sorted((p.risk_after for p in curve), reverse=True)


def test_ineffective_and_dominated_actions_are_reported():
    graph = nx.DiGraph()
    graph.add_node("w", kind="workload", name="w", public=True)
    graph.add_node("j", kind="secret", name="j", crown_jewel=True, criticality=10)
    graph.add_node("x", kind="secret", name="x")
    graph.add_edge("w", "j", relation="mounted_secret")
    graph.add_edge("w", "x", relation="mounted_secret")
    actions = [
        RemediationAction("cheap", "", "", 1, 1.0, "edge_removal", target_edges=[("w", "j")]),
        RemediationAction("pricey", "", "", 3, 2.0, "edge_removal", target_edges=[("w", "j")]),
        RemediationAction("irrelevant", "", "", 1, 0.0, "edge_removal", target_edges=[("w", "x")]),
    ]
    result = plan_remediation(graph, actions)
    assert result.diagnostics.actions_without_effect == 1
    assert result.diagnostics.actions_dominated == 1
    assert result.plans[0].selected_actions == ["cheap"]
    assert result.plans[0].risk_after == 0.0


# --------------------------------------------------------------------------- #
# Guard-based remediation (the v1 no-op)
# --------------------------------------------------------------------------- #


def test_aws_guard_tightening_reduces_risk():
    graph = AwsProvider().build_graph(aws_scenario.make_org(), aws_scenario.make_scenario())
    pivot = next((u, v) for u, v, a in graph.edges(data=True) if a.get("relation") == "pivot_identity")
    restrict = RemediationAction(
        "restrict", "restrict assume-role to a CIDR", "", 3, 1.0, "guard_modification",
        target_edges=[pivot], effect_kind="modify_guard",
        guard_delta={"add_required": "network_position", "value": "10.0.0.0/8"},
    )
    result = plan_remediation(graph, [restrict], entry_kinds=AwsProvider.entry_node_kinds)
    assert result.baseline_risk > 0
    assert result.plans, "guard tightening must be worth something"
    assert 0 < result.plans[0].risk_after < result.baseline_risk
    assert result.plans[0].exposures_after == result.baseline_exposures  # harder, not impossible


def test_org_membership_condition_does_not_fake_protection():
    """aws:PrincipalOrgID is satisfied by an attacker already inside the org: no extra effort."""
    graph = AwsProvider().build_graph(aws_scenario.make_org(), aws_scenario.make_scenario())
    free = assess_risk(graph, entry_kinds=AwsProvider.entry_node_kinds)
    strict = assess_risk(graph, entry_kinds=AwsProvider.entry_node_kinds, risk_model=RiskModel(capability_effort={}))
    assert free.baseline_risk > strict.baseline_risk


def test_capability_grants_switch_to_stateful_search():
    """A grant on the first hop satisfies the requirement of a later hop."""
    mfa = Capability(CapabilityKind.MFA, "true")
    graph = nx.DiGraph()
    graph.add_node("w", kind="workload", name="w", public=True)
    graph.add_node("a", kind="identity", name="a")
    graph.add_node("j", kind="secret", name="j", crown_jewel=True, criticality=10)
    graph.add_edge("w", "a", relation="uses_token", guard=Guard(grants=[mfa]))
    graph.add_edge("a", "j", relation="read_secret", guard=Guard(required=[mfa], static_status=GuardStatus.CONDITIONAL.value))
    with_grant = assess_risk(graph)
    graph.edges["w", "a"]["guard"] = Guard()
    without_grant = assess_risk(graph)
    assert with_grant.baseline_risk > without_grant.baseline_risk
    assert with_grant.baseline_paths[0].relations == ["uses_token", "read_secret"]


def test_feasible_subset_counter_matches_brute_force():
    """The adaptive exact mode relies on this knapsack count (zero-cost actions included)."""
    from evonhi_core.planning.search import ComponentSearch
    from evonhi_core.planning.surface import ActionEffect

    for trial in range(150):
        rng = random.Random(trial)
        costs = [rng.randint(0, 5) for _ in range(rng.randint(0, 9))]
        budget = rng.randint(0, 12)
        search = ComponentSearch.__new__(ComponentSearch)
        search.actions, search.budget, search.config = list(range(len(costs))), budget, PlannerConfig()
        search.effects = {i: ActionEffect(i, str(i), c, 0.0, frozenset(), (), ()) for i, c in enumerate(costs)}
        expected = sum(
            1 for r in range(len(costs) + 1) for combo in itertools.combinations(range(len(costs)), r) if sum(costs[i] for i in combo) <= budget
        )
        assert search._feasible_subsets() == expected
