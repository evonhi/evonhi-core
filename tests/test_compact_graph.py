"""The compact Kubernetes graph (hub nodes, escalation-relevant permissions only) must be a pure
re-encoding: same exposures, same risk, same effect of every remediation — at a fraction of the size."""

from __future__ import annotations

import random

import pytest

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
    ServiceAccount,
    SubjectRef,
    Workload,
)
from evonhi_core.planning import assess_risk, plan_remediation
from evonhi_core.planning.model import RiskModel
from evonhi_core.planning.risk import ComponentEvaluator
from evonhi_core.planning.surface import AttackSurface

RULES = [
    PolicyRule(["secrets"], ["get"], [""]),
    PolicyRule(["secrets"], ["list", "watch"], [""]),
    PolicyRule(["secrets"], ["get"], [""], resource_names=["secret-0"]),
    PolicyRule(["deployments"], ["patch", "update"], ["apps"]),
    PolicyRule(["deployments"], ["patch"], ["apps"], resource_names=["app-1"]),
    PolicyRule(["pods"], ["create"], [""]),
    PolicyRule(["*"], ["*"], ["*"]),
    PolicyRule(["configmaps", "pods"], ["get", "list"], [""]),  # no escalation semantics
]


def random_cluster(seed: int, namespaces: int = 4, workloads: int = 4, secrets: int = 3):
    rng = random.Random(seed)
    model = ClusterModel()
    for index, rule in enumerate(RULES):
        model.roles.append(Role(Metadata(f"cr-{index}", "default"), [rule], scope="Cluster"))
    names = [f"ns{n}" for n in range(namespaces)]
    for ns in names:
        for s in range(secrets):
            model.secrets.append(Secret(Metadata(f"secret-{s}", ns)))
        for w in range(workloads):
            model.service_accounts.append(ServiceAccount(Metadata(f"sa-{w}", ns)))
            model.workloads.append(
                Workload(
                    Metadata(f"app-{w}", ns),
                    "Deployment",
                    f"sa-{w}",
                    public=rng.random() < 0.3,
                    automount_token=None if rng.random() < 0.8 else False,
                    mounted_secrets=[f"secret-{rng.randrange(secrets)}"] if rng.random() < 0.2 else [],
                )
            )
    binding = 0
    for ns in names:
        for w in range(workloads):
            for _ in range(rng.randint(0, 2)):
                binding += 1
                role = f"cr-{rng.randrange(len(RULES))}"
                subject = SubjectRef("ServiceAccount", f"sa-{w}", ns)
                if rng.random() < 0.25:  # cluster-wide grant
                    model.role_bindings.append(RoleBinding(Metadata(f"crb-{binding}", "default"), "ClusterRole", role, [subject], scope="Cluster"))
                else:
                    target_ns = ns if rng.random() < 0.7 else rng.choice(names)
                    model.role_bindings.append(RoleBinding(Metadata(f"rb-{binding}", target_ns), "ClusterRole", role, [subject]))
    jewels = [CrownJewelSpec("secret", f"secret-{rng.randrange(secrets)}", ns, criticality=rng.randint(5, 10)) for ns in names]
    return model, ScenarioConfig(crown_jewels=jewels)


def catalog(graph) -> list[RemediationAction]:
    """Actions whose targets exist under the same ids in both graph shapes."""
    actions = []
    for u, v, attrs in sorted(graph.edges(data=True), key=lambda e: (e[0], e[1])):
        if attrs["relation"] == "granted_permission":
            actions.append(RemediationAction(f"drop::{v}", "drop permission", "", 3, 1.0, "node_removal", target_nodes=[v], effect_kind="remove_node"))
        elif attrs["relation"] in {"uses_token", "mounted_secret"}:
            actions.append(RemediationAction(f"cut::{u}->{v}", "cut", "", 2, 1.0, "edge_removal", target_edges=[(u, v)]))
    return actions


def risk_of(graph, actions, selected: set[str]) -> tuple[float, int]:
    surface = AttackSurface(graph, ("workload",), RiskModel())
    effects = {e.index: e for e in surface.compile_actions(actions) if e.edges}
    evaluator = ComponentEvaluator(surface, surface.jewels, surface.entries, effects)
    chosen = frozenset(i for i, a in enumerate(actions) if a.action_id in selected and i in effects)
    result = evaluator.evaluate(chosen)
    return result.risk, result.exposures


@pytest.mark.parametrize("seed", range(25))
def test_compact_graph_preserves_risk_and_remediation_effects(seed):
    model, scenario = random_cluster(seed)
    legacy = build_attack_graph(model, scenario)
    compact = build_attack_graph(model, scenario, compact=True)

    a, b = assess_risk(legacy), assess_risk(compact)
    assert b.baseline_exposures == a.baseline_exposures
    assert b.baseline_risk == pytest.approx(a.baseline_risk, abs=1e-9)
    assert b.risk_by_jewel == pytest.approx(a.risk_by_jewel, abs=1e-6)

    actions = catalog(compact)
    rng = random.Random(seed)
    for _ in range(15):
        selected = {action.action_id for action in actions if rng.random() < 0.15}
        assert risk_of(compact, actions, selected) == pytest.approx(risk_of(legacy, actions, selected), abs=1e-9)

    plan = plan_remediation(compact, actions, budget=8)
    if plan.plans:
        best = plan.plans[0]
        legacy_risk, legacy_exposures = risk_of(legacy, actions, set(best.selected_actions))
        assert best.risk_after == pytest.approx(legacy_risk, abs=1e-5)
        assert best.exposures_after == legacy_exposures


def test_some_random_clusters_actually_exercise_the_hubs():
    """Guard against a vacuous equivalence test: exposures must exist and routes must cross hubs."""
    crossing = 0
    for seed in range(25):
        model, scenario = random_cluster(seed)
        result = assess_risk(build_attack_graph(model, scenario, compact=True))
        crossing += any("contains" in path.relations for path in result.baseline_paths)
    assert crossing >= 10


def test_compact_graph_is_linear_in_cluster_size():
    model = ClusterModel(roles=[Role(Metadata("admin", "default"), [PolicyRule(["*"], ["*"], ["*"])], scope="Cluster")])
    for n in range(40):
        ns = f"ns{n}"
        for i in range(10):
            model.secrets.append(Secret(Metadata(f"s{i}", ns)))
            model.service_accounts.append(ServiceAccount(Metadata(f"sa{i}", ns)))
            model.workloads.append(Workload(Metadata(f"w{i}", ns), "Deployment", f"sa{i}", public=(i == 0)))
        model.role_bindings.append(
            RoleBinding(Metadata(f"crb{n}", "default"), "ClusterRole", "admin", [SubjectRef("ServiceAccount", "sa1", ns)], scope="Cluster")
        )
    scenario = ScenarioConfig(crown_jewels=[CrownJewelSpec("secret", "s0", "ns0")])
    legacy = build_attack_graph(model, scenario)
    compact = build_attack_graph(model, scenario, compact=True)
    objects = len(model.secrets) + len(model.service_accounts) + len(model.workloads)
    assert legacy.number_of_edges() > 30_000  # 40 admins x (400 secrets + 400 service accounts)
    assert compact.number_of_edges() < 3 * objects
    assert compact.graph["skipped_permissions"] == 0
    assert assess_risk(compact).baseline_risk == pytest.approx(assess_risk(legacy).baseline_risk, abs=1e-9)
