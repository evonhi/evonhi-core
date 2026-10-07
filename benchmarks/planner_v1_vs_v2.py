"""Reproducible comparison of the v1 optimizer (capped path counting + NSGA-II) with planner v2.

Both are scored with the same exact v2 risk model, so the comparison measures plan quality, not
metric differences. Synthetic Kubernetes clusters: every namespace has a public workload whose
service account can patch deployments (pivot) into a service account that reads the namespace's
database secret. ``giant`` adds a cluster-wide operator that can list every secret, which glues all
namespaces into one component.

    python benchmarks/planner_v1_vs_v2.py
"""

from __future__ import annotations

import time
import warnings

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
from evonhi_core.optimizer import optimize_actions
from evonhi_core.planning import plan_remediation
from evonhi_core.planning.model import RiskModel
from evonhi_core.planning.risk import ComponentEvaluator
from evonhi_core.planning.surface import AttackSurface
from evonhi_core.traversal import ReachabilityIndex

COST = {"uses_token": 2, "granted_permission": 3, "mounted_secret": 3}


def cluster(namespaces: int, workloads: int = 10, giant: bool = False) -> ClusterModel:
    model = ClusterModel()
    for n in range(namespaces):
        ns = f"ns{n:03d}"
        model.secrets.append(Secret(Metadata("db", ns)))
        for w in range(workloads):
            model.service_accounts.append(ServiceAccount(Metadata(f"sa{w}", ns)))
            model.workloads.append(Workload(Metadata(f"app{w}", ns), "Deployment", f"sa{w}", public=(w == 0)))
        model.roles.append(Role(Metadata("deployer", ns), [PolicyRule(["deployments"], ["patch"], ["apps"])]))
        model.roles.append(Role(Metadata("reader", ns), [PolicyRule(["secrets"], ["get"], [""])]))
        model.role_bindings.append(RoleBinding(Metadata("rb1", ns), "Role", "deployer", [SubjectRef("ServiceAccount", "sa0", ns)]))
        model.role_bindings.append(RoleBinding(Metadata("rb2", ns), "Role", "reader", [SubjectRef("ServiceAccount", f"sa{workloads - 1}", ns)]))
    if giant:
        model.roles.append(Role(Metadata("operator", "kube-system"), [PolicyRule(["secrets"], ["list"], [""])], scope="Cluster"))
        model.role_bindings.append(
            RoleBinding(Metadata("operator-rb", "kube-system"), "ClusterRole", "operator", [SubjectRef("ServiceAccount", "sa1", "ns000")], scope="Cluster")
        )
    return model


def actions_for(graph) -> list[RemediationAction]:
    """Generic catalog: cut any token/permission/mount edge that leaves a public workload or a SA."""
    actions = []
    for u, v, attrs in graph.edges(data=True):
        relation = attrs["relation"]
        if relation in COST:
            effect = "remove_node" if relation == "granted_permission" else "remove_edge"
            actions.append(
                RemediationAction(
                    f"{relation}::{v if effect == 'remove_node' else u + '->' + v}", relation, "", COST[relation], 1.0,
                    "node_removal" if effect == "remove_node" else "edge_removal",
                    target_edges=[] if effect == "remove_node" else [(u, v)],
                    target_nodes=[v] if effect == "remove_node" else [],
                    effect_kind=effect,
                )
            )
    return actions


def apply_v1(reach_index: ReachabilityIndex, actions, selected):
    index = {a.action_id: a for a in actions}
    edges = [e for i in selected for e in index[i].target_edges]
    nodes = [n for i in selected for n in index[i].target_nodes]
    return reach_index.apply_and_recount(removed_edges=edges, removed_nodes=nodes)


def score(graph, actions, selected_ids):
    surface = AttackSurface(graph, ("workload",), RiskModel())
    effects = surface.compile_actions(actions)
    evaluator = ComponentEvaluator(surface, surface.jewels, surface.entries, {e.index: e for e in effects if e.edges})
    ids = {a.action_id: i for i, a in enumerate(actions)}
    chosen = frozenset(ids[a] for a in selected_ids if ids[a] in evaluator.effects)
    return evaluator.baseline, evaluator.evaluate(chosen)


def main() -> None:
    warnings.simplefilter("ignore", DeprecationWarning)
    print("| scenario | budget | actions | baseline exposures | v1 exposures left | v2 exposures left | v1 risk left | v2 risk left | v2 optimality | v1 s | v2 s |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for namespaces, giant, budget in [(50, False, 20), (200, False, 20), (200, True, 20), (200, False, None)]:
        model = cluster(namespaces, giant=giant)
        jewels = [CrownJewelSpec("secret", "db", f"ns{n:03d}") for n in range(namespaces)]
        graph = build_attack_graph(model, ScenarioConfig(crown_jewels=jewels))
        actions = actions_for(graph)
        started = time.perf_counter()
        v1 = optimize_actions(graph, actions, max_paths=50, apply_actions=apply_v1, budget=budget)[0]
        v1_time = time.perf_counter() - started
        started = time.perf_counter()
        v2 = plan_remediation(graph, actions, budget=budget)
        v2_time = time.perf_counter() - started
        baseline, v1_eval = score(graph, actions, v1.selected_actions)
        best = v2.plans[0]
        name = f"{namespaces} ns{' + cluster operator' if giant else ''}"
        print(
            f"| {name} | {budget if budget is not None else '∞'} | {len(actions)} | {baseline.exposures} | {v1_eval.exposures} | "
            f"{best.exposures_after} | {v1_eval.risk:.1f} | {best.risk_after:.1f} | {v2.diagnostics.optimality} | {v1_time:.2f} | {v2_time:.2f} |"
        )


if __name__ == "__main__":
    main()
