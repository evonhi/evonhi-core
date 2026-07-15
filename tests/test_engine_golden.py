"""Golden regression suite for the pure engine (Fase 0, refactor multi-cloud).

Freezes the structural output of ``build_attack_graph`` + ``find_attack_paths`` for
self-contained Kubernetes scenarios: node count, edge count, path count, and each
path's score / relation sequence / node sequence. These values are the definition of
"the Kubernetes engine did not change" and MUST stay identical through every refactor
phase. If a value changes, a phase introduced a regression: stop and fix before
advancing.

Note on scope: the remediation generator (``propose_remediation_actions``) and the
telemetry-driven impact estimator live in evo_saas (the private moat), not here, so
this core suite freezes graph/path *structure* only. The authoritative S1-S4 golden
that also freezes remediation ``action_id``s lives in
``evo_saas/tests/test_kubernetes_golden.py``.
"""

from __future__ import annotations

import pytest

from evonhi_core.graph_builder import build_attack_graph
from evonhi_core.path_analysis import find_attack_paths
from tests.scenarios import ALL_SCENARIOS

# Frozen baseline. Do not edit to make a failing test pass — a diff here means the
# engine's Kubernetes behavior changed.
GOLDEN = {
    "secret_read": {
        "nodes": 4,
        "edges": 3,
        "paths": [
            {
                "score": 25.0,
                "relations": ["uses_token", "granted_permission", "read_secret"],
                "nodes": [
                    "workload:prod:web",
                    "serviceaccount:prod:web-sa",
                    "permission:prod:web-sa:prod:web-binding:web-role:0:core:secrets:get",
                    "secret:prod:db-secret",
                ],
            }
        ],
    },
    "mounted_secret": {
        "nodes": 3,
        "edges": 2,
        "paths": [
            {
                "score": 18.0,
                "relations": ["mounted_secret"],
                "nodes": ["workload:prod:api", "secret:prod:api-key"],
            }
        ],
    },
    "pivot": {
        "nodes": 6,
        "edges": 5,
        "paths": [
            {
                "score": 35.0,
                "relations": [
                    "uses_token",
                    "granted_permission",
                    "spawn_workload_as",
                    "granted_permission",
                    "read_secret",
                ],
                "nodes": [
                    "workload:ci:ci-runner",
                    "serviceaccount:ci:ci-sa",
                    "permission:ci:ci-sa:ci:ci-binding:ci-role:0:apps:deployments:create",
                    "serviceaccount:ci:priv-sa",
                    "permission:ci:priv-sa:ci:priv-binding:priv-role:0:core:secrets:get",
                    "secret:ci:ci-secret",
                ],
            }
        ],
    },
}


@pytest.mark.parametrize("name", sorted(ALL_SCENARIOS))
def test_engine_golden(name: str) -> None:
    model, scenario = ALL_SCENARIOS[name]()
    graph = build_attack_graph(model, scenario)
    paths = find_attack_paths(graph, max_paths=scenario.max_paths)

    expected = GOLDEN[name]
    assert graph.number_of_nodes() == expected["nodes"], f"{name}: node count drifted"
    assert graph.number_of_edges() == expected["edges"], f"{name}: edge count drifted"
    assert len(paths) == len(expected["paths"]), f"{name}: attack-path count drifted"

    for actual, exp in zip(paths, expected["paths"]):
        assert actual.nodes == exp["nodes"], f"{name}: path node sequence drifted"
        assert actual.relations == exp["relations"], f"{name}: path relation sequence drifted"
        assert round(actual.score, 2) == exp["score"], f"{name}: path score drifted"
