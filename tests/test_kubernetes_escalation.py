"""One test per Kubernetes escalation primitive covered by the extended semantics.

Shared setup: a public workload ``web`` (service account ``web-sa``) and a private workload
``db-worker`` whose service account ``admin-sa`` can read the crown-jewel secret ``db``. Each test
grants ``web-sa`` one primitive and checks that the attack route appears — in both graph shapes —
and that the legacy semantics (v1 goldens) do not see it.
"""

from __future__ import annotations

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
from evonhi_core.providers.kubernetes.snapshot import cluster_model_from_snapshot

NS = "prod"
SCENARIO = ScenarioConfig(crown_jewels=[CrownJewelSpec("secret", "db", NS)])
RBAC = "rbac.authorization.k8s.io"


def cluster(*rules: PolicyRule, subject: SubjectRef | None = None, scope: str = "Namespaced") -> ClusterModel:
    """``rules`` are granted to ``web-sa`` (or to ``subject``) in namespace ``prod``."""
    model = ClusterModel(
        service_accounts=[ServiceAccount(Metadata("web-sa", NS)), ServiceAccount(Metadata("admin-sa", NS)), ServiceAccount(Metadata("other-sa", NS))],
        secrets=[Secret(Metadata("db", NS))],
        workloads=[
            Workload(Metadata("web", NS), "Deployment", "web-sa", public=True),
            Workload(Metadata("db-worker", NS), "Deployment", "admin-sa"),
        ],
        roles=[Role(Metadata("secret-reader", NS), [PolicyRule(["secrets"], ["get"], [""])])],
        role_bindings=[RoleBinding(Metadata("admin-reads", NS), "Role", "secret-reader", [SubjectRef("ServiceAccount", "admin-sa", NS)])],
    )
    if rules:
        role_scope = "Cluster" if scope == "Cluster" else "Namespaced"
        model.roles.append(Role(Metadata("granted", NS), list(rules), scope=role_scope))
        model.role_bindings.append(
            RoleBinding(
                Metadata("grant", NS),
                "ClusterRole" if scope == "Cluster" else "Role",
                "granted",
                [subject or SubjectRef("ServiceAccount", "web-sa", NS)],
                scope=scope,
            )
        )
    return model


def relations(model: ClusterModel, *, compact: bool) -> list[str] | None:
    """Relations of the cheapest route to the crown jewel, without the zero-cost hub hops."""
    result = assess_risk(build_attack_graph(model, SCENARIO, compact=compact, extended=True))
    if not result.baseline_paths:
        return None
    return [r for r in result.baseline_paths[0].relations if r != "contains"]


PRIMITIVES = {
    "token_request": (PolicyRule(["serviceaccounts/token"], ["create"], [""]), ["uses_token", "granted_permission", "mint_token", "granted_permission", "read_secret"]),
    "impersonate": (PolicyRule(["serviceaccounts"], ["impersonate"], [""]), ["uses_token", "granted_permission", "impersonate", "granted_permission", "read_secret"]),
    "pods_exec": (PolicyRule(["pods/exec"], ["create"], [""]), ["uses_token", "granted_permission", "exec_into", "uses_token", "granted_permission", "read_secret"]),
    "rbac_bind": (PolicyRule(["roles"], ["bind"], [RBAC]), ["uses_token", "granted_permission", "escalate_rbac"]),
    "rbac_escalate": (PolicyRule(["clusterroles"], ["escalate"], [RBAC]), ["uses_token", "granted_permission", "escalate_rbac"]),
}


def test_without_any_grant_the_jewel_is_not_exposed():
    assert relations(cluster(), compact=True) is None
    assert relations(cluster(), compact=False) is None


@pytest.mark.parametrize("name", sorted(PRIMITIVES))
@pytest.mark.parametrize("compact", [True, False])
def test_primitive_creates_the_expected_route(name, compact):
    rule, expected = PRIMITIVES[name]
    assert relations(cluster(rule), compact=compact) == expected


@pytest.mark.parametrize("name", sorted(PRIMITIVES))
def test_legacy_semantics_do_not_model_the_primitive(name):
    rule, _expected = PRIMITIVES[name]
    legacy = build_attack_graph(cluster(rule), SCENARIO)  # what the v1 goldens freeze
    assert assess_risk(legacy).baseline_exposures == 0


@pytest.mark.parametrize("compact", [True, False])
def test_resource_names_limit_the_reach(compact):
    other = PolicyRule(["serviceaccounts/token"], ["create"], [""], resource_names=["other-sa"])
    assert relations(cluster(other), compact=compact) is None
    admin = PolicyRule(["serviceaccounts/token"], ["create"], [""], resource_names=["admin-sa"])
    assert relations(cluster(admin), compact=compact) is not None

    wrong_pod = PolicyRule(["pods/exec"], ["create"], [""], resource_names=["cache-0"])
    assert relations(cluster(wrong_pod), compact=compact) is None
    right_pod = PolicyRule(["pods/exec"], ["create"], [""], resource_names=["db-worker-7d9f-abcde"])
    assert relations(cluster(right_pod), compact=compact) is not None


@pytest.mark.parametrize("group", ["system:serviceaccounts:prod", "system:serviceaccounts", "system:authenticated"])
@pytest.mark.parametrize("compact", [True, False])
def test_grants_to_service_account_groups_reach_every_member(group, compact):
    model = cluster(PolicyRule(["secrets"], ["get"], [""]), subject=SubjectRef("Group", group))
    assert relations(model, compact=compact) == ["uses_token", "member_of", "granted_permission", "read_secret"]


def test_group_of_another_namespace_does_not_apply():
    model = cluster(PolicyRule(["secrets"], ["get"], [""]), subject=SubjectRef("Group", "system:serviceaccounts:staging"))
    assert relations(model, compact=True) is None


def test_unmodeled_subjects_are_counted_not_silently_dropped():
    model = cluster()
    model.role_bindings.append(
        RoleBinding(Metadata("humans", NS), "Role", "secret-reader", [SubjectRef("User", "alice"), SubjectRef("Group", "developers")])
    )
    graph = build_attack_graph(model, SCENARIO, compact=True)
    assert graph.graph["unmodeled_subjects"] == 2
    assert assess_risk(graph).baseline_exposures == 0


def test_the_easiest_primitive_wins_when_one_permission_grants_several():
    """``*`` on ``*`` can mutate workloads (effort 2) and mint tokens (effort 1): the route uses the token."""
    model = cluster(PolicyRule(["*"], ["*"], ["*"]))
    for compact in (True, False):
        path = relations(model, compact=compact)
        assert path == ["uses_token", "granted_permission", "read_secret"]  # reads the secret directly
    no_secrets = cluster(PolicyRule(["serviceaccounts/token", "deployments"], ["create"], ["", "apps"]))
    assert "mint_token" in relations(no_secrets, compact=True)


def test_removing_the_permission_closes_the_route():
    graph = build_attack_graph(cluster(PRIMITIVES["token_request"][0]), SCENARIO, compact=True)
    permission = next(v for u, v, a in graph.edges(data=True) if a["relation"] == "granted_permission" and u == "serviceaccount:prod:web-sa")
    action = RemediationAction("drop", "Remove token creation from web-sa", "", 3, 1.0, "node_removal", target_nodes=[permission], effect_kind="remove_node")
    result = plan_remediation(graph, [action])
    assert result.baseline_exposures == 1
    assert result.plans[0].risk_after == pytest.approx(0.0, abs=1e-9)


def test_collector_snapshot_with_a_group_binding_is_analyzed():
    snapshot = {
        "schema_version": "1.1",
        "cluster_id": "c",
        "collected_at": "2026-11-11T00:00:00Z",
        "workloads": [{"namespace": NS, "name": "web", "kind": "Deployment", "service_account": "web-sa", "public": True, "mounted_secrets": []}],
        "service_accounts": [{"namespace": NS, "name": "web-sa"}],
        "roles": [],
        "cluster_roles": [{"name": "secret-reader", "rules": [{"api_groups": [""], "resources": ["secrets"], "verbs": ["get"]}]}],
        "role_bindings": [
            {
                "namespace": NS,
                "name": "all-sas-read",
                "role_ref": {"kind": "ClusterRole", "name": "secret-reader"},
                "subjects": [{"kind": "Group", "name": "system:serviceaccounts:prod"}],
            }
        ],
        "cluster_role_bindings": [],
        "secrets": [{"namespace": NS, "name": "db", "mounted_by": []}],
    }
    graph = build_attack_graph(cluster_model_from_snapshot(snapshot), SCENARIO, compact=True)
    assert assess_risk(graph).baseline_exposures == 1
