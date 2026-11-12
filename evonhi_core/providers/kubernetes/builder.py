"""Kubernetes attack-graph builder (Fase 4, multi-cloud refactor).

Extracted from the old top-level ``graph_builder`` and re-implemented with inverted indexes
(see ``indexes.py``) so edge construction is ~O(N+E) instead of ~O(N^2). The emitted
``nx.DiGraph`` — every node, edge and attribute — is byte-identical to the previous builder;
the golden tests are the proof.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Iterable, Tuple

import networkx as nx

from evonhi_core.providers.kubernetes.indexes import KubernetesIndexes
from evonhi_core.providers.kubernetes.semantics import (
    _permission_escalates_rbac,
    _permission_execs_into_pods,
    _permission_impersonates,
    _permission_mints_tokens,
    _permission_targets_secret,
    _permission_targets_workload_mutation,
    service_account_group,
)

if TYPE_CHECKING:
    # Used only in annotations (strings under `from __future__ import annotations`).
    # ClusterModel/Role/RoleBinding are provider-owned; CrownJewelSpec/ScenarioConfig are generic.
    from evonhi_core.models import CrownJewelSpec, ScenarioConfig
    from evonhi_core.providers.kubernetes.model import ClusterModel, Role, RoleBinding


def node_id(kind: str, namespace: str, name: str) -> str:
    return f"{kind.lower()}:{namespace}:{name}"


def permission_id(
    subject_namespace: str,
    subject_name: str,
    binding_namespace: str,
    binding_name: str,
    role_name: str,
    index: int,
    api_group: str,
    resource: str,
    verb: str,
) -> str:
    safe_group = api_group or "core"
    return (
        f"permission:{subject_namespace}:{subject_name}:{binding_namespace}:{binding_name}:"
        f"{role_name}:{index}:{safe_group}:{resource}:{verb}"
    )


def _build_role_index(model: ClusterModel) -> Dict[Tuple[str, str, str], Role]:
    index: Dict[Tuple[str, str, str], Role] = {}
    for role in model.roles:
        index[(role.scope, role.metadata.namespace, role.metadata.name)] = role
        if role.scope == "Cluster":
            index[(role.scope, "*", role.metadata.name)] = role
    return index


def _resolve_role(binding: RoleBinding, role_index: Dict[Tuple[str, str, str], Role]) -> Role | None:
    if binding.role_ref_kind == "ClusterRole":
        return role_index.get(("Cluster", "*", binding.role_ref_name))
    return role_index.get(("Namespaced", binding.metadata.namespace, binding.role_ref_name))


def _resource_scope(binding: RoleBinding) -> tuple[str, str | None]:
    if binding.scope == "Cluster":
        return "Cluster", None
    return "Namespaced", binding.metadata.namespace


def _mark_crown_jewels(graph: nx.DiGraph, jewels: Iterable[CrownJewelSpec]) -> None:
    for jewel in jewels:
        target = node_id(jewel.kind, jewel.namespace, jewel.name)
        if graph.has_node(target):
            graph.nodes[target]["crown_jewel"] = True
            graph.nodes[target]["criticality"] = jewel.criticality
            graph.nodes[target]["rationale"] = jewel.rationale


def _attach_workload_nodes(
    graph: nx.DiGraph, model: ClusterModel, scenario: ScenarioConfig, indexes: KubernetesIndexes
) -> None:
    entry_set = set(scenario.entry_workloads)
    for workload in model.workloads:
        wid = node_id("workload", workload.metadata.namespace, workload.metadata.name)
        service_account_name = workload.service_account_name or "default"
        sa_id = node_id("serviceaccount", workload.metadata.namespace, service_account_name)
        graph.add_node(
            wid,
            kind="workload",
            name=workload.metadata.name,
            namespace=workload.metadata.namespace,
            public=workload.public or workload.metadata.name in entry_set,
            workload_kind=workload.workload_kind,
            service_account=service_account_name,
            service_account_node=sa_id,
        )
        indexes.add_workload(wid, workload.metadata.namespace, workload.metadata.name, sa_id)
        graph.add_node(sa_id, kind="serviceaccount", name=service_account_name, namespace=workload.metadata.namespace)
        indexes.add_service_account(sa_id, workload.metadata.namespace)
        automount = workload.automount_token if workload.automount_token is not None else True
        if automount:
            graph.add_edge(
                wid,
                sa_id,
                relation="uses_token",
                source_object=workload.metadata.name,
                rationale="Compromised workload can use its service account token.",
            )
        for secret_name in workload.mounted_secrets:
            sid = node_id("secret", workload.metadata.namespace, secret_name)
            graph.add_node(sid, kind="secret", name=secret_name, namespace=workload.metadata.namespace)
            indexes.add_secret(sid, workload.metadata.namespace, secret_name)
            graph.add_edge(
                wid,
                sid,
                relation="mounted_secret",
                source_object=workload.metadata.name,
                rationale="Compromised workload can read mounted secret material.",
            )


def scope_id(namespace: str | None, member_kind: str) -> str:
    """Hub node standing for "every <member_kind> in <namespace>" (``*`` = cluster-wide)."""
    return f"scope:{namespace or '*'}:{member_kind}"


def _hub(graph: nx.DiGraph, namespace: str | None, member_kind: str) -> str:
    hub = scope_id(namespace, member_kind)
    if not graph.has_node(hub):
        where = f"namespace {namespace}" if namespace else "the whole cluster"
        graph.add_node(hub, kind="scope", name=f"every {member_kind[:-1]} in {where}", scope_namespace=namespace or "*", member_kind=member_kind)
    return hub


def _link_hubs(graph: nx.DiGraph, indexes: KubernetesIndexes) -> None:
    """Connect each hub to its members once: namespace hubs to their objects, the cluster hub to the
    namespace hubs. This is what turns O(permissions x objects) edges into O(permissions + objects)."""
    for member_kind, by_namespace in (
        ("secrets", indexes.secret_nodes_by_namespace()),
        ("serviceaccounts", indexes.service_account_nodes_by_namespace()),
        ("workloads", indexes.workload_nodes_by_namespace()),
    ):
        cluster_hub = scope_id(None, member_kind)
        has_cluster_hub = graph.has_node(cluster_hub)
        for namespace, members in by_namespace.items():
            namespace_hub = scope_id(namespace, member_kind)
            if has_cluster_hub and not graph.has_node(namespace_hub):
                _hub(graph, namespace, member_kind)
            if not graph.has_node(namespace_hub):
                continue
            for member in members:
                graph.add_edge(namespace_hub, member, relation="contains", rationale=f"Member of {graph.nodes[namespace_hub]['name']}.")
            if has_cluster_hub:
                graph.add_edge(cluster_hub, namespace_hub, relation="contains", rationale="Cluster-wide scope includes every namespace.")


#: When two semantics connect the same pair of nodes, the edge keeps the one that is easier to exploit.
_RELATION_RANK = {"mint_token": 0, "impersonate": 0, "read_secret": 0, "exec_into": 1, "spawn_workload_as": 2, "escalate_rbac": 3}

_EXTENDED_RATIONALE = {
    "mint_token": "Permission can request a token for the service account (TokenRequest).",
    "impersonate": "Permission can impersonate the service account on any request.",
    "exec_into": "Permission can run commands inside the pods of this workload.",
    "escalate_rbac": "Permission can grant itself further RBAC permissions in this scope (escalate/bind).",
}


def _add_escalation_edge(graph: nx.DiGraph, source: str, target: str, relation: str, source_object: str) -> None:
    if graph.has_edge(source, target) and _RELATION_RANK.get(graph.edges[source, target].get("relation"), 99) <= _RELATION_RANK[relation]:
        return
    graph.add_edge(source, target, relation=relation, source_object=source_object, rationale=_EXTENDED_RATIONALE[relation])


def _link_groups(graph: nx.DiGraph, indexes: KubernetesIndexes, groups: dict[str, str | None]) -> None:
    """Every service account in a group's scope inherits what is bound to the group."""
    by_namespace = indexes.service_account_nodes_by_namespace()
    for group_node, namespace in groups.items():
        namespaces = [namespace] if namespace is not None else sorted(by_namespace)
        for ns in namespaces:
            for sa_node in by_namespace.get(ns, []):
                graph.add_edge(sa_node, group_node, relation="member_of", rationale=f"Service account belongs to group {graph.nodes[group_node]['name']}.")


def build_attack_graph(
    model: ClusterModel, scenario: ScenarioConfig, *, compact: bool = False, extended: bool | None = None
) -> nx.DiGraph:
    """Build the Kubernetes attack graph.

    ``compact=False`` (default, legacy shape): one permission node per granted (rule, group, resource,
    verb) and one edge from each escalating permission to every object it reaches.

    ``compact=True`` (what KubernetesProvider uses): permissions that neither read secrets nor mutate
    workloads are not materialized, and wide grants point at a shared hub node ("every secret in
    namespace X") instead of at each object. Attacker effort between any two nodes is identical in
    both shapes (hub membership edges cost nothing), so risk and plans do not change; size drops from
    O(permissions x objects) to O(permissions + objects). In compact mode a pivot grant reaches every
    service account known at the end of the build, including ones that only appear as binding
    subjects (the legacy shape misses those that are declared after the grant is processed).

    ``extended`` (defaults to ``compact``) adds the escalation primitives beyond secret reads and
    workload mutation: grants to service-account groups (``system:serviceaccounts[:<ns>]``,
    ``system:authenticated``), TokenRequest, impersonation, ``pods/exec`` and RBAC ``escalate``/``bind``.
    Subjects that are not modeled (users, other groups) are counted in ``graph.graph["unmodeled_subjects"]``.
    """
    extended = compact if extended is None else extended
    groups: dict[str, str | None] = {}
    unmodeled_subjects = 0
    graph = nx.DiGraph()
    indexes = KubernetesIndexes()
    role_index = _build_role_index(model)
    skipped_permissions = 0

    for secret in model.secrets:
        sid = node_id("secret", secret.metadata.namespace, secret.metadata.name)
        graph.add_node(sid, kind="secret", name=secret.metadata.name, namespace=secret.metadata.namespace, secret_type=secret.kind)
        indexes.add_secret(sid, secret.metadata.namespace, secret.metadata.name)

    for service_account in model.service_accounts:
        sa_id = node_id("serviceaccount", service_account.metadata.namespace, service_account.metadata.name)
        graph.add_node(sa_id, kind="serviceaccount", name=service_account.metadata.name, namespace=service_account.metadata.namespace)
        indexes.add_service_account(sa_id, service_account.metadata.namespace)

    _attach_workload_nodes(graph, model, scenario, indexes)

    for binding in model.role_bindings:
        role = _resolve_role(binding, role_index)
        if not role:
            continue
        grant_scope, grant_namespace = _resource_scope(binding)
        for subject in binding.subjects:
            is_group, group_namespace = service_account_group(subject.name) if subject.kind == "Group" else (False, None)
            if subject.kind == "ServiceAccount":
                sa_namespace = subject.namespace or binding.metadata.namespace
                sa_id = node_id("serviceaccount", sa_namespace, subject.name)
                graph.add_node(sa_id, kind="serviceaccount", name=subject.name, namespace=sa_namespace)
                indexes.add_service_account(sa_id, sa_namespace)
            elif extended and is_group:
                # The group node stands where a service account would: its members reach it at no cost.
                sa_namespace = "*"
                sa_id = f"group:{subject.name}"
                graph.add_node(sa_id, kind="group", name=subject.name)
                groups[sa_id] = group_namespace
            else:
                unmodeled_subjects += 1
                continue
            for rule_index, rule in enumerate(role.rules):
                api_groups = rule.api_groups or [""]
                for api_group in api_groups:
                    for resource in rule.resources or ["*"]:
                        for verb in rule.verbs or ["*"]:
                            binding_namespace = grant_namespace or "*"
                            pid = permission_id(
                                sa_namespace,
                                subject.name,
                                binding_namespace,
                                binding.metadata.name,
                                role.metadata.name,
                                rule_index,
                                api_group,
                                resource,
                                verb,
                            )
                            resource_names = sorted(set(rule.resource_names))
                            reads_secrets = _permission_targets_secret(resource, verb, api_group)
                            mutates_workloads = _permission_targets_workload_mutation(resource, verb, api_group)
                            mints_tokens = extended and _permission_mints_tokens(resource, verb, api_group)
                            impersonates = extended and _permission_impersonates(resource, verb, api_group)
                            execs = extended and _permission_execs_into_pods(resource, verb, api_group)
                            escalates = extended and _permission_escalates_rbac(resource, verb, api_group)
                            if compact and not (reads_secrets or mutates_workloads or mints_tokens or impersonates or execs or escalates):
                                skipped_permissions += 1
                                continue
                            graph.add_node(
                                pid,
                                kind="permission",
                                namespace=grant_namespace or sa_namespace,
                                subject_namespace=sa_namespace,
                                role_name=role.metadata.name,
                                binding_name=binding.metadata.name,
                                binding_namespace=binding.metadata.namespace,
                                resource=resource,
                                verb=verb,
                                api_group=api_group,
                                resource_names=resource_names,
                                scope=grant_scope,
                                binding_scope=binding.scope,
                            )
                            graph.add_edge(
                                sa_id,
                                pid,
                                relation="granted_permission",
                                source_object=binding.metadata.name,
                                rationale=(
                                    f"Role binding {binding.metadata.name} grants {verb} on "
                                    f"{resource} in scope {grant_scope.lower()}."
                                ),
                            )

                            if reads_secrets and compact and not resource_names:
                                graph.add_edge(
                                    pid,
                                    _hub(graph, grant_namespace, "secrets"),
                                    relation="read_secret",
                                    source_object=role.metadata.name,
                                    rationale="Permission can read secret material that could unlock crown-jewel access.",
                                )
                            elif reads_secrets:
                                for secret_id in indexes.secret_targets(grant_scope, grant_namespace, resource_names):
                                    graph.add_edge(
                                        pid,
                                        secret_id,
                                        relation="read_secret",
                                        source_object=role.metadata.name,
                                        rationale="Permission can read secret material that could unlock crown-jewel access.",
                                    )

                            if mutates_workloads:
                                targets: list[tuple[str, str | None]] = []
                                if resource_names and verb != "create":
                                    targets = indexes.workload_targets(grant_scope, grant_namespace, resource_names, current_sa=sa_id)
                                if not targets and compact:
                                    targets = [(_hub(graph, grant_namespace, "serviceaccounts"), None)]
                                elif not targets:
                                    targets = indexes.service_account_targets(grant_scope, grant_namespace, current_sa=sa_id)
                                for target_sa, target_workload in targets:
                                    graph.add_edge(
                                        pid,
                                        target_sa,
                                        relation="spawn_workload_as",
                                        source_object=role.metadata.name,
                                        target_workload=target_workload,
                                        rationale=(
                                            "Permission can create or mutate workloads and pivot into "
                                            "another service account in the reachable scope."
                                        ),
                                    )

                            source = role.metadata.name
                            for applies, relation in ((mints_tokens, "mint_token"), (impersonates, "impersonate")):
                                if not applies:
                                    continue
                                if compact and not resource_names:
                                    identity_targets = [_hub(graph, grant_namespace, "serviceaccounts")]
                                else:
                                    identity_targets = indexes.service_accounts_in_scope(grant_scope, grant_namespace, resource_names)
                                for target in identity_targets:
                                    if target != sa_id:
                                        _add_escalation_edge(graph, pid, target, relation, source)
                            if execs:
                                if compact and not resource_names:
                                    exec_targets = [_hub(graph, grant_namespace, "workloads")]
                                else:
                                    exec_targets = indexes.workloads_in_scope(grant_scope, grant_namespace, resource_names)
                                for target in exec_targets:
                                    _add_escalation_edge(graph, pid, target, "exec_into", source)
                            if escalates:
                                if compact:
                                    admin_targets = [_hub(graph, grant_namespace, "secrets"), _hub(graph, grant_namespace, "serviceaccounts")]
                                else:
                                    admin_targets = indexes.secret_targets(grant_scope, grant_namespace, []) + [
                                        t for t in indexes.service_accounts_in_scope(grant_scope, grant_namespace, []) if t != sa_id
                                    ]
                                for target in admin_targets:
                                    _add_escalation_edge(graph, pid, target, "escalate_rbac", source)

    if extended:
        _link_groups(graph, indexes, groups)
    graph.graph["unmodeled_subjects"] = unmodeled_subjects
    if compact:
        _link_hubs(graph, indexes)
        graph.graph["compact"] = True
        graph.graph["skipped_permissions"] = skipped_permissions
    _mark_crown_jewels(graph, scenario.crown_jewels)
    return graph
