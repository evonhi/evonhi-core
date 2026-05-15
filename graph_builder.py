from __future__ import annotations

from typing import Dict, Iterable, Tuple

import networkx as nx

from app.domain.analysis_models import ClusterModel, CrownJewelSpec, PolicyRule, Role, RoleBinding, ScenarioConfig

SECRET_READ_VERBS = {"get", "list", "watch", "*"}
WORKLOAD_MUTATION_VERBS = {"create", "patch", "update", "*"}
WORKLOAD_API_GROUPS = {
    "deployments": {"apps", "*"},
    "daemonsets": {"apps", "*"},
    "statefulsets": {"apps", "*"},
    "pods": {"", "*"},
    "jobs": {"batch", "*"},
    "cronjobs": {"batch", "*"},
}


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


def _permission_targets_secret(resource: str, verb: str, api_group: str) -> bool:
    if verb not in SECRET_READ_VERBS:
        return False
    if resource == "secrets":
        return api_group in {"", "*"}
    if resource == "*":
        return api_group in {"", "*"}
    return False


def _permission_targets_workload_mutation(resource: str, verb: str, api_group: str) -> bool:
    if verb not in WORKLOAD_MUTATION_VERBS:
        return False
    if resource == "*":
        return api_group in {"", "apps", "batch", "*"}
    return api_group in WORKLOAD_API_GROUPS.get(resource, set())


def _resource_scope(binding: RoleBinding) -> tuple[str, str | None]:
    if binding.scope == "Cluster":
        return "Cluster", None
    return "Namespaced", binding.metadata.namespace


def _iter_target_namespaces(graph: nx.DiGraph, grant_scope: str, grant_namespace: str | None) -> set[str]:
    if grant_scope == "Cluster":
        return {
            attrs["namespace"]
            for _, attrs in graph.nodes(data=True)
            if attrs.get("namespace")
        }
    return {grant_namespace or "default"}


def _iter_secret_targets(
    graph: nx.DiGraph,
    grant_scope: str,
    grant_namespace: str | None,
    resource_names: list[str],
) -> list[str]:
    target_namespaces = _iter_target_namespaces(graph, grant_scope, grant_namespace)
    targets = []
    for node, attrs in graph.nodes(data=True):
        if attrs.get("kind") != "secret":
            continue
        if attrs.get("namespace") not in target_namespaces:
            continue
        if resource_names and attrs.get("name") not in resource_names:
            continue
        targets.append(node)
    return targets


def _service_account_targets(
    graph: nx.DiGraph,
    current_sa: str,
    grant_scope: str,
    grant_namespace: str | None,
    resource_names: list[str],
    verb: str,
) -> list[tuple[str, str | None]]:
    target_namespaces = _iter_target_namespaces(graph, grant_scope, grant_namespace)
    workload_targets: list[tuple[str, str | None]] = []

    if resource_names and verb != "create":
        for node, attrs in graph.nodes(data=True):
            if attrs.get("kind") != "workload":
                continue
            if attrs.get("namespace") not in target_namespaces:
                continue
            if attrs.get("name") not in resource_names:
                continue
            target_sa = attrs.get("service_account_node")
            if target_sa and target_sa != current_sa:
                workload_targets.append((target_sa, attrs.get("name")))
        if workload_targets:
            return workload_targets

    targets = []
    for node, attrs in graph.nodes(data=True):
        if attrs.get("kind") != "serviceaccount":
            continue
        if node == current_sa:
            continue
        if attrs.get("namespace") not in target_namespaces:
            continue
        targets.append((node, None))
    return targets


def _mark_crown_jewels(graph: nx.DiGraph, jewels: Iterable[CrownJewelSpec]) -> None:
    for jewel in jewels:
        target = node_id(jewel.kind, jewel.namespace, jewel.name)
        if graph.has_node(target):
            graph.nodes[target]["crown_jewel"] = True
            graph.nodes[target]["criticality"] = jewel.criticality
            graph.nodes[target]["rationale"] = jewel.rationale


def _attach_workload_nodes(graph: nx.DiGraph, model: ClusterModel, scenario: ScenarioConfig) -> None:
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
        graph.add_node(sa_id, kind="serviceaccount", name=service_account_name, namespace=workload.metadata.namespace)
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
            graph.add_edge(
                wid,
                sid,
                relation="mounted_secret",
                source_object=workload.metadata.name,
                rationale="Compromised workload can read mounted secret material.",
            )


def build_attack_graph(model: ClusterModel, scenario: ScenarioConfig) -> nx.DiGraph:
    graph = nx.DiGraph()
    role_index = _build_role_index(model)

    for secret in model.secrets:
        sid = node_id("secret", secret.metadata.namespace, secret.metadata.name)
        graph.add_node(sid, kind="secret", name=secret.metadata.name, namespace=secret.metadata.namespace, secret_type=secret.kind)

    for service_account in model.service_accounts:
        sa_id = node_id("serviceaccount", service_account.metadata.namespace, service_account.metadata.name)
        graph.add_node(sa_id, kind="serviceaccount", name=service_account.metadata.name, namespace=service_account.metadata.namespace)

    _attach_workload_nodes(graph, model, scenario)

    for binding in model.role_bindings:
        role = _resolve_role(binding, role_index)
        if not role:
            continue
        grant_scope, grant_namespace = _resource_scope(binding)
        for subject in binding.subjects:
            if subject.kind != "ServiceAccount":
                continue
            sa_namespace = subject.namespace or binding.metadata.namespace
            sa_id = node_id("serviceaccount", sa_namespace, subject.name)
            graph.add_node(sa_id, kind="serviceaccount", name=subject.name, namespace=sa_namespace)
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

                            if _permission_targets_secret(resource, verb, api_group):
                                for secret_id in _iter_secret_targets(
                                    graph,
                                    grant_scope=grant_scope,
                                    grant_namespace=grant_namespace,
                                    resource_names=resource_names,
                                ):
                                    graph.add_edge(
                                        pid,
                                        secret_id,
                                        relation="read_secret",
                                        source_object=role.metadata.name,
                                        rationale="Permission can read secret material that could unlock crown-jewel access.",
                                    )

                            if _permission_targets_workload_mutation(resource, verb, api_group):
                                for target_sa, target_workload in _service_account_targets(
                                    graph,
                                    current_sa=sa_id,
                                    grant_scope=grant_scope,
                                    grant_namespace=grant_namespace,
                                    resource_names=resource_names,
                                    verb=verb,
                                ):
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

    _mark_crown_jewels(graph, scenario.crown_jewels)
    return graph
