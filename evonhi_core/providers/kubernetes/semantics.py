"""Kubernetes escalation semantics (Fase 4, multi-cloud refactor).

Moved verbatim from the old ``graph_builder`` so the effective meaning of "this permission
can read a secret / can mutate a workload and pivot" is provider-owned and unchanged.
"""

from __future__ import annotations

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
