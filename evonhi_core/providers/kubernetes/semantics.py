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


# --------------------------------------------------------------------------- #
# Extended escalation primitives (opt-in via build_attack_graph(extended=True))
# --------------------------------------------------------------------------- #

RBAC_API_GROUPS = {"rbac.authorization.k8s.io", "*"}
CORE_API_GROUPS = {"", "*"}

#: Groups every service account belongs to. ``system:serviceaccounts:<namespace>`` is handled by prefix.
SERVICE_ACCOUNT_GROUPS = {"system:serviceaccounts", "system:authenticated"}


def service_account_group(name: str) -> tuple[bool, str | None]:
    """(is a group of service accounts, namespace it is limited to or None for the whole cluster)."""
    if name in SERVICE_ACCOUNT_GROUPS:
        return True, None
    prefix = "system:serviceaccounts:"
    if name.startswith(prefix) and len(name) > len(prefix):
        return True, name[len(prefix):]
    return False, None


def _permission_mints_tokens(resource: str, verb: str, api_group: str) -> bool:
    """TokenRequest: ``create`` on ``serviceaccounts/token`` issues a token for that service account."""
    return verb in {"create", "*"} and resource in {"serviceaccounts/token", "*"} and api_group in CORE_API_GROUPS


def _permission_impersonates(resource: str, verb: str, api_group: str) -> bool:
    """``impersonate`` on service accounts lets the holder act as them on every request."""
    return verb in {"impersonate", "*"} and resource in {"serviceaccounts", "*"} and api_group in CORE_API_GROUPS


def _permission_execs_into_pods(resource: str, verb: str, api_group: str) -> bool:
    """``pods/exec`` and ``pods/attach`` run code inside existing pods (``get`` also works over websockets)."""
    return verb in {"create", "get", "*"} and resource in {"pods/exec", "pods/attach", "*"} and api_group in CORE_API_GROUPS


def _permission_escalates_rbac(resource: str, verb: str, api_group: str) -> bool:
    """``escalate``/``bind`` on roles let the holder grant itself any permission in the scope.

    Conservative: it assumes the companion verb needed to use it (update a role, create a binding)
    is available too, which is how these verbs are granted in practice."""
    return verb in {"escalate", "bind", "*"} and resource in {"roles", "clusterroles", "*"} and api_group in RBAC_API_GROUPS
