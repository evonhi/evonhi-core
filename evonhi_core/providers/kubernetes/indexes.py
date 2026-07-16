"""Inverted indexes for Kubernetes edge construction (Fase 4, multi-cloud refactor).

The old builder resolved each permission's secret/workload/service-account targets by
scanning EVERY graph node once per permission — O(permissions x N) ≈ O(N^2). These indexes
answer the same queries in ~O(1)/O(k) by precomputing ``namespace -> nodes`` maps, turning
the construction into ~O(N+E).

Correctness note: the maps mirror exactly the nodes the old scans would have seen. Secrets
and workloads are all present before the binding loop, so their maps are static. Service
accounts, however, grow during the loop (binding subjects), so the SA map is updated
incrementally at the same points the old builder added the SA node — reproducing the old
scan's "nodes added so far" visibility, and thus a byte-identical graph.

Cluster-scoped grants target every namespace; since every entity's own namespace is always
in that set, a Cluster grant simply targets all entities of that kind (the permission-only
namespaces the old scan also saw never contribute secrets/workloads/SAs).
"""

from __future__ import annotations


class KubernetesIndexes:
    __slots__ = (
        "_secrets_by_ns",
        "_all_secrets",
        "_secret_seen",
        "_workloads_by_ns",
        "_all_workloads",
        "_sas_by_ns",
        "_all_sas",
        "_sa_seen",
    )

    def __init__(self) -> None:
        self._secrets_by_ns: dict[str, list[tuple[str, str]]] = {}          # ns -> [(node, name)]
        self._all_secrets: list[tuple[str, str]] = []                       # [(node, name)] insertion order
        self._secret_seen: set[str] = set()
        self._workloads_by_ns: dict[str, list[tuple[str, str, str]]] = {}   # ns -> [(node, name, sa_node)]
        self._all_workloads: list[tuple[str, str, str]] = []                # [(node, name, sa_node)]
        self._sas_by_ns: dict[str, list[str]] = {}                          # ns -> [sa_node]
        self._all_sas: list[str] = []                                       # [sa_node] insertion order
        self._sa_seen: set[str] = set()

    # -- population (called as the builder adds nodes) -----------------------

    def add_secret(self, node: str, namespace: str, name: str) -> None:
        if node in self._secret_seen:
            return
        self._secret_seen.add(node)
        self._secrets_by_ns.setdefault(namespace, []).append((node, name))
        self._all_secrets.append((node, name))

    def add_workload(self, node: str, namespace: str, name: str, service_account_node: str) -> None:
        self._workloads_by_ns.setdefault(namespace, []).append((node, name, service_account_node))
        self._all_workloads.append((node, name, service_account_node))

    def add_service_account(self, node: str, namespace: str) -> None:
        if node in self._sa_seen:
            return
        self._sa_seen.add(node)
        self._sas_by_ns.setdefault(namespace, []).append(node)
        self._all_sas.append(node)

    # -- queries (replace the old O(N) scans) --------------------------------

    def secret_targets(self, grant_scope: str, grant_namespace: str | None, resource_names: list[str]) -> list[str]:
        names = set(resource_names)
        items = self._all_secrets if grant_scope == "Cluster" else self._secrets_by_ns.get(grant_namespace or "default", [])
        return [node for node, name in items if not names or name in names]

    def workload_targets(
        self, grant_scope: str, grant_namespace: str | None, resource_names: list[str], current_sa: str
    ) -> list[tuple[str, str | None]]:
        names = set(resource_names)
        items = self._all_workloads if grant_scope == "Cluster" else self._workloads_by_ns.get(grant_namespace or "default", [])
        out: list[tuple[str, str | None]] = []
        for node, name, sa_node in items:
            if name not in names:
                continue
            if sa_node and sa_node != current_sa:
                out.append((sa_node, name))
        return out

    def service_account_targets(
        self, grant_scope: str, grant_namespace: str | None, current_sa: str
    ) -> list[tuple[str, str | None]]:
        sas = self._all_sas if grant_scope == "Cluster" else self._sas_by_ns.get(grant_namespace or "default", [])
        return [(sa, None) for sa in sas if sa != current_sa]
