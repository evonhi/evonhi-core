"""Collector snapshot -> ClusterModel (contract: ``contracts/cluster-snapshot.v1.schema.json``).

Lives in the open core on purpose: a customer can audit exactly how the data their in-cluster
agent sends is interpreted. Pure translation, no I/O.

Semantics mirrored from Kubernetes:

* ``automountServiceAccountToken`` on the pod wins; when it is unset the service account's value
  applies; when both are unset the token is mounted.
* A secret is readable from a compromised workload when it is mounted as a volume or injected
  through ``env``/``envFrom``. ``imagePullSecrets`` are used by the kubelet, never exposed to the
  container, so they are not an exposure.
* A workload is an entry point when the collector saw it exposed (LoadBalancer/NodePort Service,
  Ingress) or it carries the ``evonhi.io/public: "true"`` label/annotation.
"""

from __future__ import annotations

from typing import Any, Mapping

from evonhi_core.providers.kubernetes.model import (
    ClusterModel,
    Metadata,
    PolicyRule,
    Role,
    RoleBinding,
    Secret,
    ServiceAccount,
    SubjectRef,
    Workload,
)

SUPPORTED_MAJOR = "1"
PUBLIC_MARKER = "evonhi.io/public"
_UNREADABLE_MOUNTS = {"imagePullSecret"}


class SnapshotError(ValueError):
    """The payload does not follow the cluster-snapshot contract."""


def cluster_model_from_snapshot(payload: Mapping[str, Any]) -> ClusterModel:
    version = str(payload.get("schema_version", ""))
    if version.split(".")[0] != SUPPORTED_MAJOR:
        raise SnapshotError(f"unsupported cluster snapshot schema_version {version!r} (supported: {SUPPORTED_MAJOR}.x)")
    for key in ("workloads", "service_accounts", "roles", "cluster_roles", "role_bindings", "cluster_role_bindings", "secrets"):
        if not isinstance(payload.get(key) or [], list):
            raise SnapshotError(f"{key} must be a list")

    model = ClusterModel()
    sa_automount: dict[tuple[str, str], bool | None] = {}
    for item in payload.get("service_accounts") or []:
        namespace, name = _required(item, "namespace", "service_accounts"), _required(item, "name", "service_accounts")
        automount = item.get("automount_token")
        sa_automount[(namespace, name)] = automount
        model.service_accounts.append(
            ServiceAccount(metadata=_metadata(item, namespace), automount_token=automount)
        )

    for item in payload.get("roles") or []:
        model.roles.append(Role(metadata=_metadata(item, _required(item, "namespace", "roles")), rules=_rules(item), scope="Namespaced"))
    for item in payload.get("cluster_roles") or []:
        model.roles.append(Role(metadata=_metadata(item, "default"), rules=_rules(item), scope="Cluster"))

    for item in payload.get("role_bindings") or []:
        namespace = _required(item, "namespace", "role_bindings")
        model.role_bindings.append(_binding(item, namespace, "Namespaced"))
    for item in payload.get("cluster_role_bindings") or []:
        model.role_bindings.append(_binding(item, "default", "Cluster"))

    readable_mounts: dict[tuple[str, str], set[str]] = {}
    for item in payload.get("secrets") or []:
        namespace, name = _required(item, "namespace", "secrets"), _required(item, "name", "secrets")
        model.secrets.append(Secret(metadata=_metadata(item, namespace), kind=item.get("type") or "Opaque"))
        for mount in item.get("mounted_by") or []:
            if mount.get("via") in _UNREADABLE_MOUNTS:
                continue
            readable_mounts.setdefault((mount.get("namespace") or namespace, mount.get("workload", "")), set()).add(name)

    for item in payload.get("workloads") or []:
        namespace, name = _required(item, "namespace", "workloads"), _required(item, "name", "workloads")
        service_account = item.get("service_account") or "default"
        automount = item.get("automount_token")
        if automount is None:
            automount = sa_automount.get((namespace, service_account))
        mounted = item.get("mounted_secrets")
        if mounted is None:  # schema 1.0: reconstruct from the secrets' mounted_by index
            mounted = sorted(readable_mounts.get((namespace, name), set()))
        labels = dict(item.get("labels") or {})
        public = bool(item.get("public")) or str(labels.get(PUBLIC_MARKER, "")).lower() == "true"
        model.workloads.append(
            Workload(
                metadata=Metadata(name=name, namespace=namespace, labels=labels, annotations=dict(item.get("annotations") or {})),
                workload_kind=item.get("kind") or "Workload",
                service_account_name=service_account,
                automount_token=automount,
                mounted_secrets=sorted(set(mounted)),
                public=public or str((item.get("annotations") or {}).get(PUBLIC_MARKER, "")).lower() == "true",
            )
        )
    return model


def _required(item: Mapping[str, Any], key: str, section: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value:
        raise SnapshotError(f"{section}: every entry needs a non-empty {key!r}")
    return value


def _metadata(item: Mapping[str, Any], namespace: str) -> Metadata:
    return Metadata(
        name=str(item.get("name", "unknown")),
        namespace=namespace,
        labels=dict(item.get("labels") or {}),
        annotations=dict(item.get("annotations") or {}),
    )


def _rules(item: Mapping[str, Any]) -> list[PolicyRule]:
    return [
        PolicyRule(
            resources=list(rule.get("resources") or []),
            verbs=list(rule.get("verbs") or []),
            api_groups=list(rule.get("api_groups") or []),
            resource_names=list(rule.get("resource_names") or []),
        )
        for rule in item.get("rules") or []
        if rule.get("resources")  # non-resource URL rules grant nothing on objects
    ]


def _binding(item: Mapping[str, Any], namespace: str, scope: str) -> RoleBinding:
    role_ref = item.get("role_ref") or {}
    if role_ref.get("kind") not in {"Role", "ClusterRole"} or not role_ref.get("name"):
        raise SnapshotError(f"binding {item.get('name')!r} has an invalid role_ref")
    subjects = [
        SubjectRef(kind=str(s.get("kind", "")), name=str(s.get("name", "")), namespace=s.get("namespace") or namespace)
        for s in item.get("subjects") or []
    ]
    return RoleBinding(
        metadata=_metadata(item, namespace),
        role_ref_kind=role_ref["kind"],
        role_ref_name=role_ref["name"],
        subjects=subjects,
        scope=scope,
    )
