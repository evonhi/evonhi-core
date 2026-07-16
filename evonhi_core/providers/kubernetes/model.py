"""Kubernetes provider model (Fase 4, multi-cloud refactor).

The Kubernetes-specific dataclasses moved here from ``evonhi_core.models`` when the provider
was extracted. Generic types (AttackPath, RemediationAction, PlanEvaluation, CrownJewelSpec,
ScenarioConfig) stay in ``evonhi_core.models``, which re-exports these for back-compat.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Metadata:
    name: str
    namespace: str = "default"
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ServiceAccount:
    metadata: Metadata
    automount_token: bool | None = None


@dataclass(slots=True)
class PolicyRule:
    resources: list[str]
    verbs: list[str]
    api_groups: list[str] = field(default_factory=list)
    resource_names: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Role:
    metadata: Metadata
    rules: list[PolicyRule]
    scope: str = "Namespaced"


@dataclass(slots=True)
class SubjectRef:
    kind: str
    name: str
    namespace: str = "default"


@dataclass(slots=True)
class RoleBinding:
    metadata: Metadata
    role_ref_kind: str
    role_ref_name: str
    subjects: list[SubjectRef]
    scope: str = "Namespaced"


@dataclass(slots=True)
class Secret:
    metadata: Metadata
    kind: str = "Opaque"


@dataclass(slots=True)
class Workload:
    metadata: Metadata
    workload_kind: str
    service_account_name: str = "default"
    automount_token: bool | None = None
    mounted_secrets: list[str] = field(default_factory=list)
    public: bool = False


@dataclass(slots=True)
class NetworkPolicy:
    metadata: Metadata


@dataclass(slots=True)
class ClusterModel:
    service_accounts: list[ServiceAccount] = field(default_factory=list)
    roles: list[Role] = field(default_factory=list)
    role_bindings: list[RoleBinding] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    workloads: list[Workload] = field(default_factory=list)
    network_policies: list[NetworkPolicy] = field(default_factory=list)
