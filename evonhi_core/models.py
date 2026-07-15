from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
class CrownJewelSpec:
    kind: str
    name: str
    namespace: str = "default"
    criticality: int = 10
    rationale: str = "High-value target"


@dataclass(slots=True)
class ScenarioConfig:
    crown_jewels: list[CrownJewelSpec] = field(default_factory=list)
    entry_workloads: list[str] = field(default_factory=list)
    max_paths: int = 50
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ClusterModel:
    service_accounts: list[ServiceAccount] = field(default_factory=list)
    roles: list[Role] = field(default_factory=list)
    role_bindings: list[RoleBinding] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    workloads: list[Workload] = field(default_factory=list)
    network_policies: list[NetworkPolicy] = field(default_factory=list)


@dataclass(slots=True)
class AttackPath:
    nodes: list[str]
    score: float
    relations: list[str] = field(default_factory=list)
    headline: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class RemediationAction:
    action_id: str
    title: str
    description: str
    cost: int
    impact: float
    action_type: str
    relation: str = ""
    target_nodes: list[str] = field(default_factory=list)
    target_edges: list[tuple[str, str]] = field(default_factory=list)
    rationale: str = ""
    telemetry_confidence: float | None = None


@dataclass(slots=True)
class PlanEvaluation:
    selected_actions: list[str]
    remaining_paths: int
    reduced_paths: int
    cost: int
    operational_impact: float
    coverage_ratio: float
    rank: int = 0
    crowding_distance: float = 0.0
