"""Generic (provider-agnostic) engine types.

The Kubernetes-specific dataclasses moved to ``evonhi_core.providers.kubernetes.model`` in
Fase 4 of the multi-cloud refactor and are re-exported here so the public import surface
(``from evonhi_core.models import ClusterModel``) stays frozen for evo_saas and the golden
fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Back-compat re-export of the Kubernetes model types (now provider-owned).
from evonhi_core.providers.kubernetes.model import (  # noqa: F401  (re-export shim)
    ClusterModel,
    Metadata,
    NetworkPolicy,
    PolicyRule,
    Role,
    RoleBinding,
    Secret,
    ServiceAccount,
    SubjectRef,
    Workload,
)


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
    # Multi-cloud refactor (Fase 3), all additive with defaults so existing constructions
    # keep working. effect_kind selects how the applicator realizes the action; guard_delta
    # carries the capability change for a modify_guard action (e.g. add required=[...] to an
    # assume-role); impact_context carries the telemetry-lookup keys the ImpactEstimator uses.
    effect_kind: str = "remove_edge"  # "remove_edge" | "modify_guard" | "remove_node" | "weaken"
    guard_delta: dict[str, Any] | None = None
    impact_context: dict[str, Any] | None = None


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
