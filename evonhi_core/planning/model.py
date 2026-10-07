"""Configuration and result types for the remediation planner (planner v2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from evonhi_core.models import AttackPath

#: Attacker effort to traverse one edge of each relation (dimensionless; 1.0 ~ "one easy step").
#: ``granted_permission`` is a structural hop into a permission node, so it costs nothing by itself;
#: the effort is paid on the edge that actually exercises the permission.
DEFAULT_RELATION_EFFORT: Mapping[str, float] = MappingProxyType(
    {
        "uses_token": 1.0,
        "mounted_secret": 1.0,
        "granted_permission": 0.0,
        "read_secret": 1.0,
        "spawn_workload_as": 2.0,
        "pivot_identity": 1.5,
        "contains": 0.0,
    }
)


#: Extra attacker effort for a guard requirement the attacker does not hold, per capability kind.
#: Organization membership is free: an attacker pivoting from a role inside the organization already
#: satisfies ``aws:PrincipalOrgID``. Network position and MFA are the conditions that actually hurt.
DEFAULT_CAPABILITY_EFFORT: Mapping[str, float] = MappingProxyType(
    {
        "org_membership": 0.0,
        "region": 0.5,
        "principal_tag": 2.0,
        "network_position": 4.0,
        "mfa": 6.0,
    }
)


@dataclass(frozen=True, slots=True)
class RiskModel:
    """How exposure is turned into a number.

    For every (entry, crown jewel) pair the attacker effort is the cheapest path under per-edge
    efforts. The likelihood that an entry reaches a jewel is ``exp(-effort / effort_scale)``, and the
    probability that a jewel is compromised aggregates all entries with a noisy-OR:
    ``P(j) = 1 - prod_e (1 - p_e * likelihood(e, j))``. Residual risk is ``sum_j criticality_j * P(j)``
    — an expected loss in criticality units. It is exact (no path cap), polynomial to compute and
    rewards changes that make attacks harder, not only changes that cut them.
    """

    relation_effort: Mapping[str, float] = DEFAULT_RELATION_EFFORT
    default_effort: float = 1.0
    #: Extra effort per unmet guard requirement, by capability kind (see DEFAULT_CAPABILITY_EFFORT).
    capability_effort: Mapping[str, float] = DEFAULT_CAPABILITY_EFFORT
    #: Fallback for capability kinds missing from ``capability_effort`` and for guard tightening that
    #: names no capability.
    unmet_requirement_effort: float = 4.0
    #: Effort added by a ``weaken`` action that does not say how much.
    default_weaken_effort: float = 2.0
    effort_scale: float = 4.0
    #: Prior probability that an entry node gets compromised (node attr ``compromise_likelihood`` wins).
    entry_compromise_likelihood: float = 0.5
    default_criticality: float = 5.0
    #: Paths costlier than this are treated as unreachable (likelihood < exp(-9) ~ 1e-4).
    max_effort: float = 36.0


@dataclass(frozen=True, slots=True)
class PlannerConfig:
    max_plans: int = 5
    #: A component is solved exactly when it has at most this many effective actions...
    exact_action_limit: int = 14
    #: ...or when the number of budget-feasible action subsets is at most this (counted by a
    #: knapsack DP), so tight budgets get provably optimal plans even with many candidate actions.
    exact_subset_limit: int = 20_000
    population_size: int = 64
    max_generations: int = 80
    stagnation_generations: int = 12
    max_evaluations: int = 250_000
    archive_size: int = 64
    #: Probability of running redundancy elimination on an offspring (memetic step).
    local_search_rate: float = 0.25
    explain_paths: int = 10
    #: Upper bound on partial solutions kept while combining component fronts.
    combine_max_points: int = 4_000
    seed: int = 7


@dataclass(slots=True)
class PlanStep:
    action_id: str
    title: str
    cost: int
    impact: float
    risk_after: float
    risk_reduction: float


@dataclass(slots=True)
class PlannedRemediation:
    strategy: str
    selected_actions: list[str]
    steps: list[PlanStep]
    cost: int
    operational_impact: float
    risk_before: float
    risk_after: float
    risk_reduction_ratio: float
    exposures_before: int
    exposures_after: int
    jewels_exposed_after: int
    residual_paths: list[AttackPath] = field(default_factory=list)


@dataclass(slots=True)
class FrontPoint:
    cost: int
    operational_impact: float
    risk_after: float
    risk_reduction_ratio: float
    selected_actions: list[str]


@dataclass(slots=True)
class PlanningDiagnostics:
    actions_total: int
    actions_effective: int
    actions_without_effect: int
    actions_dominated: int
    components: int
    exact_components: int
    evaluations: int
    optimality: str  # "exact" | "heuristic"
    runtime_seconds: float
    budget: int | None


@dataclass(slots=True)
class PlanningResult:
    baseline_risk: float
    baseline_exposures: int
    jewels_exposed: int
    risk_by_jewel: dict[str, float]
    baseline_paths: list[AttackPath]
    plans: list[PlannedRemediation]
    pareto_front: list[FrontPoint]
    diagnostics: PlanningDiagnostics


def requirement_effort(model: RiskModel, unmet) -> float:
    """Attacker effort to satisfy the capabilities in ``unmet``."""
    return sum(model.capability_effort.get(cap.kind.value, model.unmet_requirement_effort) for cap in unmet)
