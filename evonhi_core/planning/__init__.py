"""Remediation planner v2 — exact residual-risk model + decomposed memetic multi-objective search.

Replaces the v1 ``optimize_actions`` (capped path counting + plain NSGA-II), which is kept only for
backward compatibility and is deprecated.
"""

from __future__ import annotations

from evonhi_core.planning.model import (
    DEFAULT_CAPABILITY_EFFORT,
    DEFAULT_RELATION_EFFORT,
    FrontPoint,
    PlannedRemediation,
    PlannerConfig,
    PlanningDiagnostics,
    PlanningResult,
    PlanStep,
    RiskModel,
)
from evonhi_core.planning.planner import assess_risk, plan_remediation

__all__ = [
    "plan_remediation",
    "assess_risk",
    "RiskModel",
    "PlannerConfig",
    "PlanningResult",
    "PlannedRemediation",
    "PlanStep",
    "FrontPoint",
    "PlanningDiagnostics",
    "DEFAULT_RELATION_EFFORT",
    "DEFAULT_CAPABILITY_EFFORT",
]
