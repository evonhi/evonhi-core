"""Remediation planner v2: exact risk, problem decomposition, memetic search, global combination.

Pipeline
--------
1. Compile the relevant attack surface (edges on some entry -> crown-jewel route) and every action's
   effect on it. Actions that touch nothing relevant are reported, not searched.
2. Drop dominated actions (another action changes at least as much for no more cost and impact).
3. Decompose into independent components: residual risk is a sum over crown jewels, and a jewel
   only depends on edges in its weakly-connected component, so components are optimized separately.
4. Per component: exact enumeration when small, otherwise the memetic NSGA-II in ``search``.
5. Combine component fronts with a multi-choice knapsack DP into the global Pareto front under the
   budget (exact when every component was exact and no thinning was needed).
6. Pick a small, diverse set of plans (max reduction, knee, low disruption, quick win), order each
   plan's actions into an implementation sequence and explain the residual exposure.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Sequence

import networkx as nx

from evonhi_core.models import AttackPath, RemediationAction
from evonhi_core.planning.model import (
    FrontPoint,
    PlannedRemediation,
    PlannerConfig,
    PlanningDiagnostics,
    PlanningResult,
    PlanStep,
    RiskModel,
)
from evonhi_core.planning.risk import ComponentEvaluator, Evaluation
from evonhi_core.planning.search import Candidate, ComponentSearch, pareto_filter
from evonhi_core.planning.surface import ActionEffect, AttackSurface

_EPS = 1e-9


@dataclass(slots=True)
class _Component:
    evaluator: ComponentEvaluator
    actions: frozenset[int]
    front: list[Candidate]
    exact: bool


@dataclass(slots=True)
class _Partial:
    risk: float
    cost: int
    impact: float
    back: tuple[int, int]  # (index in previous layer, index in component front)


class _Plan:
    """Shared evaluation over all components (risk is additive across them)."""

    def __init__(self, components: list[_Component], effects: dict[int, ActionEffect]) -> None:
        self.components = components
        self.effects = effects
        self.component_of = {idx: comp for comp in components for idx in comp.actions}

    def component_risk(self, comp: _Component, selection: frozenset[int]) -> float:
        return comp.evaluator.evaluate(selection & comp.actions).risk

    def evaluate(self, selection: frozenset[int]) -> Evaluation:
        risk, exposures, jewels = 0.0, 0, 0
        for comp in self.components:
            result = comp.evaluator.evaluate(selection & comp.actions)
            risk += result.risk
            exposures += result.exposures
            jewels += result.jewels_exposed
        return Evaluation(risk, exposures, jewels)

    def paths(self, selection: frozenset[int], limit: int) -> list[AttackPath]:
        scored: list[tuple[float, AttackPath]] = []
        for comp in self.components:
            scored.extend(comp.evaluator.paths(selection & comp.actions, limit))
        scored.sort(key=lambda item: (-item[0], len(item[1].nodes), item[1].nodes))
        return [path for _score, path in scored[:limit]]


def assess_risk(
    graph: nx.DiGraph,
    *,
    entry_kinds: Sequence[str] = ("workload",),
    risk_model: RiskModel | None = None,
    explain_paths: int = 10,
) -> PlanningResult:
    """Baseline exposure only (no remediation search)."""
    return plan_remediation(
        graph, [], entry_kinds=entry_kinds, risk_model=risk_model, config=PlannerConfig(explain_paths=explain_paths)
    )


def plan_remediation(
    graph: nx.DiGraph,
    actions: Sequence[RemediationAction],
    *,
    budget: int | None = None,
    entry_kinds: Sequence[str] = ("workload",),
    risk_model: RiskModel | None = None,
    config: PlannerConfig | None = None,
) -> PlanningResult:
    started = time.perf_counter()
    risk_model = risk_model or RiskModel()
    config = config or PlannerConfig()
    rng = random.Random(config.seed)

    surface = AttackSurface(graph, entry_kinds, risk_model)
    all_effects = surface.compile_actions(actions)
    effective = [e for e in all_effects if e.edges]
    kept = _drop_dominated(effective)
    effects = {e.index: e for e in kept}

    # ---- decomposition: components of the relevant surface, merged by multi-component actions
    node_component = surface.components()
    parent: dict[int, int] = {c: c for c in set(node_component)}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for effect in kept:
        roots = sorted({find(node_component[surface.edge_src[e]]) for e in effect.edges})
        for other in roots[1:]:
            parent[other] = roots[0]
    jewels_by: dict[int, list[int]] = {}
    entries_by: dict[int, list[int]] = {}
    actions_by: dict[int, list[ActionEffect]] = {}
    for jewel in surface.jewels:
        jewels_by.setdefault(find(node_component[jewel]), []).append(jewel)
    for entry in surface.entries:
        entries_by.setdefault(find(node_component[entry]), []).append(entry)
    for effect in kept:
        actions_by.setdefault(find(node_component[surface.edge_src[next(iter(effect.edges))]]), []).append(effect)

    components: list[_Component] = []
    for root in sorted(jewels_by):
        comp_effects = actions_by.get(root, [])
        evaluator = ComponentEvaluator(surface, jewels_by[root], entries_by.get(root, []), {e.index: e for e in comp_effects})
        search = ComponentSearch(evaluator, comp_effects, budget, config, rng)
        front = search.run()
        components.append(_Component(evaluator, frozenset(e.index for e in comp_effects), front, search.exact or not comp_effects))

    plan_eval = _Plan(components, effects)
    baseline = plan_eval.evaluate(frozenset())
    global_front, truncated = _combine([c.front for c in components], budget, config.combine_max_points)

    plans = _select_plans(global_front, baseline.risk, config.max_plans)
    planned = [_describe(plan_eval, cand, strategy, baseline, effects, actions, config) for strategy, cand in plans]

    names = surface.node_names
    risk_by_jewel = {name: 0.0 for name in surface.all_jewels}
    for comp in components:
        for jewel, probability in comp.evaluator.jewel_probabilities(frozenset()).items():
            risk_by_jewel[names[jewel]] = round(surface.jewel_criticality[jewel] * probability, 6)

    exact = all(c.exact for c in components) and not truncated
    diagnostics = PlanningDiagnostics(
        actions_total=len(actions),
        actions_effective=len(kept),
        actions_without_effect=len(all_effects) - len(effective),
        actions_dominated=len(effective) - len(kept),
        components=len(components),
        exact_components=sum(1 for c in components if c.exact),
        evaluations=sum(c.evaluator.evaluations for c in components),
        optimality="exact" if exact else "heuristic",
        runtime_seconds=round(time.perf_counter() - started, 4),
        budget=budget,
    )
    return PlanningResult(
        baseline_risk=baseline.risk,
        baseline_exposures=baseline.exposures,
        jewels_exposed=baseline.jewels_exposed,
        risk_by_jewel=risk_by_jewel,
        baseline_paths=plan_eval.paths(frozenset(), config.explain_paths),
        plans=planned,
        pareto_front=_budget_curve(global_front, baseline.risk, actions),
        diagnostics=diagnostics,
    )


# --------------------------------------------------------------------------- #
# Steps
# --------------------------------------------------------------------------- #


def _drop_dominated(effects: list[ActionEffect]) -> list[ActionEffect]:
    """Remove actions covered by another action that is no more costly nor disruptive. Safe for the
    Pareto front because risk is monotone: more edge modifications never increase it."""
    ordered = sorted(effects, key=lambda e: (e.cost, e.impact, -len(e.edges), e.action_id))
    kept: list[ActionEffect] = []
    for effect in ordered:
        if any(k.cost <= effect.cost and k.impact <= effect.impact + _EPS and k.covers(effect) for k in kept):
            continue
        kept.append(effect)
    return sorted(kept, key=lambda e: e.index)


def _combine(fronts: list[list[Candidate]], budget: int | None, max_points: int) -> tuple[list[Candidate], bool]:
    """Multi-choice knapsack over component fronts (one option per component), keeping the
    non-dominated (risk, cost, impact) partial sums. Back-pointers avoid building action sets until
    the end."""
    layers: list[list[_Partial]] = [[_Partial(0.0, 0, 0.0, (-1, -1))]]
    truncated = False
    order = sorted(range(len(fronts)), key=lambda i: len(fronts[i]))
    for comp in order:
        front = fronts[comp]
        merged: list[_Partial] = []
        for pi, p in enumerate(layers[-1]):
            for qi, q in enumerate(front):
                cost = p.cost + q.cost
                if budget is not None and cost > budget:
                    continue
                merged.append(_Partial(p.risk + q.risk, cost, p.impact + q.impact, (pi, qi)))
        layer = pareto_filter(merged, tiebreak=lambda c: c.back)
        if len(layer) > max_points:
            layer = _thin(layer, max_points)
            truncated = True
        layers.append(layer)

    result: list[Candidate] = []
    for final in layers[-1]:
        selection: set[int] = set()
        node, depth = final, len(layers) - 1
        while depth > 0:
            prev, choice = node.back
            selection |= fronts[order[depth - 1]][choice].selection
            node, depth = layers[depth - 1][prev], depth - 1
        result.append(Candidate(frozenset(selection), final.risk, final.cost, final.impact))
    return result, truncated


def _thin(layer: list[_Partial], max_points: int) -> list[_Partial]:
    """Keep, per cost bucket, the lowest-risk and lowest-impact points plus a few spread by risk."""
    costs = sorted({p.cost for p in layer})
    width = max(1, -(-2 * len(costs) // max_points))  # ceil: at most max_points / 2 buckets
    bucket_of = {cost: i // width for i, cost in enumerate(costs)}
    buckets: dict[int, list[_Partial]] = {}
    for p in layer:
        buckets.setdefault(bucket_of[p.cost], []).append(p)
    per_bucket = max(2, max_points // len(buckets))
    kept: list[_Partial] = []
    for points in buckets.values():
        by_risk = sorted(points, key=lambda p: (p.risk, p.impact))
        picks = {0, min(range(len(by_risk)), key=lambda i: (by_risk[i].impact, by_risk[i].risk))}
        step = max(1, len(by_risk) // per_bucket)
        picks.update(range(0, len(by_risk), step))
        kept.extend(by_risk[i] for i in sorted(picks)[:per_bucket])
    return pareto_filter(kept, tiebreak=lambda c: c.back)


def _select_plans(front: list[Candidate], baseline_risk: float, max_plans: int) -> list[tuple[str, Candidate]]:
    useful = [c for c in front if baseline_risk - c.risk > _EPS * max(1.0, baseline_risk)]
    if not useful or max_plans <= 0:
        return []
    best = min(useful, key=lambda c: (c.risk, c.cost, c.impact))
    best_reduction = baseline_risk - best.risk

    def reduction(c: Candidate) -> float:
        return baseline_risk - c.risk

    picks: list[tuple[str, Candidate]] = [("max_reduction", best)]
    max_cost = max(best.cost, 1)
    knee = max(useful, key=lambda c: (reduction(c) / best_reduction - c.cost / max_cost, -c.cost, -c.impact))
    picks.append(("balanced", knee))
    low = [c for c in useful if reduction(c) >= 0.8 * best_reduction - _EPS]
    picks.append(("low_disruption", min(low, key=lambda c: (c.impact, c.cost, c.risk))))
    quick = [c for c in useful if reduction(c) >= 0.5 * best_reduction - _EPS]
    picks.append(("quick_win", min(quick, key=lambda c: (c.cost, c.risk, c.impact))))
    for cand in sorted(useful, key=lambda c: (-(reduction(c) / (c.cost + 1)), c.risk)):
        picks.append(("alternative", cand))

    chosen: list[tuple[str, Candidate]] = []
    seen: set[frozenset[int]] = set()
    for strategy, cand in picks:
        if cand.selection in seen:
            continue
        seen.add(cand.selection)
        chosen.append((strategy, cand))
        if len(chosen) >= max_plans:
            break
    return chosen


def _describe(
    plan_eval: _Plan,
    cand: Candidate,
    strategy: str,
    baseline: Evaluation,
    effects: dict[int, ActionEffect],
    actions: Sequence[RemediationAction],
    config: PlannerConfig,
) -> PlannedRemediation:
    """Order the plan's actions greedily by marginal risk reduction per unit of cost: the sequence a
    team should apply them in so that every step buys the most risk reduction available."""
    # Risk is additive over components, so an action's marginal gain only changes when another action
    # of its own component is applied: gains are recomputed for that component alone.
    def marginal(idx: int, applied: frozenset[int]) -> float:
        comp = plan_eval.component_of[idx]
        return plan_eval.component_risk(comp, applied) - plan_eval.component_risk(comp, applied | {idx})

    applied: frozenset[int] = frozenset()
    gains = {idx: marginal(idx, applied) for idx in cand.selection}
    risk = baseline.risk
    steps: list[PlanStep] = []
    while gains:
        idx = min(gains, key=lambda i: (-gains[i] / (effects[i].cost + 1e-6), effects[i].impact, actions[i].action_id))
        gain = gains.pop(idx)
        applied = applied | {idx}
        comp = plan_eval.component_of[idx]
        for other in gains:
            if plan_eval.component_of[other] is comp:
                gains[other] = marginal(other, applied)
        action = actions[idx]
        risk -= gain
        steps.append(
            PlanStep(
                action_id=action.action_id,
                title=action.title,
                cost=int(action.cost),
                impact=float(action.impact),
                risk_after=round(max(risk, 0.0), 6),
                risk_reduction=round(gain, 6),
            )
        )
    final = plan_eval.evaluate(cand.selection)
    return PlannedRemediation(
        strategy=strategy,
        selected_actions=[s.action_id for s in steps],
        steps=steps,
        cost=cand.cost,
        operational_impact=round(cand.impact, 6),
        risk_before=round(baseline.risk, 6),
        risk_after=round(final.risk, 6),
        risk_reduction_ratio=round((baseline.risk - final.risk) / baseline.risk, 6) if baseline.risk > _EPS else 0.0,
        exposures_before=baseline.exposures,
        exposures_after=final.exposures,
        jewels_exposed_after=final.jewels_exposed,
        residual_paths=plan_eval.paths(cand.selection, config.explain_paths),
    )


def _budget_curve(front: list[Candidate], baseline_risk: float, actions: Sequence[RemediationAction]) -> list[FrontPoint]:
    """Lowest achievable risk per cost level (the cost/risk projection of the Pareto front)."""
    curve: list[FrontPoint] = []
    best_risk = float("inf")
    for cand in sorted(front, key=lambda c: (c.cost, c.risk, c.impact)):
        if cand.risk < best_risk - _EPS:
            best_risk = cand.risk
            curve.append(
                FrontPoint(
                    cost=cand.cost,
                    operational_impact=round(cand.impact, 6),
                    risk_after=round(cand.risk, 6),
                    risk_reduction_ratio=round((baseline_risk - cand.risk) / baseline_risk, 6) if baseline_risk > _EPS else 0.0,
                    selected_actions=sorted(actions[i].action_id for i in cand.selection),
                )
            )
    return curve
