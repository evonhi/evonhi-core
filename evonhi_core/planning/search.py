"""Per-component multi-objective search: exact enumeration or a memetic NSGA-II.

Objectives (all minimized): residual risk, cost, operational impact. The budget is a hard
constraint handled by *repair* (dropping the least valuable actions), so every individual is
feasible — unlike the v1 optimizer, whose dense random initialization produced almost only
over-budget genomes that a penalty then discarded.

The evolutionary search is seeded with strong constructive solutions (greedy ladders under several
cost/impact trade-offs, a global minimum cut and per-jewel minimum cuts), keeps an elitist archive
of every non-dominated plan it ever sees, and applies redundancy elimination as a local search so
no returned plan contains an action that does not pull its weight.
"""

from __future__ import annotations

import bisect
import itertools
import math
import random
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

import networkx as nx

from evonhi_core.planning.model import PlannerConfig
from evonhi_core.planning.risk import ComponentEvaluator
from evonhi_core.planning.surface import ActionEffect

_EPS = 1e-9


@dataclass(frozen=True, slots=True)
class Candidate:
    selection: frozenset[int]
    risk: float
    cost: int
    impact: float

    def dominates(self, other: "Candidate") -> bool:
        no_worse = self.risk <= other.risk + _EPS and self.cost <= other.cost and self.impact <= other.impact + _EPS
        better = self.risk < other.risk - _EPS or self.cost < other.cost or self.impact < other.impact - _EPS
        return no_worse and better


def pareto_filter(points: Iterable[Candidate], tiebreak: Callable | None = None) -> list:
    """Non-dominated subset in O(n log n): sweep by cost and keep a (risk, impact) staircase.

    Works on any objects exposing ``risk``, ``cost`` and ``impact``; ``tiebreak`` orders exact ties
    (default: fewer actions first, then action ids)."""
    tiebreak = tiebreak or (lambda c: (len(c.selection), sorted(c.selection)))
    ordered = sorted(points, key=lambda c: (c.cost, c.risk, c.impact, tiebreak(c)))
    stair_risk: list[float] = []  # ascending risk
    stair_impact: list[float] = []  # descending impact (non-dominated in 2D)
    kept: list[Candidate] = []
    for cand in ordered:
        pos = bisect.bisect_right(stair_risk, cand.risk + _EPS)
        if pos and stair_impact[pos - 1] <= cand.impact + _EPS:
            continue  # an earlier (cheaper or equal cost) point is no worse in risk and impact
        kept.append(cand)
        insert = bisect.bisect_left(stair_risk, cand.risk)
        end = insert
        while end < len(stair_risk) and stair_impact[end] >= cand.impact - _EPS:
            end += 1
        stair_risk[insert:end] = [cand.risk]
        stair_impact[insert:end] = [cand.impact]
    return kept


class ComponentSearch:
    def __init__(
        self,
        evaluator: ComponentEvaluator,
        effects: Sequence[ActionEffect],
        budget: int | None,
        config: PlannerConfig,
        rng: random.Random,
    ) -> None:
        self.evaluator = evaluator
        self.effects = {e.index: e for e in effects}
        self.actions = sorted(self.effects)
        self.budget = budget
        self.config = config
        self.rng = rng
        self.exact = False

    # ------------------------------------------------------------------ helpers

    def candidate(self, selection: frozenset[int]) -> Candidate:
        effects = self.effects
        return Candidate(
            selection=selection,
            risk=self.evaluator.evaluate(selection).risk,
            cost=sum(effects[i].cost for i in selection),
            impact=sum(effects[i].impact for i in selection),
        )

    def _cost(self, selection: Iterable[int]) -> int:
        return sum(self.effects[i].cost for i in selection)

    def _affordable(self, cost: int) -> bool:
        return self.budget is None or cost <= self.budget

    # --------------------------------------------------------------- strategies

    def run(self) -> list[Candidate]:
        if not self.actions:
            return [self.candidate(frozenset())]
        if len(self.actions) <= self.config.exact_action_limit or self._feasible_subsets() <= self.config.exact_subset_limit:
            self.exact = True
            return self._exact()
        return self._memetic()

    def _feasible_subsets(self) -> int:
        """Number of action subsets within budget (0/1 knapsack counting DP), capped early."""
        limit = self.config.exact_subset_limit
        if self.budget is None:
            return 2 ** len(self.actions) if len(self.actions) < 64 else limit + 1
        ways = [0] * (self.budget + 1)
        ways[0] = 1
        for idx in self.actions:
            cost = max(self.effects[idx].cost, 0)
            for spent in range(self.budget, cost - 1, -1):
                ways[spent] = min(ways[spent] + ways[spent - cost], limit + 1)  # cost 0 doubles, as it should
        return min(sum(ways), limit + 1)

    def _exact(self) -> list[Candidate]:
        """All budget-feasible subsets (depth-first with cost pruning)."""
        found: list[Candidate] = []
        actions = sorted(self.actions, key=lambda i: self.effects[i].cost)

        def walk(start: int, chosen: list[int], cost: int) -> None:
            found.append(self.candidate(frozenset(chosen)))
            for pos in range(start, len(actions)):
                idx = actions[pos]
                new_cost = cost + self.effects[idx].cost
                if not self._affordable(new_cost):
                    break  # actions are sorted by cost: every later one is at least as expensive
                chosen.append(idx)
                walk(pos + 1, chosen, new_cost)
                chosen.pop()

        walk(0, [], 0)
        return pareto_filter(found)

    def greedy_ladder(self, impact_weight: float = 0.0, start: frozenset[int] = frozenset()) -> list[frozenset[int]]:
        """Repeatedly add the action with the best marginal risk reduction per (cost + w*impact).
        Returns every prefix, i.e. one plan per budget level. Only actions touching an edge on a
        current cheapest attack route are considered — any other has zero marginal effect."""
        selection = start
        cost = self._cost(selection)
        risk = self.evaluator.evaluate(selection).risk
        ladder = [selection]
        while True:
            tight = self.evaluator.tight_edges(selection)
            best: tuple[float, int, float] | None = None
            for idx in self.actions:
                if idx in selection:
                    continue
                effect = self.effects[idx]
                if not self._affordable(cost + effect.cost):
                    continue
                if tight is not None and not (effect.edges & tight):
                    continue
                gain = risk - self.evaluator.evaluate(selection | {idx}).risk
                if gain <= _EPS:
                    continue
                score = gain / (effect.cost + impact_weight * effect.impact + 1e-6)
                if best is None or score > best[0] + _EPS:
                    best = (score, idx, gain)
            if best is None:
                return ladder
            selection = selection | {best[1]}
            cost += self.effects[best[1]].cost
            risk -= best[2]
            ladder.append(selection)

    def min_cut_seeds(self) -> list[frozenset[int]]:
        """Cheapest action sets that fully disconnect entries from (all / each) crown jewels.

        Node-removal actions become node capacities (node splitting), edge-removal actions become edge
        capacities, everything else is uncuttable. Per-jewel cuts are then accumulated in order of
        protected criticality per unit of cost, giving one seed per budget step."""
        surface = self.evaluator.surface
        removable_node: dict[int, tuple[int, int]] = {}  # node -> (cost, action)
        removable_edge: dict[int, tuple[int, int]] = {}  # edge -> (cost, action)
        for idx in self.actions:
            effect = self.effects[idx]
            if not effect.removed:
                continue
            for node in _nodes_fully_removed(surface, effect.removed):
                if node not in removable_node or effect.cost < removable_node[node][0]:
                    removable_node[node] = (effect.cost, idx)
            if len(effect.removed) == 1:
                (eid,) = effect.removed
                if eid not in removable_edge or effect.cost < removable_edge[eid][0]:
                    removable_edge[eid] = (effect.cost, idx)

        big = (sum(self.effects[i].cost for i in self.actions) + 1) * 1000 + len(self.actions) + 1
        entries = set(self.evaluator.entries)

        def cut_for(jewels: Iterable[int], edge_ids: Iterable[int]) -> tuple[int, frozenset[int]] | None:
            """Minimum cut restricted to ``edge_ids`` (the region that can reach ``jewels``)."""
            flow = nx.DiGraph()
            nodes: set[int] = set()
            for eid in edge_ids:
                u, v = surface.edge_src[eid], surface.edge_dst[eid]
                nodes.update((u, v))
                if eid in removable_edge:
                    flow.add_edge(("out", u), ("in", v), capacity=max(removable_edge[eid][0], 0) * 1000 + 1, action=removable_edge[eid][1])
                else:
                    flow.add_edge(("out", u), ("in", v), capacity=big)
            for node in nodes:
                if node in removable_node:
                    flow.add_edge(("in", node), ("out", node), capacity=max(removable_node[node][0], 0) * 1000 + 1, action=removable_node[node][1])
                else:
                    flow.add_edge(("in", node), ("out", node), capacity=big)
                if node in entries:
                    flow.add_edge("SOURCE", ("in", node), capacity=big)
            for jewel in jewels:
                if jewel in nodes:
                    flow.add_edge(("out", jewel), "SINK", capacity=big)
            if "SINK" not in flow or "SOURCE" not in flow:
                return None
            value, (reachable, _rest) = nx.minimum_cut(flow, "SOURCE", "SINK")
            if value >= big:
                return None
            chosen = {
                attrs["action"]
                for a, b, attrs in flow.edges(data=True)
                if a in reachable and b not in reachable and "action" in attrs
            }
            return self._cost(chosen), frozenset(chosen)

        regions = {jewel: self.evaluator.region_edges(jewel) for jewel in self.evaluator.jewels}
        seeds: list[frozenset[int]] = []
        full = cut_for(self.evaluator.jewels, set().union(*regions.values()))
        if full is not None and self._affordable(full[0]):
            seeds.append(full[1])
        per_jewel = []
        for jewel in self.evaluator.jewels:
            cut = cut_for([jewel], regions[jewel])
            if cut is not None:
                crit = surface.jewel_criticality[jewel]
                per_jewel.append((crit / (cut[0] + 1e-6), cut[1]))
        per_jewel.sort(key=lambda item: (-item[0], sorted(item[1])))
        accumulated: frozenset[int] = frozenset()
        for _ratio, actions in per_jewel:
            merged = accumulated | actions
            if self._affordable(self._cost(merged)):
                accumulated = merged
                seeds.append(accumulated)
        return seeds

    def repair(self, selection: frozenset[int], value: dict[int, float]) -> frozenset[int]:
        """Drop the action with the lowest standalone value per unit of cost until within budget."""
        if self.budget is None:
            return selection
        chosen = set(selection)
        cost = self._cost(chosen)
        while cost > self.budget and chosen:
            worst = min(chosen, key=lambda i: (value.get(i, 0.0) / (self.effects[i].cost + 1e-6), -self.effects[i].cost, i))
            chosen.discard(worst)
            cost -= self.effects[worst].cost
        return frozenset(chosen)

    def drop_redundant(self, selection: frozenset[int]) -> frozenset[int]:
        """Local search: remove actions whose absence does not increase risk (costliest first)."""
        risk = self.evaluator.evaluate(selection).risk
        for idx in sorted(selection, key=lambda i: (-self.effects[i].cost, -self.effects[i].impact, i)):
            reduced = selection - {idx}
            if self.evaluator.evaluate(reduced).risk <= risk + _EPS:
                selection = reduced
        return selection

    # ------------------------------------------------------------------ memetic

    def _memetic(self) -> list[Candidate]:
        config, rng = self.config, self.rng
        empty_risk = self.evaluator.evaluate(frozenset()).risk
        value = {i: max(0.0, empty_risk - self.evaluator.evaluate(frozenset({i})).risk) for i in self.actions}
        mean_value = (sum(value.values()) / len(value)) if value else 0.0
        pool_weights = [value[i] + 0.1 * mean_value + 1e-6 for i in self.actions]

        seeds: list[frozenset[int]] = [frozenset()]
        for weight in (0.0, 0.5, 2.0):
            seeds.extend(self.greedy_ladder(impact_weight=weight))
        seeds.extend(self.min_cut_seeds())
        seeds.extend(frozenset({i}) for i in self.actions if value[i] > _EPS and self._affordable(self.effects[i].cost))

        archive: dict[frozenset[int], Candidate] = {}

        def admit(cands: Iterable[Candidate]) -> bool:
            before = set(archive)
            merged = pareto_filter(list(archive.values()) + list(cands))
            merged = _truncate(merged, config.archive_size)
            archive.clear()
            archive.update((c.selection, c) for c in merged)
            return set(archive) != before

        population: list[Candidate] = []
        seen: set[frozenset[int]] = set()
        for seed in seeds:
            seed = self.repair(seed, value)
            if seed not in seen:
                seen.add(seed)
                population.append(self.candidate(seed))
        target_size = max(config.population_size, 8)
        attempts = 0
        while len(population) < target_size and attempts < target_size * 20:
            attempts += 1
            k = rng.randint(1, max(1, min(len(self.actions), 6)))
            pick = frozenset(rng.choices(self.actions, weights=pool_weights, k=k))
            pick = self.repair(pick, value)
            if pick not in seen:
                seen.add(pick)
                population.append(self.candidate(pick))
        admit(population)

        stagnant = 0
        for _generation in range(config.max_generations):
            ranks, crowding = _rank_and_crowd(population)
            order = {id(c): i for i, c in enumerate(population)}

            def tournament() -> Candidate:
                a, b = rng.sample(population, 2) if len(population) > 1 else (population[0], population[0])
                ka = (ranks[order[id(a)]], -crowding[order[id(a)]])
                kb = (ranks[order[id(b)]], -crowding[order[id(b)]])
                return a if ka <= kb else b

            offspring: list[Candidate] = []
            while len(offspring) < config.population_size:
                a, b = tournament(), tournament()
                child = set(a.selection & b.selection)
                for idx in a.selection ^ b.selection:
                    if rng.random() < 0.5:
                        child.add(idx)
                roll = rng.random()
                if roll < 0.4 or not child:
                    child.add(rng.choices(self.actions, weights=pool_weights, k=1)[0])
                elif roll < 0.7:
                    child.discard(rng.choice(sorted(child)))
                else:
                    child.discard(rng.choice(sorted(child)))
                    child.add(rng.choices(self.actions, weights=pool_weights, k=1)[0])
                selection = self.repair(frozenset(child), value)
                if rng.random() < config.local_search_rate:
                    selection = self.drop_redundant(selection)
                offspring.append(self.candidate(selection))

            population = _environmental_selection(population + offspring, config.population_size)
            stagnant = 0 if admit(offspring) else stagnant + 1
            if stagnant >= config.stagnation_generations or self.evaluator.evaluations >= config.max_evaluations:
                break

        # Final memetic polish: redundancy elimination everywhere, then spend leftover budget greedily
        # on the lowest-risk plans.
        polished = [self.candidate(self.drop_redundant(c.selection)) for c in archive.values()]
        admit(polished)
        best = sorted(archive.values(), key=lambda c: (c.risk, c.cost, c.impact))[:3]
        for cand in best:
            admit(self.candidate(s) for s in self.greedy_ladder(start=cand.selection)[1:])
        return list(archive.values())


def _nodes_fully_removed(surface, removed: frozenset[int]) -> list[int]:
    """Nodes whose every relevant incident edge is in ``removed`` (i.e. a node-removal action)."""
    touched = {surface.edge_src[e] for e in removed} | {surface.edge_dst[e] for e in removed}
    out = []
    for node in touched:
        incident = {e for _, e in surface.out_adj[node]} | {e for _, e in surface.in_adj[node]}
        if incident and incident <= removed and len(removed) > 1:
            out.append(node)
    return out


def _truncate(front: list[Candidate], size: int) -> list[Candidate]:
    if len(front) <= size:
        return front
    crowd = _crowding(front)
    extremes = {
        min(range(len(front)), key=lambda i: (front[i].risk, front[i].cost)),
        min(range(len(front)), key=lambda i: (front[i].cost, front[i].risk)),
        min(range(len(front)), key=lambda i: (front[i].impact, front[i].risk)),
    }
    ranked = sorted(range(len(front)), key=lambda i: (i not in extremes, -crowd[i], front[i].risk))
    return [front[i] for i in ranked[:size]]


def _crowding(front: Sequence[Candidate]) -> list[float]:
    n = len(front)
    distance = [0.0] * n
    for key in (lambda c: c.risk, lambda c: float(c.cost), lambda c: c.impact):
        order = sorted(range(n), key=lambda i: key(front[i]))
        lo, hi = key(front[order[0]]), key(front[order[-1]])
        distance[order[0]] = distance[order[-1]] = math.inf
        if hi - lo <= _EPS:
            continue
        for pos in range(1, n - 1):
            distance[order[pos]] += (key(front[order[pos + 1]]) - key(front[order[pos - 1]])) / (hi - lo)
    return distance


def _rank_and_crowd(population: list[Candidate]) -> tuple[list[int], list[float]]:
    n = len(population)
    ranks = [0] * n
    dominated_by = [0] * n
    dominates: list[list[int]] = [[] for _ in range(n)]
    for i, j in itertools.combinations(range(n), 2):
        if population[i].dominates(population[j]):
            dominates[i].append(j)
            dominated_by[j] += 1
        elif population[j].dominates(population[i]):
            dominates[j].append(i)
            dominated_by[i] += 1
    front = [i for i in range(n) if dominated_by[i] == 0]
    crowding = [0.0] * n
    rank = 0
    while front:
        for i, d in zip(front, _crowding([population[i] for i in front])):
            ranks[i] = rank
            crowding[i] = d
        nxt = []
        for i in front:
            for j in dominates[i]:
                dominated_by[j] -= 1
                if dominated_by[j] == 0:
                    nxt.append(j)
        front, rank = nxt, rank + 1
    return ranks, crowding


def _environmental_selection(candidates: list[Candidate], size: int) -> list[Candidate]:
    unique: dict[frozenset[int], Candidate] = {}
    for cand in candidates:
        unique.setdefault(cand.selection, cand)
    pool = list(unique.values())
    ranks, crowding = _rank_and_crowd(pool)
    order = sorted(range(len(pool)), key=lambda i: (ranks[i], -crowding[i], pool[i].risk, pool[i].cost))
    return [pool[i] for i in order[:size]]


SearchFactory = Callable[[ComponentEvaluator, Sequence[ActionEffect]], ComponentSearch]
