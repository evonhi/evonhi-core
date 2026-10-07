"""Exact residual-risk evaluation over a compiled attack surface.

Two evaluation strategies, chosen by the surface:

* **Static edge costs** (no capability grants — Kubernetes today): one reverse Dijkstra per crown
  jewel gives the cheapest effort from every entry. Removing edges or raising their cost can only
  lengthen paths, so a jewel whose baseline shortest-path DAG does not contain any modified edge
  keeps its baseline distances exactly; it is skipped instead of recomputed.
* **Stateful edge costs** (guards that grant capabilities — AWS): forward label-setting search per
  entry over ``(node, capabilities)`` with dominance pruning (a label is discarded when another label
  at the same node is no more expensive and holds a superset of capabilities).

Results are cached per selection, so search algorithms can re-query freely.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass
from typing import Iterable, Mapping

from evonhi_core.graph.contract import Capability
from evonhi_core.models import AttackPath
from evonhi_core.planning.model import requirement_effort
from evonhi_core.planning.surface import ActionEffect, AttackSurface

_EPS = 1e-9


@dataclass(frozen=True, slots=True)
class Evaluation:
    risk: float
    exposures: int
    jewels_exposed: int


class Modifications:
    """Merged edge changes of a set of actions."""

    __slots__ = ("removed", "required", "effort", "edges")

    def __init__(self, effects: Iterable[ActionEffect]) -> None:
        self.removed: set[int] = set()
        self.required: dict[int, set[Capability]] = {}
        self.effort: dict[int, float] = {}
        for effect in effects:
            self.removed |= effect.removed
            for eid, cap in effect.added_required:
                self.required.setdefault(eid, set()).add(cap)
            for eid, extra in effect.added_effort:
                self.effort[eid] = self.effort.get(eid, 0.0) + extra
        self.edges: set[int] = self.removed | set(self.required) | set(self.effort)


_NO_MODS = Modifications(())


class ComponentEvaluator:
    """Risk of one independent component (its jewels, entries and actions) under any selection."""

    def __init__(
        self,
        surface: AttackSurface,
        jewels: list[int],
        entries: list[int],
        effects: Mapping[int, ActionEffect],
    ) -> None:
        self.surface = surface
        self.jewels = jewels
        self.entries = entries
        self.effects = effects
        self.model = surface.risk_model
        self.evaluations = 0
        self._cache: dict[frozenset[int], Evaluation] = {}
        # A "unit" is a jewel (static costs: reverse search per jewel) or an entry (stateful costs:
        # forward search per entry). A unit's result only depends on the selected actions that touch
        # its search region, so it is cached under that restriction of the selection: the same
        # per-unit result is reused by every selection that agrees on the unit's own actions.
        units = entries if surface.stateful else jewels
        region_edges = {u: self._region(u) for u in units}
        edge_units: dict[int, list[int]] = {}
        for unit, edges in region_edges.items():
            for eid in edges:
                edge_units.setdefault(eid, []).append(unit)
        unit_actions: dict[int, set[int]] = {u: set() for u in units}
        self._action_units: dict[int, tuple[int, ...]] = {}
        for idx, effect in effects.items():
            touched = sorted({u for eid in effect.edges for u in edge_units.get(eid, ())})
            self._action_units[idx] = tuple(touched)
            for unit in touched:
                unit_actions[unit].add(idx)
        self._unit_actions = {u: frozenset(a) for u, a in unit_actions.items()}
        self._unit_cache: dict[tuple[int, frozenset[int]], tuple] = {}
        self._baseline_unit = {u: self._compute_unit(u, _NO_MODS) for u in units}
        self.baseline = self._full_evaluation({u: self._baseline_unit[u] for u in units})
        self._cache[frozenset()] = self.baseline

    # ------------------------------------------------------------------ public

    def evaluate(self, selection: frozenset[int]) -> Evaluation:
        cached = self._cache.get(selection)
        if cached is not None:
            return cached
        self.evaluations += 1
        affected: set[int] = set()
        for idx in selection:
            affected.update(self._action_units[idx])
        if self.surface.stateful:
            states = {u: self._unit_state(u, selection) for u in self.entries}
            result = self._full_evaluation(states)
        else:
            base = self.baseline
            risk, exposures, jewels_exposed = base.risk, base.exposures, base.jewels_exposed
            for jewel in affected:
                p, n, _tight = self._unit_state(jewel, selection)
                p0, n0, _ = self._baseline_unit[jewel]
                risk += self.surface.jewel_criticality[jewel] * (p - p0)
                exposures += n - n0
                jewels_exposed += (n > 0) - (n0 > 0)
            result = Evaluation(risk=max(risk, 0.0), exposures=exposures, jewels_exposed=jewels_exposed)
        self._cache[selection] = result
        return result

    def jewel_probabilities(self, selection: frozenset[int]) -> dict[int, float]:
        if self.surface.stateful:
            states = {u: self._unit_state(u, selection) for u in self.entries}
            return {j: p for j, (p, _n) in self._combine_entries(states).items()}
        return {j: self._unit_state(j, selection)[0] for j in self.jewels}

    def tight_edges(self, selection: frozenset[int]) -> set[int] | None:
        """Edges on some current cheapest attack route. An action touching none of them cannot
        reduce risk by itself from this selection. ``None`` when the surface is stateful."""
        if self.surface.stateful:
            return None
        tight: set[int] = set()
        for jewel in self.jewels:
            tight |= self._unit_state(jewel, selection)[2]
        return tight

    # ------------------------------------------------------------- unit states

    def region_edges(self, jewel: int) -> set[int]:
        """Edges that can lead to ``jewel`` (backward-reachable), regardless of the evaluation mode."""
        return self._region(jewel, self.surface.in_adj)

    def _region(self, unit: int, adjacency: list | None = None) -> set[int]:
        """Edges a unit's search can traverse: backward from a jewel, forward from an entry."""
        if adjacency is None:
            adjacency = self.surface.out_adj if self.surface.stateful else self.surface.in_adj
        seen, stack, edges = {unit}, [unit], set()
        while stack:
            node = stack.pop()
            for nxt, eid in adjacency[node]:
                edges.add(eid)
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return edges

    def _unit_state(self, unit: int, selection: frozenset[int]) -> tuple:
        key = selection & self._unit_actions[unit]
        if not key:
            return self._baseline_unit[unit]
        cache_key = (unit, key)
        state = self._unit_cache.get(cache_key)
        if state is None:
            mods = Modifications(self.effects[i] for i in key)
            baseline = self._baseline_unit[unit]
            if not self.surface.stateful and not (mods.edges & baseline[2]):
                state = baseline  # no modified edge lies on this jewel's cheapest routes
            else:
                state = self._compute_unit(unit, mods)
            self._unit_cache[cache_key] = state
        return state

    def _compute_unit(self, unit: int, mods: "Modifications") -> tuple:
        if self.surface.stateful:
            best, _labels = self._forward_labels(unit, mods)
            return ({j: effort for j, (effort, _label) in best.items()},)
        dist, _nxt, tight = self._reverse_dijkstra(unit, mods)
        probability, reached = self._jewel_probability(dist)
        return probability, reached, frozenset(tight)

    def _combine_entries(self, states: Mapping[int, tuple]) -> dict[int, tuple[float, int]]:
        survive = {j: 1.0 for j in self.jewels}
        reached = {j: 0 for j in self.jewels}
        for entry, (efforts,) in states.items():
            weight = self.surface.entry_weight[entry]
            for jewel, effort in efforts.items():
                survive[jewel] *= 1.0 - weight * math.exp(-effort / self.model.effort_scale)
                reached[jewel] += 1
        return {j: (1.0 - survive[j], reached[j]) for j in self.jewels}

    def _full_evaluation(self, states: Mapping[int, tuple]) -> Evaluation:
        per_jewel = (
            self._combine_entries(states)
            if self.surface.stateful
            else {j: (state[0], state[1]) for j, state in states.items()}
        )
        return Evaluation(
            risk=sum(self.surface.jewel_criticality[j] * p for j, (p, _) in per_jewel.items()),
            exposures=sum(n for _, n in per_jewel.values()),
            jewels_exposed=sum(1 for _, n in per_jewel.values() if n),
        )

    def paths(self, selection: frozenset[int], limit: int) -> list[tuple[float, AttackPath]]:
        """Cheapest route of every exposed (entry, jewel) pair, ranked by risk contribution."""
        mods = Modifications(self.effects[i] for i in selection)
        found: list[tuple[float, list[int], float]] = []  # (contribution, edge ids, effort)
        if self.surface.stateful:
            for entry in self.entries:
                best, labels = self._forward_labels(entry, mods)
                for jewel, (effort, label) in best.items():
                    edges: list[int] = []
                    while labels[label][3] >= 0:
                        edges.append(labels[label][4])
                        label = labels[label][3]
                    found.append((self._contribution(entry, jewel, effort), edges[::-1], effort))
        else:
            for jewel in self.jewels:
                dist, nxt, _tight = self._reverse_dijkstra(jewel, mods)
                for entry in self.entries:
                    if entry not in dist or entry == jewel:
                        continue
                    edges, node = [], entry
                    while node != jewel:
                        eid = nxt[node]
                        edges.append(eid)
                        node = self.surface.edge_dst[eid]
                    found.append((self._contribution(entry, jewel, dist[entry]), edges, dist[entry]))
        found.sort(key=lambda item: (-item[0], len(item[1]), item[1]))
        return [(score, self._as_attack_path(edges, score, effort)) for score, edges, effort in found[:limit]]

    # ----------------------------------------------------------------- helpers

    def _edge_cost(self, eid: int, mods: Modifications, held: frozenset[Capability] = frozenset()) -> float:
        surface = self.surface
        required = surface.edge_required[eid]
        extra_req = mods.required.get(eid)
        if extra_req:
            required = required | extra_req
        unmet = required - held if held else required
        return surface.edge_base[eid] + mods.effort.get(eid, 0.0) + requirement_effort(self.model, unmet)

    def _reverse_dijkstra(self, jewel: int, mods: Modifications) -> tuple[dict[int, float], dict[int, int], set[int]]:
        surface = self.surface
        cutoff = self.model.max_effort
        baseline = surface.baseline_effort
        removed, touched = mods.removed, mods.edges
        dist: dict[int, float] = {jewel: 0.0}
        nxt: dict[int, int] = {}
        done: set[int] = set()
        relaxed: list[tuple[int, int, float]] = []
        heap: list[tuple[float, int]] = [(0.0, jewel)]
        while heap:
            d, v = heapq.heappop(heap)
            if v in done:
                continue
            done.add(v)
            for u, eid in surface.in_adj[v]:
                if eid in removed:
                    continue
                nd = d + (self._edge_cost(eid, mods) if eid in touched else baseline[eid])
                if nd > cutoff:
                    continue
                relaxed.append((u, eid, nd))
                if nd < dist.get(u, math.inf) - 1e-12:
                    dist[u] = nd
                    nxt[u] = eid
                    heapq.heappush(heap, (nd, u))
        tight = {eid for u, eid, nd in relaxed if abs(dist[u] - nd) <= _EPS}
        return dist, nxt, tight

    def _forward_labels(
        self, entry: int, mods: Modifications
    ) -> tuple[dict[int, tuple[float, int]], list[tuple[int, float, frozenset[Capability], int, int]]]:
        """Label-setting search from one entry. Returns, per reached jewel, the cheapest effort and the
        label to trace back; labels are ``(node, effort, caps, parent_label, edge)``."""
        surface = self.surface
        cutoff = self.model.max_effort
        jewels = set(self.jewels)
        labels: list[tuple[int, float, frozenset[Capability], int, int]] = [(entry, 0.0, frozenset(), -1, -1)]
        settled: dict[int, list[tuple[float, frozenset[Capability]]]] = {}
        best: dict[int, tuple[float, int]] = {}
        heap: list[tuple[float, int]] = [(0.0, 0)]
        while heap:
            d, label_id = heapq.heappop(heap)
            node, _d, caps, _parent, _edge = labels[label_id]
            seen = settled.setdefault(node, [])
            if any(sd <= d + _EPS and caps <= sc for sd, sc in seen):
                continue
            seen.append((d, caps))
            if node in jewels and node != entry and (node not in best or d < best[node][0]):
                best[node] = (d, label_id)
            for succ, eid in surface.out_adj[node]:
                if eid in mods.removed:
                    continue
                nd = d + self._edge_cost(eid, mods, caps)
                if nd > cutoff:
                    continue
                new_caps = caps | surface.edge_grants[eid] if surface.edge_grants[eid] else caps
                if any(sd <= nd + _EPS and new_caps <= sc for sd, sc in settled.get(succ, ())):
                    continue
                labels.append((succ, nd, new_caps, label_id, eid))
                heapq.heappush(heap, (nd, len(labels) - 1))
        return best, labels

    def _jewel_probability(self, dist: Mapping[int, float]) -> tuple[float, int]:
        survive, reached = 1.0, 0
        for entry in self.entries:
            effort = dist.get(entry)
            if effort is None:
                continue
            reached += 1
            survive *= 1.0 - self.surface.entry_weight[entry] * math.exp(-effort / self.model.effort_scale)
        return 1.0 - survive, reached

    def _contribution(self, entry: int, jewel: int, effort: float) -> float:
        likelihood = self.surface.entry_weight[entry] * math.exp(-effort / self.model.effort_scale)
        return self.surface.jewel_criticality[jewel] * likelihood

    def _as_attack_path(self, edges: list[int], score: float, effort: float) -> AttackPath:
        surface = self.surface
        names = surface.node_names
        nodes = [names[surface.edge_src[edges[0]]]] + [names[surface.edge_dst[e]] for e in edges]
        graph = surface.graph
        source, target = graph.nodes[nodes[0]], graph.nodes[nodes[-1]]
        headline = (
            f"Public {source.get('kind', 'entry')} {source.get('name', nodes[0])} can reach "
            f"{target.get('kind', 'asset')} {target.get('name', nodes[-1])} (attacker effort {effort:.1f})"
        )
        return AttackPath(
            nodes=nodes,
            score=round(score, 6),
            relations=[surface.edge_relation[e] for e in edges],
            headline=headline,
        )
