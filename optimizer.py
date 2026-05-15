from __future__ import annotations

import itertools
import math
import random
from dataclasses import dataclass
from typing import Sequence

from app.domain.analysis_models import PlanEvaluation, RemediationAction
from app.engine.path_analysis import find_attack_paths
from app.engine.remediation import apply_actions


@dataclass(slots=True)
class _Individual:
    genome: list[int]
    evaluation: PlanEvaluation


EXACT_SEARCH_LIMIT = 14


def _evaluate(
    genome: Sequence[int],
    graph,
    actions: Sequence[RemediationAction],
    baseline_paths: int,
    max_paths: int,
    budget: int | None,
) -> PlanEvaluation:
    selected_actions = [action.action_id for bit, action in zip(genome, actions) if bit]
    total_cost = sum(action.cost for bit, action in zip(genome, actions) if bit)
    total_impact = sum(action.impact for bit, action in zip(genome, actions) if bit)

    if budget is not None and total_cost > budget:
        return PlanEvaluation(
            selected_actions=selected_actions,
            remaining_paths=baseline_paths + (total_cost - budget),
            reduced_paths=0,
            cost=total_cost,
            operational_impact=total_impact + 10,
            coverage_ratio=0.0,
        )

    remediated_graph = apply_actions(graph, list(actions), selected_actions)
    remaining_paths = len(find_attack_paths(remediated_graph, max_paths=max_paths))
    reduced_paths = max(0, baseline_paths - remaining_paths)
    coverage = (reduced_paths / baseline_paths) if baseline_paths else 0.0
    return PlanEvaluation(
        selected_actions=selected_actions,
        remaining_paths=remaining_paths,
        reduced_paths=reduced_paths,
        cost=total_cost,
        operational_impact=total_impact,
        coverage_ratio=coverage,
    )


def _seed_population(population_size: int, genome_length: int) -> list[list[int]]:
    seeds: list[list[int]] = [[0] * genome_length]
    for index in range(genome_length):
        genome = [0] * genome_length
        genome[index] = 1
        seeds.append(genome)
    while len(seeds) < population_size:
        seeds.append([random.randint(0, 1) for _ in range(genome_length)])
    return seeds[:population_size]


def _dominates(a: PlanEvaluation, b: PlanEvaluation) -> bool:
    better_or_equal = a.remaining_paths <= b.remaining_paths and a.cost <= b.cost and a.operational_impact <= b.operational_impact
    strictly_better = a.remaining_paths < b.remaining_paths or a.cost < b.cost or a.operational_impact < b.operational_impact
    return better_or_equal and strictly_better


def _non_dominated_sort(population: list[_Individual]) -> list[list[_Individual]]:
    fronts: list[list[_Individual]] = []
    domination_counts = {}
    dominated_sets = {}
    first_front: list[_Individual] = []

    for p in population:
        dominated_sets[id(p)] = []
        domination_counts[id(p)] = 0
        for q in population:
            if p is q:
                continue
            if _dominates(p.evaluation, q.evaluation):
                dominated_sets[id(p)].append(q)
            elif _dominates(q.evaluation, p.evaluation):
                domination_counts[id(p)] += 1
        if domination_counts[id(p)] == 0:
            p.evaluation.rank = 0
            first_front.append(p)

    fronts.append(first_front)
    index = 0
    while index < len(fronts) and fronts[index]:
        next_front: list[_Individual] = []
        for p in fronts[index]:
            for q in dominated_sets[id(p)]:
                domination_counts[id(q)] -= 1
                if domination_counts[id(q)] == 0:
                    q.evaluation.rank = index + 1
                    next_front.append(q)
        if next_front:
            fronts.append(next_front)
        index += 1
    return fronts


def _crowding_distance(front: list[_Individual]) -> None:
    if not front:
        return
    for individual in front:
        individual.evaluation.crowding_distance = 0.0

    metrics = ["remaining_paths", "cost", "operational_impact"]
    for metric in metrics:
        front.sort(key=lambda ind: getattr(ind.evaluation, metric))
        front[0].evaluation.crowding_distance = math.inf
        front[-1].evaluation.crowding_distance = math.inf
        min_value = getattr(front[0].evaluation, metric)
        max_value = getattr(front[-1].evaluation, metric)
        if max_value == min_value:
            continue
        for i in range(1, len(front) - 1):
            prev_value = getattr(front[i - 1].evaluation, metric)
            next_value = getattr(front[i + 1].evaluation, metric)
            front[i].evaluation.crowding_distance += (next_value - prev_value) / (max_value - min_value)


def _tournament(population: list[_Individual]) -> _Individual:
    a, b = random.sample(population, 2)
    if a.evaluation.rank < b.evaluation.rank:
        return a
    if b.evaluation.rank < a.evaluation.rank:
        return b
    return a if a.evaluation.crowding_distance >= b.evaluation.crowding_distance else b


def _crossover(a: Sequence[int], b: Sequence[int], probability: float) -> tuple[list[int], list[int]]:
    if len(a) < 2 or random.random() > probability:
        return list(a), list(b)
    point = random.randint(1, len(a) - 1)
    return list(a[:point] + b[point:]), list(b[:point] + a[point:])


def _mutate(genome: list[int], probability: float) -> list[int]:
    clone = genome[:]
    for i in range(len(clone)):
        if random.random() < probability:
            clone[i] = 0 if clone[i] else 1
    return clone


def _finalize(population: list[_Individual], budget: int | None) -> list[PlanEvaluation]:
    feasible_population = [individual for individual in population if budget is None or individual.evaluation.cost <= budget]
    source = feasible_population or population
    final_fronts = _non_dominated_sort(source)
    for front in final_fronts:
        _crowding_distance(front)
    best_front = sorted(
        final_fronts[0],
        key=lambda ind: (
            ind.evaluation.remaining_paths,
            ind.evaluation.cost,
            ind.evaluation.operational_impact,
            -ind.evaluation.coverage_ratio,
            len(ind.evaluation.selected_actions),
        ),
    )

    unique = []
    seen = set()
    for individual in best_front:
        key = tuple(sorted(individual.evaluation.selected_actions))
        if key not in seen:
            seen.add(key)
            unique.append(individual.evaluation)
    return unique[:5]


def _exact_search(
    graph,
    actions: Sequence[RemediationAction],
    baseline_paths: int,
    max_paths: int,
    budget: int | None,
) -> list[PlanEvaluation]:
    population: list[_Individual] = []
    for bits in itertools.product((0, 1), repeat=len(actions)):
        if budget is not None:
            total_cost = sum(action.cost for bit, action in zip(bits, actions) if bit)
            if total_cost > budget:
                continue
        evaluation = _evaluate(bits, graph, actions, baseline_paths, max_paths, budget)
        population.append(_Individual(genome=list(bits), evaluation=evaluation))
    if not population:
        population.append(_Individual(genome=[0] * len(actions), evaluation=_evaluate([0] * len(actions), graph, actions, baseline_paths, max_paths, budget)))
    return _finalize(population, budget)


def optimize_actions(
    graph,
    actions: Sequence[RemediationAction],
    max_paths: int,
    budget: int | None = None,
    population_size: int = 40,
    generations: int = 25,
    seed: int = 7,
) -> list[PlanEvaluation]:
    random.seed(seed)
    baseline_paths = len(find_attack_paths(graph, max_paths=max_paths))
    if not actions:
        return [PlanEvaluation([], baseline_paths, 0, 0, 0, 0.0)]

    genome_length = len(actions)
    if genome_length <= EXACT_SEARCH_LIMIT:
        return _exact_search(graph, actions, baseline_paths, max_paths, budget)

    population: list[_Individual] = []
    for genome in _seed_population(population_size, genome_length):
        evaluation = _evaluate(genome, graph, actions, baseline_paths, max_paths, budget)
        population.append(_Individual(genome=genome, evaluation=evaluation))

    for _ in range(generations):
        fronts = _non_dominated_sort(population)
        for front in fronts:
            _crowding_distance(front)

        offspring: list[_Individual] = []
        while len(offspring) < population_size:
            parent_a = _tournament(population)
            parent_b = _tournament(population)
            child_a, child_b = _crossover(parent_a.genome, parent_b.genome, probability=0.85)
            child_a = _mutate(child_a, probability=max(0.05, 1 / genome_length))
            child_b = _mutate(child_b, probability=max(0.05, 1 / genome_length))
            offspring.append(_Individual(child_a, _evaluate(child_a, graph, actions, baseline_paths, max_paths, budget)))
            if len(offspring) < population_size:
                offspring.append(_Individual(child_b, _evaluate(child_b, graph, actions, baseline_paths, max_paths, budget)))

        combined = population + offspring
        new_population: list[_Individual] = []
        fronts = _non_dominated_sort(combined)
        for front in fronts:
            _crowding_distance(front)
            ordered = sorted(front, key=lambda ind: (ind.evaluation.rank, -ind.evaluation.crowding_distance))
            if len(new_population) + len(ordered) <= population_size:
                new_population.extend(ordered)
            else:
                remaining = population_size - len(new_population)
                new_population.extend(ordered[:remaining])
                break
        population = new_population

    return _finalize(population, budget)
