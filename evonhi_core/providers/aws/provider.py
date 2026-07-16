"""AwsProvider (Fase 5, multi-cloud refactor).

Materializes the four engines: the action/resource index, SCP-aware resolution,
backward-reachability from the crown jewels, and construction through CanonicalGraph so every
permission edge is a resolved effective permission (raw permissions are structurally rejected).

Unlike KubernetesProvider (which emits a raw nx.DiGraph to protect the golden), AwsProvider
builds through ``CanonicalGraph.add_permission_edge`` — AWS has no golden to protect, so the
guard/weight edge attributes are the desired behavior. build_graph still returns the underlying
nx.DiGraph so the unchanged traversal/optimizer consume it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import networkx as nx

from evonhi_core.graph.canonical_graph import CanonicalGraph
from evonhi_core.graph.contract import EdgeRelation, Guard, NodeKind
from evonhi_core.providers.aws.index import ActionResourceIndex
from evonhi_core.providers.aws.resolver import AwsEffectivePolicyResolver
from evonhi_core.providers.aws.semantics import CAPABILITY_DOMAIN, condition_to_guard, statement_matches
from evonhi_core.resolution.base import EffectivePermission, EffectivePermissionSet

if TYPE_CHECKING:
    from evonhi_core.models import ScenarioConfig
    from evonhi_core.providers.aws.model import AwsOrganization, IamRole
    from evonhi_core.resolution.base import EffectivePolicyResolver

_PIVOT_WEIGHT = 7.0
_READ_SECRET_WEIGHT = 8.0


class AwsProvider:
    """Graph-side AWS provider. Structurally conforms to GraphProvider."""

    name: str = "aws"
    entry_node_kinds: tuple[str, ...] = ("workload",)  # NodeKind.COMPUTE -> "workload" (shared entry string)
    capability_domain = CAPABILITY_DOMAIN

    def __init__(self) -> None:
        self._resolver: AwsEffectivePolicyResolver | None = None

    def resolver(self) -> "EffectivePolicyResolver":
        # A fresh resolver is bound per build_graph (it precomputes per-org SCP chains); expose
        # the last one, or a detached instance for interface conformance.
        return self._resolver if self._resolver is not None else AwsEffectivePolicyResolver(_EMPTY_ORG)

    def _assumers(self, org: "AwsOrganization", target: "IamRole", resolver: AwsEffectivePolicyResolver) -> list[tuple[str, Guard]]:
        """Roles that can assume ``target``: allowed by target's trust AND holding an
        (undenied) sts:AssumeRole on target. The guard comes from the trust condition."""
        trust_principals: set[str] = set()
        trust_condition: dict[str, str] = {}
        for ts in target.trust_statements:
            if ts.effect != "Allow":
                continue
            trust_principals.update(ts.principals)
            trust_condition.update(ts.condition)
        result: list[tuple[str, Guard]] = []
        for role in org.roles:
            if role.arn == target.arn:
                continue
            if not (role.arn in trust_principals or "*" in trust_principals):
                continue
            if not any(
                st.effect == "Allow" and statement_matches(st.actions, st.resources, "sts:AssumeRole", target.arn)
                for st in role.identity_statements
            ):
                continue
            if resolver.denies(role.arn, ["sts:AssumeRole"], target.arn):
                continue
            guard = condition_to_guard(trust_condition, rationale=f"assume-role into {target.name} gated by trust condition")
            result.append((role.arn, guard))
        return result

    def build_graph(self, model: "AwsOrganization", scenario: "ScenarioConfig") -> nx.DiGraph:
        index = ActionResourceIndex(model.roles)
        resolver = AwsEffectivePolicyResolver(model)
        self._resolver = resolver
        roles_by_arn = {r.arn: r for r in model.roles}

        crown_jewels = {cj.name: cj for cj in scenario.crown_jewels}  # name == resource ARN for AWS

        permissions: list[EffectivePermission] = []
        reachable_identities: set[str] = set()
        frontier: list[str] = []

        # --- seed: identities with direct (undenied) access to a crown jewel ---
        for cj_arn in crown_jewels:
            for role_arn, statement, guard in index.principals_with_access(cj_arn):
                if resolver.denies(role_arn, statement.actions, cj_arn):
                    continue  # SCP / explicit Deny cut this edge — it never enters the graph
                permissions.append(
                    EffectivePermission(
                        source=role_arn,
                        target=cj_arn,
                        relation=EdgeRelation.READ_SECRET,
                        guard=guard,
                        weight=_READ_SECRET_WEIGHT,
                        rationale=f"Role can access crown jewel {cj_arn} (survives Deny/SCP).",
                    )
                )
                if role_arn not in reachable_identities:
                    reachable_identities.add(role_arn)
                    frontier.append(role_arn)

        # --- backward-reachability: expand along undenied assume-role chains ---
        while frontier:
            target_arn = frontier.pop()
            target = roles_by_arn.get(target_arn)
            if target is None:
                continue
            for assumer_arn, guard in self._assumers(model, target, resolver):
                permissions.append(
                    EffectivePermission(
                        source=assumer_arn,
                        target=target_arn,
                        relation=EdgeRelation.PIVOT_IDENTITY,
                        guard=guard,
                        weight=_PIVOT_WEIGHT,
                        rationale=f"Role {assumer_arn} can assume {target_arn}.",
                    )
                )
                if assumer_arn not in reachable_identities:
                    reachable_identities.add(assumer_arn)
                    frontier.append(assumer_arn)

        # --- entry compute: any that runs as a reachable role ---
        entry_computes = [c for c in model.computes if c.execution_role_arn in reachable_identities]

        # --- materialize through CanonicalGraph (enforces effective-permission resolution) ---
        cg = CanonicalGraph()
        for arn in reachable_identities:
            role = roles_by_arn.get(arn)
            cg.add_identity(arn, name=role.name if role else arn, account_id=role.account_id if role else "")
        for cj_arn, cj in crown_jewels.items():
            if any(p.target == cj_arn for p in permissions):
                cg.add_node(cj_arn, NodeKind.RESOURCE, name=cj.name)
        for compute in entry_computes:
            cg.add_node(compute.arn, NodeKind.COMPUTE, name=compute.name, public=compute.public, account_id=compute.account_id)
            cg.add_structural_edge(
                compute.arn,
                compute.execution_role_arn,
                EdgeRelation.USES_TOKEN,
                weight=2.0,
                rationale=f"Compromised compute {compute.name} runs as its execution role.",
            )

        cg.add_permissions(EffectivePermissionSet(permissions))

        for cj_arn, cj in crown_jewels.items():
            if cg.has_node(cj_arn):
                cg.mark_crown_jewel(cj_arn, criticality=cj.criticality, rationale=cj.rationale)

        return cg.to_digraph()


# Sentinel empty org so resolver() can return a conforming instance before build_graph runs.
def _make_empty_org() -> "AwsOrganization":
    from evonhi_core.providers.aws.model import AwsOrganization

    return AwsOrganization()


_EMPTY_ORG = _make_empty_org()
