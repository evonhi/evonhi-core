"""AWS effective-policy resolver (Fase 5, multi-cloud refactor).

Applies AWS precedence — identity Allow, minus explicit Deny, minus the Service Control
Policies (SCP) of the account's OU hierarchy — BEFORE any edge is created. Only what survives
becomes an effective permission; a permission a Deny or SCP nullifies never reaches the graph.
This is why the traversal never has to evaluate Deny.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from evonhi_core.graph.contract import EdgeRelation
from evonhi_core.providers.aws.index import ActionResourceIndex
from evonhi_core.providers.aws.semantics import action_matches, resource_matches
from evonhi_core.resolution.base import EffectivePermission, EffectivePermissionSet, EffectivePolicyResolver

if TYPE_CHECKING:
    from evonhi_core.providers.aws.model import AwsOrganization, IamPolicyStatement, IamRole

_READ_SECRET_WEIGHT = 8.0


def _deny_matches(deny: "IamPolicyStatement", allow_actions: list[str], resource_arn: str) -> bool:
    """A Deny (identity or SCP) nullifies an Allow if it covers the same resource and any of
    the Allow's actions (wildcard-aware, so ``s3:*`` Deny cancels an ``s3:*`` Allow)."""
    if deny.effect != "Deny":
        return False
    if not any(resource_matches(p, resource_arn) for p in deny.resources):
        return False
    return any(action_matches(deny_pat, allow_act) for deny_pat in deny.actions for allow_act in allow_actions)


class AwsEffectivePolicyResolver(EffectivePolicyResolver):
    def __init__(self, org: "AwsOrganization") -> None:
        self._roles_by_arn: dict[str, IamRole] = {r.arn: r for r in org.roles}
        account_ou: dict[str, str | None] = {a.account_id: a.ou_id for a in org.accounts}
        ou_by_id = {ou.ou_id: ou for ou in org.organizational_units}
        # Precompute each role's effective SCP Deny statements (its account's OU chain).
        self._scp_denies_by_role: dict[str, list[IamPolicyStatement]] = {}
        for role in org.roles:
            denies: list[IamPolicyStatement] = []
            ou_id = account_ou.get(role.account_id)
            seen: set[str] = set()
            while ou_id is not None and ou_id not in seen:
                seen.add(ou_id)
                ou = ou_by_id.get(ou_id)
                if ou is None:
                    break
                denies.extend(s for s in ou.scps if s.effect == "Deny")
                ou_id = ou.parent_ou_id
            self._scp_denies_by_role[role.arn] = denies

    def denies(self, role_arn: str, allow_actions: list[str], resource_arn: str) -> bool:
        """True if an explicit identity Deny or an SCP in the role's OU chain cancels the Allow."""
        role = self._roles_by_arn.get(role_arn)
        if role is None:
            return True
        for statement in role.identity_statements:
            if _deny_matches(statement, allow_actions, resource_arn):
                return True
        for scp in self._scp_denies_by_role.get(role_arn, []):
            if _deny_matches(scp, allow_actions, resource_arn):
                return True
        return False

    def resolve(self, provider_model: "AwsOrganization") -> EffectivePermissionSet:
        """Surviving direct resource-access permissions across the org (identity Allow minus
        Deny minus SCP). Assume-role pivots are materialized by the provider's
        backward-reachability, which uses ``denies`` with the same precedence."""
        index = ActionResourceIndex(provider_model.roles)
        permissions: list[EffectivePermission] = []
        for resource in provider_model.resources:
            for role_arn, statement, guard in index.principals_with_access(resource.arn):
                if self.denies(role_arn, statement.actions, resource.arn):
                    continue
                permissions.append(
                    EffectivePermission(
                        source=role_arn,
                        target=resource.arn,
                        relation=EdgeRelation.READ_SECRET,
                        guard=guard,
                        weight=_READ_SECRET_WEIGHT,
                        rationale=f"Role can access {resource.arn} (survives Deny/SCP resolution).",
                    )
                )
        return EffectivePermissionSet(permissions)
