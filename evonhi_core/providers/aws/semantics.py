"""AWS escalation semantics (Fase 5, multi-cloud refactor).

Translates IAM conditions into canonical Guards and declares the closed capability domain
and the escalation action sets. No boto3, no ingestion — pure translation.
"""

from __future__ import annotations

import fnmatch

from evonhi_core.graph.contract import Capability, CapabilityKind, Guard, GuardStatus, open_guard

# Closed capability domain for AWS (Fase 2.3 requires it small; traversal asserts <= 8).
CAPABILITY_DOMAIN: tuple[CapabilityKind, ...] = (
    CapabilityKind.ORG_MEMBERSHIP,
    CapabilityKind.NETWORK_POSITION,
    CapabilityKind.PRINCIPAL_TAG,
    CapabilityKind.REGION,
    CapabilityKind.MFA,
)

# IAM condition key -> capability kind.
_CONDITION_TO_CAPABILITY: dict[str, CapabilityKind] = {
    "aws:PrincipalOrgID": CapabilityKind.ORG_MEMBERSHIP,
    "aws:SourceIp": CapabilityKind.NETWORK_POSITION,
    "aws:VpcId": CapabilityKind.NETWORK_POSITION,
    "aws:PrincipalTag": CapabilityKind.PRINCIPAL_TAG,
    "aws:RequestedRegion": CapabilityKind.REGION,
    "aws:MultiFactorAuthPresent": CapabilityKind.MFA,
}

ASSUME_ROLE_ACTIONS = frozenset({"sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"})
PASS_ROLE_ACTIONS = frozenset({"iam:PassRole"})
SELF_ESCALATION_ACTIONS = frozenset({"iam:CreatePolicyVersion", "iam:AttachRolePolicy", "iam:PutRolePolicy"})


def action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action, pattern)


def resource_matches(pattern: str, resource_arn: str) -> bool:
    if pattern == "*":
        return True
    return fnmatch.fnmatchcase(resource_arn, pattern)


def statement_matches(actions: list[str], resources: list[str], action: str | None, resource_arn: str) -> bool:
    if not any(resource_matches(p, resource_arn) for p in resources):
        return False
    if action is not None and not any(action_matches(p, action) for p in actions):
        return False
    return True


def condition_to_guard(condition: dict[str, str], rationale: str = "") -> Guard:
    """A non-empty condition becomes a conditional Guard whose required capabilities the
    attacker must (conservatively) be assumed able to satisfy. An empty condition is open."""
    if not condition:
        return open_guard(rationale)
    required: list[Capability] = []
    for key, value in condition.items():
        kind = _CONDITION_TO_CAPABILITY.get(key)
        if kind is not None:
            required.append(Capability(kind, value))
    if not required:
        return open_guard(rationale)
    return Guard(required=required, grants=[], static_status=GuardStatus.CONDITIONAL.value, rationale=rationale)
