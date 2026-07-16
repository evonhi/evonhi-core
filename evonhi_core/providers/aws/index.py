"""Inverted action/resource index (Fase 5, multi-cloud refactor).

In AWS with identity-based policies a resource does not know which identities can reach it;
that knowledge is scattered across thousands of role policies, so backward-reachability is
impossible without a precomputed index. Built once per org snapshot from all roles' Allow
statements; queries by (service, ARN pattern) are sublinear — a resource ARN only probes the
statements bucketed under its service plus the resource-``*`` bucket, never a full re-scan.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from evonhi_core.graph.contract import Guard
from evonhi_core.providers.aws.semantics import condition_to_guard, statement_matches

if TYPE_CHECKING:
    from evonhi_core.providers.aws.model import IamPolicyStatement, IamRole


def _service_of(resource_pattern: str) -> str | None:
    # arn:aws:<service>:<region>:<account>:<rest>  -> <service>; "*" or unparseable -> None
    if resource_pattern == "*":
        return None
    parts = resource_pattern.split(":")
    if len(parts) >= 3 and parts[0] == "arn":
        return parts[2] or None
    return None


class ActionResourceIndex:
    __slots__ = ("_by_service", "_wildcard", "statement_count")

    def __init__(self, roles: "list[IamRole]") -> None:
        self._by_service: dict[str, list[tuple[str, IamPolicyStatement]]] = {}
        self._wildcard: list[tuple[str, IamPolicyStatement]] = []  # resource "*" (any service)
        self.statement_count = 0
        for role in roles:
            for statement in role.identity_statements:
                if statement.effect != "Allow":
                    continue
                self.statement_count += 1
                for resource_pattern in statement.resources:
                    service = _service_of(resource_pattern)
                    if service is None:
                        self._wildcard.append((role.arn, statement))
                    else:
                        self._by_service.setdefault(service, []).append((role.arn, statement))

    def principals_with_access(
        self, resource_arn: str, action: str | None = None
    ) -> list[tuple[str, "IamPolicyStatement", Guard]]:
        """Roles whose Allow statements cover ``resource_arn`` (optionally for ``action``),
        each with the Guard derived from the statement's condition. Sublinear: only the
        resource's service bucket and the wildcard bucket are probed."""
        service = _service_of(resource_arn)
        candidates = self._wildcard + (self._by_service.get(service, []) if service is not None else [])
        out: list[tuple[str, IamPolicyStatement, Guard]] = []
        seen: set[tuple[str, int]] = set()
        for role_arn, statement in candidates:
            if not statement_matches(statement.actions, statement.resources, action, resource_arn):
                continue
            key = (role_arn, id(statement))
            if key in seen:
                continue
            seen.add(key)
            out.append((role_arn, statement, condition_to_guard(statement.condition)))
        return out
