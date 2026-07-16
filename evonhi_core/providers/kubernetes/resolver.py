"""Kubernetes effective-policy resolver (Fase 4, multi-cloud refactor).

Kubernetes RBAC has no explicit Deny and no hierarchical ceilings (SCP / Deny Assignment /
Org Policy), so resolution is trivial: every granted (subject, rule, resource, verb) is an
effective permission. This resolver enumerates exactly the grants the builder materializes
as ``granted_permission`` edges, exposing them as an EffectivePermissionSet. Its existence
forces AWS/Azure/GCP to implement real precedence resolution instead of smuggling Deny in as
edges.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from evonhi_core.graph.contract import EdgeRelation, open_guard
from evonhi_core.providers.kubernetes.builder import (
    _build_role_index,
    _resolve_role,
    _resource_scope,
    node_id,
    permission_id,
)
from evonhi_core.resolution.base import EffectivePermission, EffectivePermissionSet, EffectivePolicyResolver

if TYPE_CHECKING:
    from evonhi_core.providers.kubernetes.model import ClusterModel

_GRANTED_PERMISSION_WEIGHT = 3.0  # mirrors EDGE_RISK["granted_permission"]


class KubernetesEffectivePolicyResolver(EffectivePolicyResolver):
    def resolve(self, provider_model: "ClusterModel") -> EffectivePermissionSet:
        role_index = _build_role_index(provider_model)
        permissions: list[EffectivePermission] = []
        for binding in provider_model.role_bindings:
            role = _resolve_role(binding, role_index)
            if not role:
                continue
            grant_scope, grant_namespace = _resource_scope(binding)
            for subject in binding.subjects:
                if subject.kind != "ServiceAccount":
                    continue
                sa_namespace = subject.namespace or binding.metadata.namespace
                sa_id = node_id("serviceaccount", sa_namespace, subject.name)
                for rule_index, rule in enumerate(role.rules):
                    for api_group in rule.api_groups or [""]:
                        for resource in rule.resources or ["*"]:
                            for verb in rule.verbs or ["*"]:
                                binding_namespace = grant_namespace or "*"
                                pid = permission_id(
                                    sa_namespace,
                                    subject.name,
                                    binding_namespace,
                                    binding.metadata.name,
                                    role.metadata.name,
                                    rule_index,
                                    api_group,
                                    resource,
                                    verb,
                                )
                                permissions.append(
                                    EffectivePermission(
                                        source=sa_id,
                                        target=pid,
                                        relation=EdgeRelation.GRANTED_PERMISSION,
                                        guard=open_guard(),
                                        weight=_GRANTED_PERMISSION_WEIGHT,
                                        rationale=(
                                            f"Role binding {binding.metadata.name} grants {verb} on "
                                            f"{resource} in scope {grant_scope.lower()}."
                                        ),
                                    )
                                )
        return EffectivePermissionSet(permissions)
