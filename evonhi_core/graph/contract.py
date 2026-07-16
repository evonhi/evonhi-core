"""Canonical attack-graph contract (Fase 1, multi-cloud refactor).

The canonical graph is the decoupling boundary between providers (Kubernetes, AWS,
and later Azure/GCP/Oracle) and the provider-agnostic engine (traversal +
optimization). Each provider keeps its own rich model and translates it into the
node kinds, edge relations and guards defined here.

NORMATIVE SEMANTICS OF A PERMISSION EDGE
----------------------------------------
A permission edge (``GRANTED_PERMISSION``, ``READ_SECRET``, ``SPAWN_WORKLOAD_AS``,
``PIVOT_IDENTITY``) represents an EFFECTIVE permission: the net result after applying
the provider's full evaluation order — direct and ``CONTAINS``-inherited Allow, minus
explicit Deny, minus hierarchical ceilings (AWS SCP, Azure Deny Assignment, GCP Org
Policy). The graph NEVER contains a permission that a Deny or a ceiling nullifies.
Precedence is resolved in the provider builder, before the edge is created. The
traversal does not evaluate Deny: it assumes whatever is in the graph already survived
resolution. This separation preserves the locality of the traversal.

Deny / SCP / Deny Assignment / Org Policy must therefore never appear as negative
edges nor as ``blocked`` guards evaluated during traversal — they are resolved away at
construction time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class NodeKind(str, Enum):
    """Kinds of node in the canonical graph. Closed, small vocabulary shared by all
    providers; a provider maps its concrete objects onto these."""

    IDENTITY = "identity"        # service account (k8s), IAM role/user (aws), principal (azure/gcp)
    PERMISSION = "permission"    # rule (k8s), policy statement (aws)
    SECRET = "secret"
    COMPUTE = "compute"          # workload (k8s), lambda/ec2 (aws)
    RESOURCE = "resource"        # generic protectable resource (bucket, db, kms key)
    CROWN_JEWEL = "crown_jewel"
    SCOPE = "scope"              # hierarchical container: namespace, account, management group, folder/project


class EdgeRelation(str, Enum):
    """Edge relations in the canonical graph.

    Permission relations (subject to effective-permission resolution): GRANTED_PERMISSION,
    READ_SECRET, SPAWN_WORKLOAD_AS, PIVOT_IDENTITY.
    Structural relations (inherent, not policy-resolved): USES_TOKEN, MOUNTED_SECRET, CONTAINS.
    """

    USES_TOKEN = "uses_token"
    MOUNTED_SECRET = "mounted_secret"
    GRANTED_PERMISSION = "granted_permission"
    READ_SECRET = "read_secret"
    SPAWN_WORKLOAD_AS = "spawn_workload_as"   # keep this exact string (golden tests depend on it)
    PIVOT_IDENTITY = "pivot_identity"         # generalizes aws assume-role
    CONTAINS = "contains"                     # hierarchical containment


#: Relations whose edges represent an effective permission and therefore must only be
#: added from a resolved EffectivePermissionSet (enforced by CanonicalGraph).
PERMISSION_RELATIONS: frozenset[EdgeRelation] = frozenset(
    {
        EdgeRelation.GRANTED_PERMISSION,
        EdgeRelation.READ_SECRET,
        EdgeRelation.SPAWN_WORKLOAD_AS,
        EdgeRelation.PIVOT_IDENTITY,
    }
)

#: Relations that are inherent/structural and do not go through policy resolution.
STRUCTURAL_RELATIONS: frozenset[EdgeRelation] = frozenset(
    {
        EdgeRelation.USES_TOKEN,
        EdgeRelation.MOUNTED_SECRET,
        EdgeRelation.CONTAINS,
    }
)


class CapabilityKind(str, Enum):
    """Attacker-held conditions that gate edge traversal.

    CLOSED, SMALL domain. Adding a kind impacts the ``2^k`` term of the stateful
    traversal (Fase 2) and is a deliberate architectural decision, not an ad-hoc
    extension a builder invents on the fly.
    """

    NETWORK_POSITION = "network_position"   # aws:SourceIp / VpcId
    PRINCIPAL_TAG = "principal_tag"         # aws:PrincipalTag
    ORG_MEMBERSHIP = "org_membership"       # aws:PrincipalOrgID
    REGION = "region"                       # aws:RequestedRegion
    MFA = "mfa"                             # aws:MultiFactorAuthPresent


class GuardStatus(str, Enum):
    OPEN = "open"                # unconditionally traversable
    BLOCKED = "blocked"          # never traversable (rarely used; precedence is resolved at build time)
    CONDITIONAL = "conditional"  # traversable subject to conditions (treated as traversable in conservative mode)


@dataclass(slots=True, frozen=True)
class Capability:
    """An attacker-held capability. Frozen + hashable so it can live in the
    ``frozenset[Capability]`` accumulated by the stateful traversal (Fase 2)."""

    kind: CapabilityKind
    value: str


@dataclass(slots=True)
class Guard:
    """Traversability contract carried by every canonical edge.

    ``required``: capabilities the attacker must already hold to traverse the edge.
    ``grants``: capabilities gained by traversing it (enables second-order escalation).
    ``static_status``: open / blocked / conditional (see GuardStatus).
    In the absence of conditions (e.g. Kubernetes) the guard is ``open`` with empty
    lists, which reproduces today's behavior. Traversability is decided by the guard;
    the scalar edge weight exists only for path scoring — guards are NOT scalar weights.
    """

    required: list[Capability] = field(default_factory=list)
    grants: list[Capability] = field(default_factory=list)
    static_status: str = GuardStatus.OPEN.value
    rationale: str = ""

    @property
    def is_open(self) -> bool:
        return self.static_status == GuardStatus.OPEN.value and not self.required

    @property
    def is_conditional(self) -> bool:
        return self.static_status == GuardStatus.CONDITIONAL.value


def open_guard(rationale: str = "") -> Guard:
    """An unconditional guard (Kubernetes default): open, no required/granted caps."""
    return Guard(required=[], grants=[], static_status=GuardStatus.OPEN.value, rationale=rationale)


class UnresolvedPermissionError(TypeError):
    """Raised when a permission edge is added from something other than a resolved
    EffectivePermissionSet — i.e. an attempt to bypass effective-policy resolution."""
