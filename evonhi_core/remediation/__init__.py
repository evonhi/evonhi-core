"""Remediation and impact interfaces (contract only; impls live in evo_saas)."""

from __future__ import annotations

from evonhi_core.remediation.base import (
    ImpactEstimator,
    ImpactEstimatorProtocol,
    RemediationApplicator,
    RemediationApplicatorProtocol,
    RemediationGenerator,
    RemediationGeneratorProtocol,
    RemediationProvider,
    RemediationProviderProtocol,
)
from evonhi_core.remediation.registry import (
    get_remediation_provider,
    register_remediation_provider,
    registered_remediation_providers,
)

__all__ = [
    "RemediationGenerator",
    "RemediationApplicator",
    "ImpactEstimator",
    "RemediationProvider",
    "RemediationGeneratorProtocol",
    "RemediationApplicatorProtocol",
    "ImpactEstimatorProtocol",
    "RemediationProviderProtocol",
    "register_remediation_provider",
    "get_remediation_provider",
    "registered_remediation_providers",
]
