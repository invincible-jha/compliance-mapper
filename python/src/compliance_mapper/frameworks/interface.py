# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
ComplianceFramework abstract base class.

Implement this ABC to add a new regulatory framework to the mapper.
Built-in implementations: ``SOC2Framework``, ``GDPRFramework``, ``EUAIActFramework``.

Example — implementing a custom framework::

    from compliance_mapper.frameworks.interface import (
        ComplianceFramework,
        FrameworkMetadata,
    )
    from compliance_mapper.types import (
        AuditLog,
        ControlAssessment,
        GovernanceConfig,
        MapperOptions,
    )

    class ISO27001Framework(ComplianceFramework):
        @property
        def metadata(self) -> FrameworkMetadata:
            return FrameworkMetadata(
                id="iso27001",
                name="ISO/IEC 27001:2022",
                version="2022",
                source="ISO/IEC",
                scope_description="Information security management system controls.",
            )

        def list_control_ids(self) -> tuple[str, ...]:
            return ("A.5.1", "A.5.2")

        def assess(
            self,
            governance_config: GovernanceConfig,
            audit_log: AuditLog,
            options: MapperOptions,
        ) -> tuple[ControlAssessment, ...]:
            ...
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from compliance_mapper.types import (
    AuditLog,
    ControlAssessment,
    GovernanceConfig,
    MapperOptions,
)


@dataclass(frozen=True)
class FrameworkMetadata:
    """Metadata describing a compliance framework."""

    id: str
    """Stable machine-readable identifier, lowercase with hyphens (e.g. ``'soc2'``)."""

    name: str
    """Human-readable display name (e.g. ``'SOC 2 Type II'``)."""

    version: str
    """Regulation version or year (e.g. ``'2017'``, ``'2016/679'``)."""

    source: str
    """Issuing body or reference (e.g. ``'AICPA'``, ``'EU Official Journal'``)."""

    scope_description: str
    """Brief scope description shown in reports."""


class ComplianceFramework(ABC):
    """
    Pluggable compliance framework interface.

    Each framework knows its own controls and how to assess them against a
    governance configuration and audit log.  The mapper orchestrates collection
    across multiple framework instances.

    Subclasses must implement:

    - ``metadata`` property — returns ``FrameworkMetadata``.
    - ``list_control_ids()`` — returns all control/article IDs this framework covers.
    - ``assess()`` — evaluates all controls and returns ``ControlAssessment`` objects.
    """

    @property
    @abstractmethod
    def metadata(self) -> FrameworkMetadata:
        """Framework identification and metadata."""

    @abstractmethod
    def list_control_ids(self) -> tuple[str, ...]:
        """
        Return all control or article IDs this framework can assess.

        Used by the mapper to apply ``MapperOptions.exclude_control_ids`` filtering
        before calling ``assess()``.
        """

    @abstractmethod
    def assess(
        self,
        governance_config: GovernanceConfig,
        audit_log: AuditLog,
        options: MapperOptions,
    ) -> tuple[ControlAssessment, ...]:
        """
        Assess all controls against the provided governance config and audit log.

        Parameters
        ----------
        governance_config:
            The full governance configuration object.
        audit_log:
            Structured audit log covering the assessment period.
        options:
            Mapper options (exclusion list, report timestamp, gap inclusion flag).

        Returns
        -------
        tuple[ControlAssessment, ...]
            One assessment per control or article defined by this framework.
        """
