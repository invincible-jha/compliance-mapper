# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
ComplianceMapper — the main engine of the compliance-mapper Python package.

Orchestrates multiple ``ComplianceFramework`` implementations against a
``GovernanceConfig`` and ``AuditLog``, producing a single ``ComplianceReport``.

The mapper itself is intentionally stateless.  All state is created fresh per
``map()`` invocation, making the instance safe to reuse across calls.

Example::

    from compliance_mapper.mapper import ComplianceMapper
    from compliance_mapper.frameworks.soc2 import SOC2Framework
    from compliance_mapper.frameworks.gdpr import GDPRFramework
    from compliance_mapper.frameworks.eu_ai_act import EUAIActFramework

    mapper = ComplianceMapper()
    report = mapper.map(
        governance_config,
        audit_log,
        [SOC2Framework(), GDPRFramework(), EUAIActFramework()],
    )
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from compliance_mapper.evidence.generator import EvidenceGenerator
from compliance_mapper.frameworks.interface import ComplianceFramework
from compliance_mapper.types import (
    AuditLog,
    ComplianceReport,
    ControlAssessment,
    FrameworkResult,
    GapItem,
    GovernanceConfig,
    MapperOptions,
    ReportSummary,
)

# Severity ordering used for sorting gaps (lower index = higher severity).
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


# ── Internal helpers ──────────────────────────────────────────────────────────


def _derive_framework_result(
    framework_id: str,
    framework_name: str,
    framework_version: str,
    controls: tuple[ControlAssessment, ...],
) -> FrameworkResult:
    """Aggregate status counts from a set of control assessments."""
    satisfied_count = 0
    gap_count = 0
    partial_count = 0
    not_applicable_count = 0

    for control in controls:
        if control.status == "satisfied":
            satisfied_count += 1
        elif control.status == "gap":
            gap_count += 1
        elif control.status == "partial":
            partial_count += 1
        elif control.status == "not_applicable":
            not_applicable_count += 1

    return FrameworkResult(
        framework_id=framework_id,
        framework_name=framework_name,
        framework_version=framework_version,
        controls=controls,
        satisfied_count=satisfied_count,
        gap_count=gap_count,
        partial_count=partial_count,
        not_applicable_count=not_applicable_count,
        total_count=len(controls),
    )


def _derive_report_summary(
    framework_results: tuple[FrameworkResult, ...],
    gaps: tuple[GapItem, ...],
) -> ReportSummary:
    """Compute high-level statistics across all framework results."""
    total_controls = 0
    total_satisfied = 0
    total_gaps = 0
    total_partial = 0
    total_not_applicable = 0

    for result in framework_results:
        total_controls += result.total_count
        total_satisfied += result.satisfied_count
        total_gaps += result.gap_count
        total_partial += result.partial_count
        total_not_applicable += result.not_applicable_count

    assessed_controls = total_controls - total_not_applicable
    overall_compliance_rate = (
        total_satisfied / assessed_controls if assessed_controls > 0 else 0.0
    )
    critical_gaps_count = sum(1 for g in gaps if g.severity == "critical")

    return ReportSummary(
        total_frameworks=len(framework_results),
        total_controls=total_controls,
        total_satisfied=total_satisfied,
        total_gaps=total_gaps,
        total_partial=total_partial,
        overall_compliance_rate=overall_compliance_rate,
        critical_gaps_count=critical_gaps_count,
    )


# ── ComplianceMapper ──────────────────────────────────────────────────────────


class ComplianceMapper:
    """
    Primary entry point for generating compliance evidence reports.

    The mapper is stateless — each ``map()`` call produces an independent
    ``ComplianceReport`` snapshot with a fresh ``report_id``.

    Parameters
    ----------
    None — all configuration is passed per-call via ``MapperOptions``.

    Example::

        from compliance_mapper.mapper import ComplianceMapper
        from compliance_mapper.frameworks.soc2 import SOC2Framework

        mapper = ComplianceMapper()
        report = mapper.map(
            governance_config,
            audit_log,
            [SOC2Framework()],
            MapperOptions(include_audit_event_gaps=True),
        )
    """

    def __init__(self) -> None:
        self._generator = EvidenceGenerator()

    def map(
        self,
        governance_config: GovernanceConfig,
        audit_log: AuditLog,
        frameworks: list[ComplianceFramework] | tuple[ComplianceFramework, ...],
        options: MapperOptions | None = None,
    ) -> ComplianceReport:
        """
        Map a governance configuration and audit log against one or more
        compliance frameworks, returning a structured evidence report.

        Parameters
        ----------
        governance_config:
            The governance configuration to assess.
        audit_log:
            Structured audit log covering the assessment period.
        frameworks:
            One or more ``ComplianceFramework`` implementations to assess against.
        options:
            Optional mapping behaviour overrides.  Defaults to ``MapperOptions()``.

        Returns
        -------
        ComplianceReport
            Immutable report containing assessments, gaps, and summary statistics.

        Raises
        ------
        ValueError
            If ``frameworks`` is empty.
        """
        if not frameworks:
            raise ValueError(
                "ComplianceMapper.map() requires at least one framework. "
                "Pass instances of SOC2Framework, GDPRFramework, EUAIActFramework, "
                "or a custom ComplianceFramework implementation."
            )

        resolved_options = options if options is not None else MapperOptions()
        report_timestamp = (
            resolved_options.report_timestamp
            or datetime.now(tz=timezone.utc).isoformat()
        )
        # Ensure all framework invocations share the same timestamp.
        stamped_options = MapperOptions(
            report_timestamp=report_timestamp,
            include_audit_event_gaps=resolved_options.include_audit_event_gaps,
            exclude_control_ids=resolved_options.exclude_control_ids,
        )

        framework_results: list[FrameworkResult] = []
        all_gaps: list[GapItem] = []

        for framework in frameworks:
            controls = framework.assess(governance_config, audit_log, stamped_options)
            framework_result = _derive_framework_result(
                framework_id=framework.metadata.id,
                framework_name=framework.metadata.name,
                framework_version=framework.metadata.version,
                controls=controls,
            )
            framework_results.append(framework_result)

            for control in controls:
                gap = self._generator.generate_gap_item(framework.metadata.id, control)
                if gap is not None:
                    all_gaps.append(gap)

        # Sort gaps by severity, critical first.
        all_gaps.sort(key=lambda g: _SEVERITY_ORDER.get(g.severity, 99))

        summary = _derive_report_summary(tuple(framework_results), tuple(all_gaps))

        return ComplianceReport(
            report_id=str(uuid.uuid4()),
            generated_at=report_timestamp,
            assessment_period_start=audit_log.start_period,
            assessment_period_end=audit_log.end_period,
            framework_results=tuple(framework_results),
            gaps=tuple(all_gaps),
            summary=summary,
        )
