# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
EvidenceGenerator — converts raw ``ControlEvidenceCollection`` objects into
structured ``ControlAssessment``, ``EvidenceItem``, and ``GapItem`` objects.

All logic is pure and deterministic for the same inputs. No I/O or external
state is accessed here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from compliance_mapper.evidence.types import ControlEvidenceCollection
from compliance_mapper.types import (
    ControlAssessment,
    ControlStatus,
    EvidenceItem,
    GapItem,
    GapSeverity,
)

if TYPE_CHECKING:
    pass


# ── Status derivation ────────────────────────────────────────────────────────


def _derive_status(
    satisfied_paths: tuple[str, ...],
    gap_paths: tuple[str, ...],
    satisfied_events: tuple[str, ...],
    missing_events: tuple[str, ...],
    include_audit_event_gaps: bool,
) -> ControlStatus:
    """
    Derive a ``ControlStatus`` from satisfied and missing path/event counts.

    Rules:

    - If no requirements are defined (and audit gaps are not counted), the
      control is ``'not_applicable'``.
    - If every requirement is met, the control is ``'satisfied'``.
    - If *no* requirements are met, the control is ``'gap'``.
    - Otherwise, the control is ``'partial'``.
    """
    total_config = len(satisfied_paths) + len(gap_paths)
    has_audit_requirements = (
        include_audit_event_gaps
        and (len(satisfied_events) + len(missing_events)) > 0
    )

    if total_config == 0 and not has_audit_requirements:
        return "not_applicable"

    config_satisfied = total_config == 0 or len(satisfied_paths) == total_config
    audit_satisfied = not has_audit_requirements or len(missing_events) == 0

    if config_satisfied and audit_satisfied:
        return "satisfied"

    # All config paths missing and no audit events found = full gap.
    if len(satisfied_paths) == 0 and (
        not has_audit_requirements or len(satisfied_events) == 0
    ):
        return "gap"

    return "partial"


# ── Severity derivation ──────────────────────────────────────────────────────


def _derive_severity(
    gap_paths: tuple[str, ...],
    missing_events: tuple[str, ...],
    total_paths: int,
    total_events: int,
) -> GapSeverity:
    """
    Derive gap severity from the ratio of missing items to total required items.

    Thresholds:

    - >= 80% missing → ``'critical'``
    - >= 50% missing → ``'high'``
    - >= 25% missing → ``'medium'``
    - < 25% missing  → ``'low'``
    """
    total_missing = len(gap_paths) + len(missing_events)
    total_required = total_paths + total_events

    if total_required == 0:
        return "low"

    missing_ratio = total_missing / total_required

    if missing_ratio >= 0.8:
        return "critical"
    if missing_ratio >= 0.5:
        return "high"
    if missing_ratio >= 0.25:
        return "medium"
    return "low"


# ── Gap description / recommendation builders ────────────────────────────────


def _build_gap_description(
    gap_paths: tuple[str, ...],
    missing_events: tuple[str, ...],
) -> str:
    """Produce a human-readable gap description from missing paths and events."""
    parts: list[str] = []

    if gap_paths:
        shown = ", ".join(gap_paths[:3])
        remainder = f" and {len(gap_paths) - 3} more" if len(gap_paths) > 3 else ""
        parts.append(f"Missing governance configuration: {shown}{remainder}.")

    if missing_events:
        shown = ", ".join(missing_events[:3])
        remainder = f" and {len(missing_events) - 3} more" if len(missing_events) > 3 else ""
        parts.append(f"No audit log evidence for: {shown}{remainder}.")

    return " ".join(parts)


def _build_recommendation(
    gap_paths: tuple[str, ...],
    missing_events: tuple[str, ...],
    control_title: str,
) -> str:
    """Produce a single-sentence remediation recommendation."""
    if gap_paths and missing_events:
        first_path = gap_paths[0]
        return (
            f'Establish governance policies for "{control_title}" and ensure relevant '
            f"operations are captured in audit logs. Start by populating: {first_path}."
        )
    if gap_paths:
        first_path = gap_paths[0]
        return (
            f'Populate the governance configuration paths for "{control_title}". '
            f"Start with: {first_path}."
        )
    first_event = missing_events[0] if missing_events else ""
    return (
        f'Ensure operations related to "{control_title}" generate audit log entries, '
        f"particularly: {first_event}."
    )


# ── Public dataclass and class ───────────────────────────────────────────────


@dataclass(frozen=True)
class AssessmentGenerationParams:
    """Parameters needed to generate a ``ControlAssessment`` from collected evidence."""

    control_id: str
    """Framework-specific control identifier."""

    title: str
    """Human-readable control title."""

    description: str
    """Narrative description of the control's intent."""

    framework_id: str
    """Machine-readable framework identifier (e.g. ``'soc2'``)."""

    collection: ControlEvidenceCollection
    """Raw evidence collection produced by ``EvidenceCollector``."""

    include_audit_event_gaps: bool
    """Whether missing audit events contribute to gap status."""

    is_excluded: bool
    """Whether this control has been excluded by ``MapperOptions.exclude_control_ids``."""


class EvidenceGenerator:
    """
    Convert raw ``ControlEvidenceCollection`` objects into fully structured
    compliance assessment objects.

    This class holds no state; all methods are effectively pure functions
    wrapped in a class for namespacing.

    Example::

        from compliance_mapper.evidence.generator import (
            EvidenceGenerator,
            AssessmentGenerationParams,
        )

        generator = EvidenceGenerator()
        assessment = generator.generate_assessment(params)
        gap_item = generator.generate_gap_item("soc2", assessment)
    """

    def generate_assessment(self, params: AssessmentGenerationParams) -> ControlAssessment:
        """
        Generate a ``ControlAssessment`` from a raw evidence collection.

        Parameters
        ----------
        params:
            All inputs required to produce the assessment.

        Returns
        -------
        ControlAssessment
            Immutable assessment including status, evidence items, and gap info.
        """
        if params.is_excluded:
            return ControlAssessment(
                control_id=params.control_id,
                title=params.title,
                description=params.description,
                status="not_applicable",
                evidence=(),
                satisfied_paths=(),
                gap_paths=(),
                satisfied_events=(),
                missing_events=(),
            )

        satisfied_paths = tuple(
            r.path for r in params.collection.config_resolutions if r.found
        )
        gap_paths = tuple(
            r.path for r in params.collection.config_resolutions if not r.found
        )
        satisfied_events = tuple(
            r.event_type for r in params.collection.audit_event_resolutions if r.found
        )
        missing_events: tuple[str, ...]
        if params.include_audit_event_gaps:
            missing_events = tuple(
                r.event_type
                for r in params.collection.audit_event_resolutions
                if not r.found
            )
        else:
            missing_events = ()

        status = _derive_status(
            satisfied_paths,
            gap_paths,
            satisfied_events,
            missing_events,
            params.include_audit_event_gaps,
        )

        # Build EvidenceItems from satisfied config resolutions.
        config_evidence: list[EvidenceItem] = [
            EvidenceItem(
                evidence_id=str(uuid.uuid4()),
                title=f"Config: {r.path}",
                description=f'Governance configuration path "{r.path}" is populated.',
                source_kind="governance_config",
                source_path=r.path,
                value=r.value,
                collected_at=params.collection.collected_at,
                is_present=True,
            )
            for r in params.collection.config_resolutions
            if r.found
        ]

        # Build EvidenceItems from satisfied audit log resolutions.
        audit_evidence: list[EvidenceItem] = [
            EvidenceItem(
                evidence_id=str(uuid.uuid4()),
                title=f"Audit: {r.event_type}",
                description=(
                    f'Audit log event "{r.event_type}" was observed '
                    f"{r.occurrence_count} time(s). "
                    f"Most recent: {r.last_seen_at or 'unknown'}."
                ),
                source_kind="audit_log",
                source_path=r.event_type,
                value=r.occurrence_count,
                collected_at=params.collection.collected_at,
                is_present=True,
            )
            for r in params.collection.audit_event_resolutions
            if r.found
        ]

        evidence = tuple(config_evidence + audit_evidence)

        gap_description: str | None = None
        if status not in ("satisfied", "not_applicable"):
            gap_description = _build_gap_description(gap_paths, missing_events)

        return ControlAssessment(
            control_id=params.control_id,
            title=params.title,
            description=params.description,
            status=status,
            evidence=evidence,
            satisfied_paths=satisfied_paths,
            gap_paths=gap_paths,
            satisfied_events=satisfied_events,
            missing_events=missing_events,
            gap_description=gap_description,
        )

    def generate_gap_item(
        self,
        framework_id: str,
        assessment: ControlAssessment,
    ) -> GapItem | None:
        """
        Generate a ``GapItem`` from a ``ControlAssessment`` that has gaps.

        Returns ``None`` if the assessment is fully satisfied or not applicable.

        Parameters
        ----------
        framework_id:
            Machine-readable framework identifier (e.g. ``'gdpr'``).
        assessment:
            The control assessment to derive a gap from.

        Returns
        -------
        GapItem | None
            A gap item, or ``None`` if no gap exists.
        """
        if assessment.status in ("satisfied", "not_applicable"):
            return None

        total_paths = len(assessment.satisfied_paths) + len(assessment.gap_paths)
        total_events = len(assessment.satisfied_events) + len(assessment.missing_events)

        severity = _derive_severity(
            assessment.gap_paths,
            assessment.missing_events,
            total_paths,
            total_events,
        )
        recommendation = _build_recommendation(
            assessment.gap_paths,
            assessment.missing_events,
            assessment.title,
        )

        return GapItem(
            framework_id=framework_id,
            control_id=assessment.control_id,
            control_title=assessment.title,
            missing_config_paths=assessment.gap_paths,
            missing_audit_events=assessment.missing_events,
            severity=severity,
            recommendation=recommendation,
        )
