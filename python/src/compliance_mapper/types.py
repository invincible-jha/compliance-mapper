# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Core type definitions for the compliance-mapper Python package.

All types are designed for point-in-time compliance evidence generation.
No mutable state is held between mapper invocations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

# ── Governance Configuration ─────────────────────────────────────────────────

# A nested dict representing governance configuration settings.
# Mirrors the TypeScript GovernanceConfig type.  Used internally by all
# framework implementations for dot-path evidence resolution.
GovernanceConfig = dict[str, Any]


# ── Compliance Run Configuration ─────────────────────────────────────────────


class ComplianceFrameworkId(str, Enum):
    """Supported compliance framework identifiers."""

    SOC2 = "soc2"
    GDPR = "gdpr"
    EU_AI_ACT = "eu_ai_act"
    ISO_42001 = "iso_42001"


class ComplianceRunConfig(BaseModel):
    """
    Validated configuration for a single compliance mapping run.

    Use this model to supply structured, runtime-validated parameters to
    ``ComplianceMapper.map_from_config()`` instead of passing raw dicts.
    All fields are validated by Pydantic v2 on construction.

    Example::

        config = ComplianceRunConfig(
            framework=ComplianceFrameworkId.SOC2,
            organization_name="Acme Corp",
            audit_period_start="2026-01-01T00:00:00Z",
            audit_period_end="2026-12-31T23:59:59Z",
        )
    """

    framework: ComplianceFrameworkId
    """The compliance framework to assess against."""

    organization_name: str = Field(..., min_length=1)
    """Legal or trading name of the organisation being assessed."""

    audit_period_start: Optional[str] = None
    """ISO 8601 timestamp marking the start of the audit window.
    When provided, must be earlier than ``audit_period_end``."""

    audit_period_end: Optional[str] = None
    """ISO 8601 timestamp marking the end of the audit window."""

    governance_data_path: Optional[str] = None
    """Filesystem path to the governance configuration JSON file.
    When ``None`` the caller is expected to supply the ``GovernanceConfig``
    dict directly."""

    output_format: str = Field(default="json", pattern="^(json|pdf|html)$")
    """Report output format. One of ``'json'``, ``'pdf'``, or ``'html'``."""

    include_evidence: bool = True
    """Whether to include individual evidence items in the generated report."""

    trust_level_threshold: Optional[float] = Field(
        default=None, ge=0.0, le=1.0
    )
    """Minimum overall compliance rate (0.0–1.0) required to pass the run.
    When ``None`` no pass/fail threshold is applied."""

# ── Audit Log ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AuditLogEntry:
    """A single structured audit log entry."""

    timestamp: str
    """ISO 8601 timestamp of the event."""

    event_type: str
    """Machine-readable event identifier matching mapping ``audit_log_events``."""

    actor: str
    """Actor that triggered the event (user ID, service name, etc.)."""

    metadata: dict[str, Any]
    """Free-form metadata specific to the event type."""

    outcome: Literal["success", "failure", "partial"]
    """Outcome of the event."""

    resource_id: str | None = None
    """Optional reference to the resource affected."""


@dataclass(frozen=True)
class AuditLog:
    """Structured audit log containing time-ordered entries."""

    start_period: str
    """ISO 8601 timestamp marking the start of the log window."""

    end_period: str
    """ISO 8601 timestamp marking the end of the log window."""

    entries: tuple[AuditLogEntry, ...]
    """Time-ordered audit log entries."""


# ── Evidence ─────────────────────────────────────────────────────────────────

EvidenceSourceKind = Literal["governance_config", "audit_log", "generated_document"]


@dataclass(frozen=True)
class EvidenceItem:
    """A discrete piece of compliance evidence tied to a control or article."""

    evidence_id: str
    """Unique identifier for this evidence item within a report."""

    title: str
    """Human-readable label."""

    description: str
    """Description of what this evidence demonstrates."""

    source_kind: EvidenceSourceKind
    """How the evidence was obtained."""

    source_path: str
    """Dot-separated config path or audit log event type that sourced this item."""

    value: Any
    """The raw value or summary retrieved from the source."""

    collected_at: str
    """ISO 8601 timestamp when this evidence was collected."""

    is_present: bool
    """Whether this evidence is present and meaningful."""


# ── Control / Article Assessment ─────────────────────────────────────────────

ControlStatus = Literal["satisfied", "gap", "partial", "not_applicable"]


@dataclass(frozen=True)
class ControlAssessment:
    """Assessment of a single framework control or regulatory article."""

    control_id: str
    """Framework-specific control or article identifier (e.g. 'CC6.1', 'Art32')."""

    title: str
    """Human-readable title from the mapping JSON."""

    description: str
    """Narrative description of the control's intent."""

    status: ControlStatus
    """Aggregate status based on collected evidence."""

    evidence: tuple[EvidenceItem, ...]
    """Evidence items collected for this control."""

    satisfied_paths: tuple[str, ...]
    """Config paths that were present in the governance config."""

    gap_paths: tuple[str, ...]
    """Config paths that were missing or empty."""

    satisfied_events: tuple[str, ...]
    """Audit log events that were found in the log window."""

    missing_events: tuple[str, ...]
    """Audit log events that were not found."""

    gap_description: str | None = None
    """Human-readable gap description if status is 'gap' or 'partial'."""


# ── Framework Result ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FrameworkResult:
    """Full results for one regulatory framework within a report."""

    framework_id: str
    """Machine-readable framework identifier (e.g. 'soc2', 'gdpr', 'eu-ai-act')."""

    framework_name: str
    """Display name of the framework."""

    framework_version: str
    """Version or regulation number."""

    controls: tuple[ControlAssessment, ...]
    """All control/article assessments for this framework."""

    satisfied_count: int
    """Number of controls with status 'satisfied'."""

    gap_count: int
    """Number of controls with status 'gap'."""

    partial_count: int
    """Number of controls with status 'partial'."""

    not_applicable_count: int
    """Number of controls with status 'not_applicable'."""

    total_count: int
    """Total controls assessed."""


# ── Gap Analysis ─────────────────────────────────────────────────────────────

GapSeverity = Literal["critical", "high", "medium", "low"]


@dataclass(frozen=True)
class GapItem:
    """Aggregated gap identified across frameworks."""

    framework_id: str
    """The framework this gap belongs to."""

    control_id: str
    """The control or article with the gap."""

    control_title: str
    """Title of the control."""

    missing_config_paths: tuple[str, ...]
    """Missing governance config paths."""

    missing_audit_events: tuple[str, ...]
    """Missing audit log event types."""

    severity: GapSeverity
    """Severity derived from gap completeness."""

    recommendation: str
    """Suggested remediation action."""


# ── Compliance Report ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ReportSummary:
    """High-level statistics surfaced in a compliance report."""

    total_frameworks: int
    total_controls: int
    total_satisfied: int
    total_gaps: int
    total_partial: int
    overall_compliance_rate: float
    critical_gaps_count: int


@dataclass(frozen=True)
class ComplianceReport:
    """
    Top-level output of ``ComplianceMapper.map()``.

    Immutable, serialisable, and timestamped for audit trail purposes.
    """

    report_id: str
    """Unique report identifier."""

    generated_at: str
    """ISO 8601 timestamp when the report was generated."""

    assessment_period_start: str
    """ISO 8601 start of the audit log window assessed."""

    assessment_period_end: str
    """ISO 8601 end of the audit log window assessed."""

    framework_results: tuple[FrameworkResult, ...]
    """Results per framework."""

    gaps: tuple[GapItem, ...]
    """All gaps identified across all frameworks."""

    summary: ReportSummary
    """High-level summary statistics."""


# ── Mapper Options ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MapperOptions:
    """Options passed to ``ComplianceMapper.map()``."""

    report_timestamp: str | None = None
    """ISO 8601 timestamp to use as the report's 'generated at' value.
    Defaults to the current UTC time."""

    include_audit_event_gaps: bool = True
    """Whether to include audit log events that were not found as explicit gap items."""

    exclude_control_ids: tuple[str, ...] = field(default_factory=tuple)
    """Controls with these IDs will be marked 'not_applicable' rather than assessed."""
