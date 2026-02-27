# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
ISO/IEC 42001:2023 AI Management System compliance framework implementation.

Maps ISO/IEC 42001 clauses (4–10) and Annex A controls (A.2–A.10) to
governance configuration paths and audit log events.  Provides coverage
reporting, evidence requirement lookup, and gap analysis against a
Governance Bill of Materials (GBOM) control list.

The framework loads the clause mapping from
``mappings/iso-42001-controls.json`` at the repository root.  If the file is
unavailable (e.g. installed as a library without the repo), it falls back to
an inline subset covering the most commonly assessed controls.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from compliance_mapper.evidence.collector import EvidenceCollector
from compliance_mapper.evidence.generator import AssessmentGenerationParams, EvidenceGenerator
from compliance_mapper.evidence.types import ControlEvidenceCollection
from compliance_mapper.frameworks.interface import ComplianceFramework, FrameworkMetadata
from compliance_mapper.types import (
    AuditLog,
    ControlAssessment,
    GovernanceConfig,
    MapperOptions,
)


# ── Pydantic v2 models for return types ──────────────────────────────────────


class EvidenceRequirement(BaseModel):
    """A single evidence requirement for an ISO 42001 clause."""

    clause_id: str = Field(description="ISO 42001 clause identifier")
    evidence_type: str = Field(description="Type of evidence required")
    governance_config_paths: list[str] = Field(description="Required governance configuration paths")
    audit_log_events: list[str] = Field(description="Required audit log event types")
    description: str = Field(description="Human-readable description of the requirement")


class ClauseCoverage(BaseModel):
    """Coverage status for a single ISO 42001 clause."""

    clause_id: str = Field(description="ISO 42001 clause identifier")
    title: str = Field(description="Clause title")
    category: str = Field(description="Clause category")
    status: Literal["covered", "partial", "gap"] = Field(description="Coverage status")
    matched_controls: list[str] = Field(description="GBOM controls satisfying this clause")
    missing_controls: list[str] = Field(description="AumOS controls not matched by GBOM")


class CoverageReport(BaseModel):
    """Full coverage report for ISO 42001 against GBOM controls."""

    standard: str = Field(default="ISO/IEC 42001:2023")
    total_clauses: int = Field(description="Total number of clauses assessed")
    covered_count: int = Field(description="Number of fully covered clauses")
    partial_count: int = Field(description="Number of partially covered clauses")
    gap_count: int = Field(description="Number of clauses with no coverage")
    coverage_percentage: float = Field(description="Overall coverage percentage (0.0–100.0)")
    clauses: list[ClauseCoverage] = Field(description="Per-clause coverage detail")
    generated_at: str = Field(description="ISO 8601 timestamp of report generation")


class GapDetail(BaseModel):
    """A single gap identified in the gap analysis."""

    clause_id: str = Field(description="ISO 42001 clause identifier")
    title: str = Field(description="Clause title")
    category: str = Field(description="Clause category")
    missing_aumos_controls: list[str] = Field(description="AumOS controls needed but not provided")
    recommendation: str = Field(description="Remediation recommendation")
    severity: Literal["critical", "high", "medium", "low"] = Field(description="Gap severity")


class GapAnalysis(BaseModel):
    """Gap analysis result for ISO 42001 against GBOM controls."""

    standard: str = Field(default="ISO/IEC 42001:2023")
    total_gaps: int = Field(description="Total number of gaps identified")
    critical_gaps: int = Field(description="Number of critical gaps")
    high_gaps: int = Field(description="Number of high-severity gaps")
    gaps: list[GapDetail] = Field(description="Detailed gap list")
    generated_at: str = Field(description="ISO 8601 timestamp of analysis generation")


# ── Internal mapping dataclass ────────────────────────────────────────────────


@dataclass(frozen=True)
class _ISO42001Control:
    id: str
    title: str
    category: str
    aumos_protocols: tuple[str, ...]
    aumos_controls: tuple[str, ...]
    coverage: str
    evidence_type: str
    notes: str
    governance_config_paths: tuple[str, ...]
    audit_log_events: tuple[str, ...]


# ── Fallback inline mapping ──────────────────────────────────────────────────

_INLINE_CONTROLS: tuple[_ISO42001Control, ...] = (
    _ISO42001Control(
        id="5.1",
        title="Leadership and commitment",
        category="Leadership",
        aumos_protocols=("ATP", "AOAP"),
        aumos_controls=("ATP-001", "AOAP-001"),
        coverage="full",
        evidence_type="governance_config",
        notes="Trust level assignments demonstrate AI governance commitment",
        governance_config_paths=(
            "governance.ai.leadershipCommitment",
            "governance.ai.managementReview",
            "governance.organization.aiGovernanceCharter",
        ),
        audit_log_events=("leadership_commitment_attested", "management_review_completed"),
    ),
    _ISO42001Control(
        id="5.2",
        title="AI policy",
        category="Leadership",
        aumos_protocols=("ATP", "ALP"),
        aumos_controls=("ATP-005", "ALP-002"),
        coverage="full",
        evidence_type="policy_document",
        notes="AI policy established and communicated via trust and logging protocols",
        governance_config_paths=(
            "governance.ai.aiPolicy",
            "governance.ai.aiPolicyObjectives",
            "governance.ai.aiPolicyCommunication",
        ),
        audit_log_events=("ai_policy_approved", "ai_policy_communicated"),
    ),
    _ISO42001Control(
        id="6.1",
        title="Actions to address risks and opportunities",
        category="Planning",
        aumos_protocols=("ATP", "AOAP"),
        aumos_controls=("ATP-007", "AOAP-004"),
        coverage="full",
        evidence_type="risk_assessment",
        notes="Risk and opportunity actions planned through governance framework",
        governance_config_paths=(
            "governance.ai.riskOpportunityRegister",
            "governance.ai.riskTreatmentPlan",
            "governance.ai.aiImpactAssessment",
        ),
        audit_log_events=("ai_risk_assessment_completed", "risk_treatment_plan_approved"),
    ),
    _ISO42001Control(
        id="8.2",
        title="AI risk assessment",
        category="Operation",
        aumos_protocols=("ATP", "AOAP"),
        aumos_controls=("ATP-014", "AOAP-007"),
        coverage="full",
        evidence_type="risk_assessment",
        notes="AI-specific risk assessments conducted at planned intervals",
        governance_config_paths=(
            "governance.ai.riskAssessmentMethodology",
            "governance.ai.riskAssessmentSchedule",
            "governance.ai.riskCriteria",
        ),
        audit_log_events=("ai_risk_assessment_conducted", "risk_level_determined"),
    ),
    _ISO42001Control(
        id="9.2",
        title="Internal audit",
        category="Performance evaluation",
        aumos_protocols=("ALP", "AOAP"),
        aumos_controls=("ALP-007", "AOAP-011"),
        coverage="full",
        evidence_type="audit_report",
        notes="Internal audits of the AIMS conducted at planned intervals",
        governance_config_paths=(
            "governance.ai.internalAuditPlan",
            "governance.ai.auditProgramSchedule",
            "governance.ai.auditCriteria",
        ),
        audit_log_events=("internal_audit_completed", "audit_findings_reported"),
    ),
    _ISO42001Control(
        id="A.5.2",
        title="AI impact assessment",
        category="Annex A — Assessing impacts of AI systems",
        aumos_protocols=("ATP", "AOAP"),
        aumos_controls=("ATP-024", "AOAP-016"),
        coverage="full",
        evidence_type="impact_assessment",
        notes="Impact assessments conducted before deployment and at intervals",
        governance_config_paths=(
            "governance.ai.impactAssessmentPolicy",
            "governance.ai.socialImpactAssessment",
            "governance.ai.environmentalImpactAssessment",
        ),
        audit_log_events=("impact_assessment_initiated", "impact_results_documented"),
    ),
)


# ── JSON loading ──────────────────────────────────────────────────────────────

_MAPPING_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent.parent
    / "mappings"
    / "iso-42001-controls.json"
)


def _parse_control(raw: dict[str, Any]) -> _ISO42001Control:
    return _ISO42001Control(
        id=raw["id"],
        title=raw["title"],
        category=raw.get("category", ""),
        aumos_protocols=tuple(raw.get("aumos_protocols", [])),
        aumos_controls=tuple(raw.get("aumos_controls", [])),
        coverage=raw.get("coverage", "full"),
        evidence_type=raw.get("evidence_type", "governance_config"),
        notes=raw.get("notes", ""),
        governance_config_paths=tuple(raw.get("governanceConfigPaths", [])),
        audit_log_events=tuple(raw.get("auditLogEvents", [])),
    )


def _load_controls() -> tuple[_ISO42001Control, ...]:
    """
    Attempt to load the full ISO 42001 mapping from the JSON file on disk.
    Falls back to the inline set if the file is unavailable or malformed.
    """
    try:
        raw_text = _MAPPING_PATH.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(raw_text)
        controls = [_parse_control(c) for c in data.get("controls", [])]
        return tuple(controls) if controls else _INLINE_CONTROLS
    except (OSError, KeyError, json.JSONDecodeError):
        return _INLINE_CONTROLS


# ── Helper functions ─────────────────────────────────────────────────────────


def _derive_gap_severity(missing_count: int, total_count: int) -> Literal["critical", "high", "medium", "low"]:
    """Derive gap severity from the ratio of missing controls to total."""
    if total_count == 0:
        return "low"
    ratio = missing_count / total_count
    if ratio >= 0.8:
        return "critical"
    if ratio >= 0.5:
        return "high"
    if ratio >= 0.25:
        return "medium"
    return "low"


# ── Public API functions ─────────────────────────────────────────────────────


def get_coverage_report(gbom_controls: list[str]) -> CoverageReport:
    """
    Generate a coverage report showing which ISO 42001 clauses are satisfied
    by the provided GBOM control identifiers.

    Parameters
    ----------
    gbom_controls:
        List of AumOS control identifiers present in the Governance BOM
        (e.g. ``["ATP-001", "AOAP-001", "ALP-002"]``).

    Returns
    -------
    CoverageReport
        Structured report with per-clause coverage status.
    """
    controls = _load_controls()
    gbom_set = set(gbom_controls)

    clauses: list[ClauseCoverage] = []
    covered_count = 0
    partial_count = 0
    gap_count = 0

    for control in controls:
        matched = [c for c in control.aumos_controls if c in gbom_set]
        missing = [c for c in control.aumos_controls if c not in gbom_set]

        if len(matched) == len(control.aumos_controls) and len(matched) > 0:
            status: Literal["covered", "partial", "gap"] = "covered"
            covered_count += 1
        elif len(matched) > 0:
            status = "partial"
            partial_count += 1
        else:
            status = "gap"
            gap_count += 1

        clauses.append(
            ClauseCoverage(
                clause_id=control.id,
                title=control.title,
                category=control.category,
                status=status,
                matched_controls=matched,
                missing_controls=missing,
            )
        )

    total = len(controls)
    coverage_pct = (covered_count / total * 100.0) if total > 0 else 0.0

    return CoverageReport(
        total_clauses=total,
        covered_count=covered_count,
        partial_count=partial_count,
        gap_count=gap_count,
        coverage_percentage=round(coverage_pct, 2),
        clauses=clauses,
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
    )


def get_evidence_requirements(clause_id: str) -> list[EvidenceRequirement]:
    """
    Return the evidence requirements for a specific ISO 42001 clause.

    Parameters
    ----------
    clause_id:
        The ISO 42001 clause identifier (e.g. ``"5.1"``, ``"A.5.2"``).

    Returns
    -------
    list[EvidenceRequirement]
        Evidence requirements for the clause. Empty list if clause not found.
    """
    controls = _load_controls()
    results: list[EvidenceRequirement] = []

    for control in controls:
        if control.id == clause_id:
            results.append(
                EvidenceRequirement(
                    clause_id=control.id,
                    evidence_type=control.evidence_type,
                    governance_config_paths=list(control.governance_config_paths),
                    audit_log_events=list(control.audit_log_events),
                    description=f"{control.title}: {control.notes}",
                )
            )

    return results


def generate_gap_analysis(gbom_controls: list[str]) -> GapAnalysis:
    """
    Generate a gap analysis identifying ISO 42001 clauses not satisfied
    by the provided GBOM controls.

    Parameters
    ----------
    gbom_controls:
        List of AumOS control identifiers present in the Governance BOM.

    Returns
    -------
    GapAnalysis
        Structured gap analysis with severity ratings and recommendations.
    """
    controls = _load_controls()
    gbom_set = set(gbom_controls)

    gaps: list[GapDetail] = []

    for control in controls:
        missing = [c for c in control.aumos_controls if c not in gbom_set]
        if not missing:
            continue

        severity = _derive_gap_severity(len(missing), len(control.aumos_controls))
        first_missing = missing[0]
        recommendation = (
            f"Implement {first_missing} to address \"{control.title}\" requirements. "
            f"Configure governance paths: {', '.join(control.governance_config_paths[:2])}."
        )

        gaps.append(
            GapDetail(
                clause_id=control.id,
                title=control.title,
                category=control.category,
                missing_aumos_controls=missing,
                recommendation=recommendation,
                severity=severity,
            )
        )

    critical_count = sum(1 for g in gaps if g.severity == "critical")
    high_count = sum(1 for g in gaps if g.severity == "high")

    return GapAnalysis(
        total_gaps=len(gaps),
        critical_gaps=critical_count,
        high_gaps=high_count,
        gaps=gaps,
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
    )


# ── Framework class ───────────────────────────────────────────────────────────


class ISO42001Framework(ComplianceFramework):
    """
    ISO/IEC 42001:2023 AI Management System compliance framework.

    Covers clauses 4–10 (management system requirements) and Annex A controls
    (A.2–A.10) for AI-specific management system objectives.

    Example::

        from compliance_mapper.frameworks.iso42001 import ISO42001Framework
        from compliance_mapper.mapper import ComplianceMapper

        mapper = ComplianceMapper()
        report = mapper.map(governance_config, audit_log, [ISO42001Framework()])
    """

    def __init__(self) -> None:
        self._controls: tuple[_ISO42001Control, ...] | None = None

    @property
    def metadata(self) -> FrameworkMetadata:
        return FrameworkMetadata(
            id="iso-42001",
            name="ISO/IEC 42001:2023",
            version="2023",
            source="ISO/IEC",
            scope_description=(
                "AI Management System standard covering governance, risk management, "
                "lifecycle management, data governance, transparency, and continual "
                "improvement for AI systems."
            ),
        )

    def _ensure_loaded(self) -> tuple[_ISO42001Control, ...]:
        if self._controls is None:
            self._controls = _load_controls()
        return self._controls

    def list_control_ids(self) -> tuple[str, ...]:
        return tuple(c.id for c in self._ensure_loaded())

    def assess(
        self,
        governance_config: GovernanceConfig,
        audit_log: AuditLog,
        options: MapperOptions,
    ) -> tuple[ControlAssessment, ...]:
        """
        Assess all ISO 42001 clauses against the governance config and audit log.

        Parameters
        ----------
        governance_config:
            Full governance configuration dict.
        audit_log:
            Structured audit log for the assessment period.
        options:
            Mapper options controlling exclusions and gap inclusion.

        Returns
        -------
        tuple[ControlAssessment, ...]
            One assessment per ISO 42001 clause.
        """
        controls = self._ensure_loaded()
        excluded_ids = set(options.exclude_control_ids)
        include_audit_event_gaps = options.include_audit_event_gaps
        report_timestamp = options.report_timestamp or datetime.now(tz=timezone.utc).isoformat()

        collector = EvidenceCollector(config=governance_config, audit_log=audit_log)
        generator = EvidenceGenerator()

        assessments: list[ControlAssessment] = []
        for control in controls:
            is_excluded = control.id in excluded_ids

            if is_excluded:
                collection = ControlEvidenceCollection(
                    control_id=control.id,
                    config_resolutions=(),
                    audit_event_resolutions=(),
                    collected_at=report_timestamp,
                )
            else:
                collection = collector.collect_for_control(
                    control_id=control.id,
                    required_config_paths=control.governance_config_paths,
                    required_audit_events=control.audit_log_events,
                )

            assessments.append(
                generator.generate_assessment(
                    AssessmentGenerationParams(
                        control_id=control.id,
                        title=control.title,
                        description=control.notes,
                        framework_id=self.metadata.id,
                        collection=collection,
                        include_audit_event_gaps=include_audit_event_gaps,
                        is_excluded=is_excluded,
                    )
                )
            )

        return tuple(assessments)
