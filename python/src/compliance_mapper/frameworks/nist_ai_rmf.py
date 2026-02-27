# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
NIST AI Risk Management Framework (AI RMF 1.0) compliance framework.

Maps the four NIST AI RMF core functions — GOVERN, MAP, MEASURE, MANAGE — and
their subcategories to governance configuration paths and audit log events.

The framework loads the function mapping from
``mappings/nist-ai-rmf-functions.json`` at the repository root.  If the file
is unavailable it falls back to an inline subset covering the most commonly
assessed subcategories.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
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


class RMFMapping(BaseModel):
    """A single NIST AI RMF subcategory mapping."""

    subcategory_id: str = Field(description="NIST AI RMF subcategory identifier")
    title: str = Field(description="Subcategory title")
    description: str = Field(description="Subcategory description")
    aumos_protocols: list[str] = Field(description="Mapped AumOS protocols")
    aumos_controls: list[str] = Field(description="Mapped AumOS control identifiers")
    coverage: str = Field(description="Coverage level (full or partial)")
    evidence_type: str = Field(description="Type of evidence required")


class SubcategoryCoverage(BaseModel):
    """Coverage status for a single NIST AI RMF subcategory."""

    subcategory_id: str = Field(description="NIST AI RMF subcategory identifier")
    function_id: str = Field(description="Parent function (GOVERN, MAP, MEASURE, MANAGE)")
    title: str = Field(description="Subcategory title")
    status: Literal["covered", "partial", "gap"] = Field(description="Coverage status")
    matched_controls: list[str] = Field(description="GBOM controls satisfying this subcategory")
    missing_controls: list[str] = Field(description="AumOS controls not matched by GBOM")


class RMFCoverageReport(BaseModel):
    """Full coverage report for NIST AI RMF against GBOM controls."""

    standard: str = Field(default="NIST AI RMF 1.0")
    total_subcategories: int = Field(description="Total number of subcategories assessed")
    covered_count: int = Field(description="Number of fully covered subcategories")
    partial_count: int = Field(description="Number of partially covered subcategories")
    gap_count: int = Field(description="Number of subcategories with no coverage")
    coverage_percentage: float = Field(description="Overall coverage percentage (0.0–100.0)")
    function_summary: dict[str, dict[str, int]] = Field(
        description="Per-function summary with covered/partial/gap counts"
    )
    subcategories: list[SubcategoryCoverage] = Field(description="Per-subcategory detail")
    generated_at: str = Field(description="ISO 8601 timestamp of report generation")


# ── Internal mapping dataclass ────────────────────────────────────────────────


@dataclass(frozen=True)
class _RMFSubcategory:
    id: str
    function_id: str
    title: str
    description: str
    aumos_protocols: tuple[str, ...]
    aumos_controls: tuple[str, ...]
    coverage: str
    evidence_type: str
    governance_config_paths: tuple[str, ...]
    audit_log_events: tuple[str, ...]


# ── Fallback inline mapping ──────────────────────────────────────────────────

_INLINE_SUBCATEGORIES: tuple[_RMFSubcategory, ...] = (
    _RMFSubcategory(
        id="GOVERN-1",
        function_id="GOVERN",
        title="Policies, processes, procedures, and practices",
        description="Legal and regulatory requirements involving AI are understood, managed, and documented.",
        aumos_protocols=("ATP", "AOAP"),
        aumos_controls=("ATP-001", "AOAP-001"),
        coverage="full",
        evidence_type="governance_config",
        governance_config_paths=(
            "governance.ai.aiGovernancePolicy",
            "governance.ai.regulatoryComplianceRegister",
            "governance.ai.aiRiskManagementPolicy",
        ),
        audit_log_events=("governance_policy_approved", "regulatory_review_completed"),
    ),
    _RMFSubcategory(
        id="GOVERN-2",
        function_id="GOVERN",
        title="Accountability structures",
        description="Accountability structures are in place for AI risk management.",
        aumos_protocols=("ATP", "AOAP"),
        aumos_controls=("ATP-002", "AOAP-002"),
        coverage="full",
        evidence_type="governance_config",
        governance_config_paths=(
            "governance.ai.accountabilityMatrix",
            "governance.ai.aiGovernanceBoard",
            "governance.ai.rolesAndResponsibilities",
        ),
        audit_log_events=("accountability_assignment_made", "governance_board_meeting"),
    ),
    _RMFSubcategory(
        id="MAP-1",
        function_id="MAP",
        title="Context is established",
        description="Context is established and understood for AI systems.",
        aumos_protocols=("ATP",),
        aumos_controls=("ATP-007",),
        coverage="full",
        evidence_type="governance_config",
        governance_config_paths=(
            "governance.ai.systemPurposeStatement",
            "governance.ai.intendedUseDocumentation",
            "governance.ai.benefitHarmAnalysis",
        ),
        audit_log_events=("system_context_documented", "purpose_statement_approved"),
    ),
    _RMFSubcategory(
        id="MEASURE-1",
        function_id="MEASURE",
        title="Appropriate methods and metrics",
        description="Appropriate methods and metrics are identified and applied.",
        aumos_protocols=("ALP", "AOAP"),
        aumos_controls=("ALP-002", "AOAP-008"),
        coverage="full",
        evidence_type="governance_config",
        governance_config_paths=(
            "governance.ai.measurementMethodology",
            "governance.ai.performanceMetrics",
            "governance.ai.fairnessMetrics",
        ),
        audit_log_events=("metrics_defined", "measurement_methodology_approved"),
    ),
    _RMFSubcategory(
        id="MANAGE-1",
        function_id="MANAGE",
        title="AI risks are prioritized and responded to",
        description="AI risks are prioritized, responded to, and managed.",
        aumos_protocols=("ATP", "AOAP"),
        aumos_controls=("ATP-012", "AOAP-012"),
        coverage="full",
        evidence_type="risk_assessment",
        governance_config_paths=(
            "governance.ai.riskPrioritizationMatrix",
            "governance.ai.riskResponsePlan",
            "governance.ai.riskMitigationActions",
        ),
        audit_log_events=("risk_prioritized", "risk_response_implemented"),
    ),
)


# ── JSON loading ──────────────────────────────────────────────────────────────

_MAPPING_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent.parent
    / "mappings"
    / "nist-ai-rmf-functions.json"
)


def _parse_subcategory(raw: dict[str, Any], function_id: str) -> _RMFSubcategory:
    return _RMFSubcategory(
        id=raw["id"],
        function_id=function_id,
        title=raw["title"],
        description=raw["description"],
        aumos_protocols=tuple(raw.get("aumos_protocols", [])),
        aumos_controls=tuple(raw.get("aumos_controls", [])),
        coverage=raw.get("coverage", "full"),
        evidence_type=raw.get("evidence_type", "governance_config"),
        governance_config_paths=tuple(raw.get("governanceConfigPaths", [])),
        audit_log_events=tuple(raw.get("auditLogEvents", [])),
    )


def _load_subcategories() -> tuple[_RMFSubcategory, ...]:
    """
    Attempt to load NIST AI RMF subcategories from the JSON file on disk.
    Falls back to the inline set if the file is unavailable or malformed.
    """
    try:
        raw_text = _MAPPING_PATH.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(raw_text)
        subcategories: list[_RMFSubcategory] = []
        for function_data in data.get("functions", []):
            function_id = function_data["id"]
            for sub_raw in function_data.get("subcategories", []):
                subcategories.append(_parse_subcategory(sub_raw, function_id))
        return tuple(subcategories) if subcategories else _INLINE_SUBCATEGORIES
    except (OSError, KeyError, json.JSONDecodeError):
        return _INLINE_SUBCATEGORIES


# ── Public API functions ─────────────────────────────────────────────────────


def get_rmf_coverage(gbom_controls: list[str]) -> RMFCoverageReport:
    """
    Generate a coverage report showing which NIST AI RMF subcategories
    are satisfied by the provided GBOM control identifiers.

    Parameters
    ----------
    gbom_controls:
        List of AumOS control identifiers present in the Governance BOM.

    Returns
    -------
    RMFCoverageReport
        Structured report with per-subcategory and per-function coverage.
    """
    subcategories = _load_subcategories()
    gbom_set = set(gbom_controls)

    coverage_items: list[SubcategoryCoverage] = []
    function_counts: dict[str, dict[str, int]] = {}
    covered_count = 0
    partial_count = 0
    gap_count = 0

    for sub in subcategories:
        matched = [c for c in sub.aumos_controls if c in gbom_set]
        missing = [c for c in sub.aumos_controls if c not in gbom_set]

        if len(matched) == len(sub.aumos_controls) and len(matched) > 0:
            status: Literal["covered", "partial", "gap"] = "covered"
            covered_count += 1
        elif len(matched) > 0:
            status = "partial"
            partial_count += 1
        else:
            status = "gap"
            gap_count += 1

        # Track per-function counts.
        if sub.function_id not in function_counts:
            function_counts[sub.function_id] = {"covered": 0, "partial": 0, "gap": 0}
        function_counts[sub.function_id][status] += 1

        coverage_items.append(
            SubcategoryCoverage(
                subcategory_id=sub.id,
                function_id=sub.function_id,
                title=sub.title,
                status=status,
                matched_controls=matched,
                missing_controls=missing,
            )
        )

    total = len(subcategories)
    coverage_pct = (covered_count / total * 100.0) if total > 0 else 0.0

    return RMFCoverageReport(
        total_subcategories=total,
        covered_count=covered_count,
        partial_count=partial_count,
        gap_count=gap_count,
        coverage_percentage=round(coverage_pct, 2),
        function_summary=function_counts,
        subcategories=coverage_items,
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
    )


def get_function_mapping(function: str) -> list[RMFMapping]:
    """
    Return all subcategory mappings for a specific NIST AI RMF function.

    Parameters
    ----------
    function:
        NIST AI RMF function identifier: ``"GOVERN"``, ``"MAP"``,
        ``"MEASURE"``, or ``"MANAGE"``.

    Returns
    -------
    list[RMFMapping]
        Subcategory mappings for the requested function.
        Empty list if the function is not found.
    """
    subcategories = _load_subcategories()
    function_upper = function.upper()

    return [
        RMFMapping(
            subcategory_id=sub.id,
            title=sub.title,
            description=sub.description,
            aumos_protocols=list(sub.aumos_protocols),
            aumos_controls=list(sub.aumos_controls),
            coverage=sub.coverage,
            evidence_type=sub.evidence_type,
        )
        for sub in subcategories
        if sub.function_id == function_upper
    ]


# ── Framework class ───────────────────────────────────────────────────────────


class NISTAIRMFFramework(ComplianceFramework):
    """
    NIST AI Risk Management Framework (AI RMF 1.0) compliance framework.

    Covers the four core functions — GOVERN, MAP, MEASURE, MANAGE — and
    their subcategories as defined in NIST AI 100-1.

    Example::

        from compliance_mapper.frameworks.nist_ai_rmf import NISTAIRMFFramework
        from compliance_mapper.mapper import ComplianceMapper

        mapper = ComplianceMapper()
        report = mapper.map(governance_config, audit_log, [NISTAIRMFFramework()])
    """

    def __init__(self) -> None:
        self._subcategories: tuple[_RMFSubcategory, ...] | None = None

    @property
    def metadata(self) -> FrameworkMetadata:
        return FrameworkMetadata(
            id="nist-ai-rmf",
            name="NIST AI Risk Management Framework",
            version="1.0",
            source="National Institute of Standards and Technology (NIST) AI 100-1",
            scope_description=(
                "Four core functions — GOVERN, MAP, MEASURE, MANAGE — for identifying, "
                "assessing, and managing AI risks throughout the AI system lifecycle."
            ),
        )

    def _ensure_loaded(self) -> tuple[_RMFSubcategory, ...]:
        if self._subcategories is None:
            self._subcategories = _load_subcategories()
        return self._subcategories

    def list_control_ids(self) -> tuple[str, ...]:
        return tuple(s.id for s in self._ensure_loaded())

    def assess(
        self,
        governance_config: GovernanceConfig,
        audit_log: AuditLog,
        options: MapperOptions,
    ) -> tuple[ControlAssessment, ...]:
        """
        Assess all NIST AI RMF subcategories against the governance config.

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
            One assessment per NIST AI RMF subcategory.
        """
        subcategories = self._ensure_loaded()
        excluded_ids = set(options.exclude_control_ids)
        include_audit_event_gaps = options.include_audit_event_gaps
        report_timestamp = options.report_timestamp or datetime.now(tz=timezone.utc).isoformat()

        collector = EvidenceCollector(config=governance_config, audit_log=audit_log)
        generator = EvidenceGenerator()

        assessments: list[ControlAssessment] = []
        for sub in subcategories:
            is_excluded = sub.id in excluded_ids

            if is_excluded:
                collection = ControlEvidenceCollection(
                    control_id=sub.id,
                    config_resolutions=(),
                    audit_event_resolutions=(),
                    collected_at=report_timestamp,
                )
            else:
                collection = collector.collect_for_control(
                    control_id=sub.id,
                    required_config_paths=sub.governance_config_paths,
                    required_audit_events=sub.audit_log_events,
                )

            assessments.append(
                generator.generate_assessment(
                    AssessmentGenerationParams(
                        control_id=sub.id,
                        title=sub.title,
                        description=sub.description,
                        framework_id=self.metadata.id,
                        collection=collection,
                        include_audit_event_gaps=include_audit_event_gaps,
                        is_excluded=is_excluded,
                    )
                )
            )

        return tuple(assessments)
