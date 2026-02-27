# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Evidence package generator.

Produces structured evidence package manifests for compliance audits.  Collects
governance configuration snapshots, audit trail records, conformance test
results, and risk assessments into a single package manifest suitable for
auditor review.

Supported standards: SOC 2, GDPR, EU AI Act, ISO 42001, NIST AI RMF.

The generator produces a package *manifest* — a structured description of
what evidence is available and where it came from.  It does not create
actual ZIP archives; downstream tooling handles serialization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


# ── Pydantic v2 models ───────────────────────────────────────────────────────


class EvidenceArtifact(BaseModel):
    """A single evidence artifact within a package."""

    artifact_id: str = Field(description="Unique artifact identifier")
    title: str = Field(description="Human-readable artifact title")
    description: str = Field(description="Description of what this artifact demonstrates")
    artifact_type: Literal[
        "governance_config",
        "audit_trail",
        "conformance_test",
        "risk_assessment",
        "policy_document",
        "training_record",
        "impact_assessment",
    ] = Field(description="Classification of the artifact")
    source_path: str = Field(description="Source path or reference for the artifact")
    standards: list[str] = Field(description="Standards this artifact supports")
    collected_at: str = Field(description="ISO 8601 timestamp of collection")
    is_present: bool = Field(description="Whether the artifact was found and collected")
    content_hash: str | None = Field(
        default=None,
        description="SHA-256 hash of content for integrity verification",
    )


class PackageSection(BaseModel):
    """A section within the evidence package, grouped by evidence type."""

    section_id: str = Field(description="Section identifier")
    title: str = Field(description="Section title")
    description: str = Field(description="Section description")
    artifacts: list[EvidenceArtifact] = Field(description="Artifacts in this section")
    artifact_count: int = Field(description="Number of artifacts")
    present_count: int = Field(description="Number of present artifacts")


class EvidencePackage(BaseModel):
    """Complete evidence package manifest for compliance audit."""

    package_id: str = Field(description="Unique package identifier")
    title: str = Field(description="Package title")
    description: str = Field(description="Package description")
    standards: list[str] = Field(description="Standards covered by this package")
    generated_at: str = Field(description="ISO 8601 generation timestamp")
    assessment_period_start: str = Field(description="ISO 8601 start of assessment period")
    assessment_period_end: str = Field(description="ISO 8601 end of assessment period")
    sections: list[PackageSection] = Field(description="Package sections by evidence type")
    total_artifacts: int = Field(description="Total artifacts in the package")
    present_artifacts: int = Field(description="Artifacts that were found and collected")
    completeness_percentage: float = Field(
        description="Percentage of artifacts present (0.0–100.0)"
    )


class EvidenceConfig(BaseModel):
    """Configuration for evidence package generation."""

    standards: list[str] = Field(
        description="Standards to include (soc2, gdpr, eu-ai-act, iso-42001, nist-ai-rmf)"
    )
    assessment_period_start: str = Field(description="ISO 8601 start of assessment period")
    assessment_period_end: str = Field(description="ISO 8601 end of assessment period")
    governance_config_paths: list[str] = Field(
        default_factory=list,
        description="Governance config paths to check for evidence",
    )
    audit_event_types: list[str] = Field(
        default_factory=list,
        description="Audit event types to include as evidence",
    )
    include_risk_assessments: bool = Field(
        default=True,
        description="Whether to include risk assessment artifacts",
    )
    include_conformance_tests: bool = Field(
        default=True,
        description="Whether to include conformance test results",
    )
    package_title: str | None = Field(
        default=None,
        description="Optional custom package title",
    )


# ── Standard-specific evidence requirements ───────────────────────────────────

_STANDARD_EVIDENCE: dict[str, dict[str, list[tuple[str, str, str]]]] = {
    # standard -> section_type -> [(artifact_id_suffix, title, source_path)]
    "soc2": {
        "governance_config": [
            ("soc2-gc-001", "Ethics Code of Conduct", "governance.ethics.codeOfConduct"),
            ("soc2-gc-002", "Access Control Policy", "governance.access.authenticationPolicy"),
            ("soc2-gc-003", "Change Management Policy", "governance.changeManagement.changePolicy"),
            ("soc2-gc-004", "Incident Response Policy", "governance.incident.responsePolicy"),
            ("soc2-gc-005", "Risk Management Register", "governance.risk.riskRegister"),
        ],
        "audit_trail": [
            ("soc2-at-001", "Access Provisioning Log", "user_provisioned"),
            ("soc2-at-002", "Change Deployment Log", "change_deployed"),
            ("soc2-at-003", "Incident Response Log", "incident_response_initiated"),
        ],
        "conformance_test": [
            ("soc2-ct-001", "Access Control Test Results", "governance.controls.accessControlTest"),
            ("soc2-ct-002", "Change Management Test Results", "governance.controls.changeManagementTest"),
        ],
        "risk_assessment": [
            ("soc2-ra-001", "Annual Risk Assessment", "governance.risk.riskRegister"),
        ],
    },
    "gdpr": {
        "governance_config": [
            ("gdpr-gc-001", "Data Protection Policy", "governance.privacy.dataProtectionPolicy"),
            ("gdpr-gc-002", "Processing Records (Art 30)", "governance.privacy.processingRecords"),
            ("gdpr-gc-003", "Consent Management Configuration", "governance.privacy.consentManagement"),
            ("gdpr-gc-004", "Data Subject Access Process", "governance.privacy.dataSubjectAccessProcess"),
        ],
        "audit_trail": [
            ("gdpr-at-001", "Consent Collection Log", "consent_obtained"),
            ("gdpr-at-002", "Data Subject Request Log", "subject_access_request_received"),
            ("gdpr-at-003", "Breach Notification Log", "breach_notification_sent"),
        ],
        "risk_assessment": [
            ("gdpr-ra-001", "Data Protection Impact Assessment", "governance.privacy.dpiaResults"),
        ],
    },
    "eu-ai-act": {
        "governance_config": [
            ("euai-gc-001", "Risk Classification Record", "governance.ai.riskClassification"),
            ("euai-gc-002", "Technical Documentation Package", "governance.ai.technicalDocumentationRegister"),
            ("euai-gc-003", "Human Oversight Configuration", "governance.ai.humanOversightProcess"),
            ("euai-gc-004", "Transparency Documentation", "governance.ai.systemTransparencyDocument"),
        ],
        "audit_trail": [
            ("euai-at-001", "Risk Classification Log", "ai_risk_classification_completed"),
            ("euai-at-002", "Human Override Log", "human_override_exercised"),
            ("euai-at-003", "Accuracy Benchmark Log", "accuracy_benchmark_completed"),
        ],
        "conformance_test": [
            ("euai-ct-001", "Robustness Test Results", "governance.ai.robustnessTesting"),
            ("euai-ct-002", "Adversarial Test Results", "governance.ai.adversarialTestingPolicy"),
        ],
        "risk_assessment": [
            ("euai-ra-001", "AI Risk Management Plan", "governance.ai.riskManagementSystem"),
            ("euai-ra-002", "Bias Assessment Report", "governance.ai.biasAssessmentProcess"),
        ],
        "impact_assessment": [
            ("euai-ia-001", "AI System Impact Assessment", "governance.ai.impactAssessmentResults"),
        ],
    },
    "iso-42001": {
        "governance_config": [
            ("iso42-gc-001", "AI Policy Document", "governance.ai.aiPolicy"),
            ("iso42-gc-002", "AIMS Scope Statement", "governance.ai.aimsScope"),
            ("iso42-gc-003", "Leadership Commitment Attestation", "governance.ai.leadershipCommitment"),
            ("iso42-gc-004", "AI System Inventory", "governance.ai.aiSystemInventory"),
        ],
        "audit_trail": [
            ("iso42-at-001", "Management Review Log", "management_review_completed"),
            ("iso42-at-002", "Internal Audit Log", "internal_audit_completed"),
            ("iso42-at-003", "Corrective Action Log", "corrective_action_implemented"),
        ],
        "conformance_test": [
            ("iso42-ct-001", "AIMS Conformance Test Results", "governance.ai.aimsConformanceTest"),
        ],
        "risk_assessment": [
            ("iso42-ra-001", "AI Risk Assessment", "governance.ai.riskAssessmentMethodology"),
            ("iso42-ra-002", "AI Impact Assessment", "governance.ai.impactAssessmentPolicy"),
        ],
    },
    "nist-ai-rmf": {
        "governance_config": [
            ("nist-gc-001", "AI Governance Policy", "governance.ai.aiGovernancePolicy"),
            ("nist-gc-002", "Accountability Matrix", "governance.ai.accountabilityMatrix"),
            ("nist-gc-003", "System Purpose Statement", "governance.ai.systemPurposeStatement"),
        ],
        "audit_trail": [
            ("nist-at-001", "Governance Policy Approval Log", "governance_policy_approved"),
            ("nist-at-002", "Risk Prioritization Log", "risk_prioritized"),
            ("nist-at-003", "Stakeholder Engagement Log", "stakeholder_engagement_completed"),
        ],
        "risk_assessment": [
            ("nist-ra-001", "AI Risk Prioritization Matrix", "governance.ai.riskPrioritizationMatrix"),
            ("nist-ra-002", "Social Impact Assessment", "governance.ai.socialImpactAssessment"),
        ],
    },
}

# Section metadata for package organization.
_SECTION_METADATA: dict[str, tuple[str, str]] = {
    "governance_config": (
        "Governance Configuration Evidence",
        "Snapshots of governance configuration settings demonstrating control implementation.",
    ),
    "audit_trail": (
        "Audit Trail Records",
        "Audit log entries demonstrating operational compliance activities.",
    ),
    "conformance_test": (
        "Conformance Test Results",
        "Results from control testing and conformance verification activities.",
    ),
    "risk_assessment": (
        "Risk Assessments",
        "Risk assessment records demonstrating risk identification and treatment.",
    ),
    "policy_document": (
        "Policy Documents",
        "Formal policy documents supporting governance requirements.",
    ),
    "impact_assessment": (
        "Impact Assessments",
        "AI system impact assessments on individuals, groups, and society.",
    ),
}


# ── Generator ─────────────────────────────────────────────────────────────────


def _check_artifact_presence(
    source_path: str,
    governance_config_paths: list[str],
    audit_event_types: list[str],
) -> bool:
    """
    Check if an artifact source path is present in the provided evidence lists.

    A governance config artifact is present if its path appears in the
    governance_config_paths list.  An audit trail artifact is present if its
    event type appears in the audit_event_types list.
    """
    if source_path.startswith("governance."):
        return source_path in governance_config_paths
    return source_path in audit_event_types


def generate_evidence_package(config: EvidenceConfig) -> EvidencePackage:
    """
    Generate a structured evidence package manifest for compliance audit.

    Collects evidence artifacts from governance configurations, audit trail
    records, conformance test results, and risk assessments into a single
    structured manifest.

    Parameters
    ----------
    config:
        Configuration specifying which standards to cover, the assessment
        period, and available evidence sources.

    Returns
    -------
    EvidencePackage
        Structured package manifest with artifact inventory and completeness
        metrics.
    """
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    package_id = f"ep-{datetime.now(tz=timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    validated_standards = [
        s for s in config.standards if s in _STANDARD_EVIDENCE
    ]

    # Collect all artifacts grouped by section type.
    section_artifacts: dict[str, list[EvidenceArtifact]] = {}

    for standard in validated_standards:
        standard_sections = _STANDARD_EVIDENCE.get(standard, {})
        for section_type, artifact_defs in standard_sections.items():
            # Skip sections based on config flags.
            if section_type == "risk_assessment" and not config.include_risk_assessments:
                continue
            if section_type == "conformance_test" and not config.include_conformance_tests:
                continue

            if section_type not in section_artifacts:
                section_artifacts[section_type] = []

            for artifact_id_suffix, title, source_path in artifact_defs:
                is_present = _check_artifact_presence(
                    source_path,
                    config.governance_config_paths,
                    config.audit_event_types,
                )

                section_artifacts[section_type].append(
                    EvidenceArtifact(
                        artifact_id=artifact_id_suffix,
                        title=title,
                        description=f"Evidence artifact for {standard}: {title}",
                        artifact_type=section_type,  # type: ignore[arg-type]
                        source_path=source_path,
                        standards=[standard],
                        collected_at=now_iso,
                        is_present=is_present,
                        content_hash=None,
                    )
                )

    # Build package sections.
    sections: list[PackageSection] = []
    total_artifacts = 0
    present_artifacts = 0

    for section_type, artifacts in section_artifacts.items():
        section_title, section_desc = _SECTION_METADATA.get(
            section_type, (section_type.replace("_", " ").title(), "")
        )
        artifact_count = len(artifacts)
        present_count = sum(1 for a in artifacts if a.is_present)

        sections.append(
            PackageSection(
                section_id=section_type,
                title=section_title,
                description=section_desc,
                artifacts=artifacts,
                artifact_count=artifact_count,
                present_count=present_count,
            )
        )

        total_artifacts += artifact_count
        present_artifacts += present_count

    completeness_pct = (
        (present_artifacts / total_artifacts * 100.0)
        if total_artifacts > 0
        else 0.0
    )

    title = config.package_title or (
        f"Compliance Evidence Package — "
        f"{', '.join(s.upper().replace('-', ' ') for s in validated_standards)}"
    )

    return EvidencePackage(
        package_id=package_id,
        title=title,
        description=(
            f"Evidence package covering {len(validated_standards)} standard(s) "
            f"for the assessment period {config.assessment_period_start} to "
            f"{config.assessment_period_end}."
        ),
        standards=validated_standards,
        generated_at=now_iso,
        assessment_period_start=config.assessment_period_start,
        assessment_period_end=config.assessment_period_end,
        sections=sections,
        total_artifacts=total_artifacts,
        present_artifacts=present_artifacts,
        completeness_percentage=round(completeness_pct, 2),
    )
