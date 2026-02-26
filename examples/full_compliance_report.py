# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Example: Full multi-framework compliance report.

Runs SOC 2 Type II, GDPR, and EU AI Act assessments in a single mapper
invocation and writes both a Markdown report and a JSON summary to disk.

Run from the repository root::

    python examples/full_compliance_report.py

Output files are written to the current working directory:
- compliance_report.md
- compliance_report_summary.json
"""

from __future__ import annotations

import json
import pathlib
import sys

# Allow running from the repo root without installing the package.
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "python" / "src"))

from compliance_mapper import (
    AuditLog,
    AuditLogEntry,
    ComplianceMapper,
    EUAIActFramework,
    GDPRFramework,
    JsonRendererOptions,
    MapperOptions,
    MarkdownRendererOptions,
    ReportGenerator,
    SOC2Framework,
)

# ── Governance configuration ──────────────────────────────────────────────────
# A realistic partial configuration for an AI-enabled SaaS service.

GOVERNANCE_CONFIG: dict = {
    "governance": {
        "ethics": {
            "codeOfConduct": "https://example.com/code-of-conduct",
            "conflictOfInterestPolicy": "https://example.com/coi",
            "whistleblowerPolicy": "https://example.com/whistleblower",
        },
        "organization": {
            "leadershipAttestation": "signed-2025-10-01",
            "boardComposition": "7-members-3-independent",
            "auditCommittee": "established",
            "orgChart": "https://example.com/org-chart",
            "roleDefinitions": "https://example.com/roles",
        },
        "oversight": {
            "reviewFrequency": "quarterly",
        },
        "hr": {
            "hiringPolicy": "https://example.com/hiring",
            "backgroundCheckPolicy": "level-2",
            "trainingRequirements": "annual-security-privacy",
        },
        "access": {
            "authenticationPolicy": "sso-plus-mfa",
            "mfaPolicy": "required",
            "networkSegmentationPolicy": "micro-segmentation",
            "userProvisioningProcess": "automated-via-hris",
            "approvalWorkflow": "manager-plus-security",
            "accessRequestPolicy": "self-service-portal",
            "rbacPolicy": "least-privilege",
            "leastPrivilegePolicy": "quarterly-review",
            "privilegedAccessPolicy": "pam-vault",
            "offboardingProcess": "automated-48h",
            "accountDeactivationSLA": "1-business-day",
            "defaultAccessRestriction": "deny-all",
        },
        "incident": {
            "responsePolicy": "https://example.com/irp",
            "responseTeam": "security-on-call",
            "communicationPlan": "https://example.com/comms",
            "triageProcess": "severity-matrix",
            "classificationCriteria": "p1-p4",
            "recoveryProcedures": "runbook-library",
        },
        "changeManagement": {
            "changePolicy": "https://example.com/change-mgmt",
            "approvalWorkflow": "two-approver",
            "testingRequirements": "ci-green",
            "rollbackProcedure": "blue-green-deployment",
            "changeRiskPolicy": "risk-tiered",
            "impactAssessmentProcess": "automated-blast-radius",
        },
        "business": {
            "bcpPolicy": "https://example.com/bcp",
            "rtoRpoTargets": "rto=4h,rpo=30m",
            "drTestSchedule": "bi-annual",
        },
        "data": {
            "classificationPolicy": "https://example.com/data-class",
            "confidentialDataInventory": "https://example.com/data-inventory",
            "labelingPolicy": "auto-tagging",
            "retentionPolicy": "https://example.com/retention",
            "retentionSchedule": "7-years-financial-3-years-operational",
            "disposalPolicy": "nist-800-88",
            "encryptionPolicy": "aes-256",
            "encryptionAtRestPolicy": "aes-256-gcm",
            "encryptionInTransitPolicy": "tls-1.3-only",
            "pseudonymisationPolicy": "k-anonymity-k5",
            "accuracyPolicy": "https://example.com/accuracy",
            "qualityPolicy": "completeness-consistency-timeliness",
            "minimizationByDefault": "opt-in",
            "personalDataInTrainingPolicy": "pseudonymised-only",
        },
        "privacy": {
            "privacyNoticeUrl": "https://example.com/privacy",
            "noticeReviewSchedule": "annual",
            "noticeLanguages": "en,de,fr,es",
            "consentManagement": "consent-platform-v3",
            "optOutMechanism": "https://example.com/opt-out",
            "consentRecordRetention": "7-years",
            "withdrawalMechanism": "one-click-withdrawal",
            "granularConsentOptions": "marketing,analytics,personalization,essential",
            "dataSubjectAccessProcess": "privacy-portal",
            "accessResponseSLA": "30-days",
            "identityVerificationProcess": "id-document-plus-email",
            "accessFulfillmentProcess": "automated-export",
            "erasureProcess": "scheduled-deletion-pipeline",
            "erasureSLA": "30-days",
            "thirdPartyErasureNotification": "automated-via-dpa",
            "processingPurposes": "service-delivery,analytics,product-improvement",
            "lawfulBasisRegister": "https://example.com/lawful-basis",
            "minimizationPolicy": "collect-only-required",
            "accountabilityRecord": "https://example.com/ropa",
            "legitimateInterestAssessments": "https://example.com/lia",
            "privacyByDesignProcess": "mandatory-pbt-gate",
            "dpiaProcess": "threshold-assessment-first",
            "dpiaThresholdCriteria": "high-risk-processing-types",
            "dpiaRegister": "https://example.com/dpia-register",
            "dpoReviewProcess": "dpo-sign-off-required",
            "dpoContact": "dpo@example.com",
            "thirdPartyDisclosurePolicy": "dpa-required",
            "dataProcessingAgreements": "https://example.com/dpa-template",
            "breachNotificationProcess": "72h-to-supervisory-authority",
        },
        "security": {
            "firewallPolicy": "allowlist-only",
            "accessControlPolicy": "rbac-sod",
            "penetrationTestingSchedule": "annual",
            "vulnerabilityManagementPolicy": "https://example.com/vuln-mgmt",
            "aiSystemSecurityPolicy": "https://example.com/ai-security",
        },
        "sdlc": {
            "privacyReview": "mandatory-pre-launch",
        },
        "monitoring": {
            "controlTestingSchedule": "quarterly",
            "siemConfig": "splunk-cloud",
        },
        "ai": {
            "riskClassification": "high-risk-annex-3",
            "complianceFramework": "eu-ai-act-chapter-2",
            "highRiskDesignation": "confirmed-2025-09-15",
            "riskManagementSystem": "https://example.com/ai-rms",
            "riskRegister": "https://example.com/ai-risk-register",
            "misuseScenariosRegister": "https://example.com/misuse-register",
            "riskMitigationMeasures": "https://example.com/mitigations",
            "residualRiskAcceptanceCriteria": "dpo-plus-cto-sign-off",
            "postMarketMonitoringPlan": "https://example.com/post-market",
            "dataGovernancePolicy": "https://example.com/ai-data-gov",
            "trainingDataRegister": "https://example.com/training-data",
            "dataQualityPolicy": "completeness-representativeness",
            "biasAssessmentProcess": "pre-training-post-training",
            "dataLineageTracking": "mlflow-lineage",
            "dataGapsRegister": "https://example.com/data-gaps",
            "technicalDocumentationRegister": "https://example.com/tech-docs",
            "systemArchitectureDocument": "https://example.com/architecture",
            "modelCard": "https://example.com/model-card",
            "validationResults": "https://example.com/validation",
            "standardsCompliance": "iso-42001",
            "changeManagementPolicy": "https://example.com/ai-change-mgmt",
            "auditLoggingPolicy": "all-decisions-logged",
            "logRetentionPolicy": "5-years",
            "logIntegrityControls": "immutable-append-only",
            "operationalLogFormat": "opentelemetry",
            "logAccessControls": "rbac-audit-team-only",
            "systemTransparencyDocument": "https://example.com/ai-transparency",
            "deployerInstructionsForUse": "https://example.com/ifu",
            "capabilitiesLimitationsDocument": "https://example.com/caps-limits",
            "performanceMetricsRegister": "https://example.com/perf-metrics",
            "knownRisksDocument": "https://example.com/known-risks",
            "humanOversightGuidance": "https://example.com/oversight-guide",
            "humanOversightProcess": "human-in-the-loop-required",
            "overrideCapability": "operator-override-button",
            "haltCapability": "emergency-stop-api",
            "humanReviewTriggers": "confidence-below-threshold",
            "operatorTrainingRequirements": "annual-certification",
            "automationBiasControls": "uncertainty-highlighting",
            "automatedDecisionRegister": "https://example.com/adr",
            "profilingPolicy": "https://example.com/profiling-policy",
            "explainabilityProcess": "shap-plus-lime",
            # accuracyMetrics intentionally absent to demo a gap.
            "robustnessTesting": "adversarial-benchmark-suite",
            # adversarialTestingPolicy intentionally absent.
            "modelValidationPolicy": "https://example.com/model-validation",
            "driftMonitoringPolicy": "evidently-ai-weekly",
            "fallbackMechanisms": "rule-based-fallback",
        },
    }
}

# ── Audit log ─────────────────────────────────────────────────────────────────

AUDIT_LOG = AuditLog(
    start_period="2025-10-01T00:00:00Z",
    end_period="2025-12-31T23:59:59Z",
    entries=(
        # SOC 2 events
        AuditLogEntry(
            timestamp="2025-10-02T09:00:00Z",
            event_type="ethics_training_completed",
            actor="hr-system",
            metadata={"completion_rate": 0.99},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-03T10:00:00Z",
            event_type="policy_acknowledged",
            actor="employee-portal",
            metadata={"policy": "code-of-conduct-2025"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-05T08:00:00Z",
            event_type="mfa_enforced",
            actor="idp-service",
            metadata={"users": 560},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-10T09:00:00Z",
            event_type="user_provisioned",
            actor="hris-integration",
            metadata={"user_id": "u-9912"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-10T09:05:00Z",
            event_type="access_approved",
            actor="security-team",
            metadata={"ticket": "SEC-2200"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-20T10:00:00Z",
            event_type="role_assigned",
            actor="iam-service",
            metadata={"role": "data-analyst-prod"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-15T14:00:00Z",
            event_type="incident_response_initiated",
            actor="security-on-call",
            metadata={"incident_id": "INC-0099"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-16T10:00:00Z",
            event_type="incident_resolved",
            actor="security-on-call",
            metadata={"incident_id": "INC-0099"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-16T16:00:00Z",
            event_type="postmortem_completed",
            actor="eng-team",
            metadata={"incident_id": "INC-0099"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-01T09:00:00Z",
            event_type="change_requested",
            actor="eng-bot",
            metadata={"change_id": "CHG-3300"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-01T10:00:00Z",
            event_type="change_approved",
            actor="release-manager",
            metadata={"change_id": "CHG-3300"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-01T11:00:00Z",
            event_type="change_tested",
            actor="ci-pipeline",
            metadata={"change_id": "CHG-3300"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-01T12:00:00Z",
            event_type="change_deployed",
            actor="ci-pipeline",
            metadata={"change_id": "CHG-3300"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-10T08:00:00Z",
            event_type="bcp_tested",
            actor="dr-team",
            metadata={"scenario": "east-west-failover"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-10T10:00:00Z",
            event_type="dr_exercise_completed",
            actor="dr-team",
            metadata={"rto_achieved": "3h45m"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-12T09:00:00Z",
            event_type="data_classified",
            actor="dlp-service",
            metadata={"records": 24_000},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-15T09:00:00Z",
            event_type="consent_obtained",
            actor="sign-up-flow",
            metadata={"consent_version": "v4"},
            outcome="success",
        ),
        # GDPR events
        AuditLogEntry(
            timestamp="2025-10-01T08:00:00Z",
            event_type="lawful_basis_documented",
            actor="privacy-officer",
            metadata={"ropa_version": "2025-Q4"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-05T09:00:00Z",
            event_type="lawful_basis_applied",
            actor="data-platform",
            metadata={"activity": "analytics"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-08T10:00:00Z",
            event_type="lia_completed",
            actor="privacy-officer",
            metadata={"activity": "email-retargeting"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-15T09:00:00Z",
            event_type="consent_recorded",
            actor="sign-up-flow",
            metadata={"consent_version": "v4"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-01T09:00:00Z",
            event_type="access_request_received",
            actor="privacy-portal",
            metadata={"request_id": "SAR-0120"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-29T16:00:00Z",
            event_type="access_request_fulfilled",
            actor="privacy-portal",
            metadata={"request_id": "SAR-0120"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-03T09:00:00Z",
            event_type="erasure_request_received",
            actor="privacy-portal",
            metadata={"request_id": "DEL-0044"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-20T14:00:00Z",
            event_type="data_erased",
            actor="deletion-pipeline",
            metadata={"request_id": "DEL-0044"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-21T09:00:00Z",
            event_type="third_party_erasure_notified",
            actor="privacy-portal",
            metadata={"vendors_notified": 3},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-05T10:00:00Z",
            event_type="automated_decision_made",
            actor="recommendation-engine",
            metadata={"model": "reco-v5"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-05T10:01:00Z",
            event_type="human_review_triggered",
            actor="oversight-service",
            metadata={"case_id": "ADR-0088"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-08T14:00:00Z",
            event_type="privacy_by_design_review_completed",
            actor="sdlc-gate",
            metadata={"feature": "ai-scoring"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-15T09:00:00Z",
            event_type="security_assessment_completed",
            actor="security-team",
            metadata={"scope": "gdpr-art32"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-16T10:00:00Z",
            event_type="encryption_verified",
            actor="security-team",
            metadata={"scope": "all-datastores"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-18T09:00:00Z",
            event_type="dpia_completed",
            actor="privacy-officer",
            metadata={"dpia_id": "DPIA-2025-003"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-19T11:00:00Z",
            event_type="dpia_approved",
            actor="dpo",
            metadata={"dpia_id": "DPIA-2025-003"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-22T10:00:00Z",
            event_type="retention_enforced",
            actor="data-lifecycle",
            metadata={"purged_records": 8_200},
            outcome="success",
        ),
        # EU AI Act events
        AuditLogEntry(
            timestamp="2025-10-01T10:00:00Z",
            event_type="ai_risk_classification_completed",
            actor="ai-governance-team",
            metadata={"system": "recommendation-engine"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-01T11:00:00Z",
            event_type="high_risk_designation_confirmed",
            actor="legal-team",
            metadata={"annex": "III-2"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-10T09:00:00Z",
            event_type="ai_risk_review_completed",
            actor="ai-governance-team",
            metadata={"quarter": "Q4-2025"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-15T10:00:00Z",
            event_type="misuse_scenario_assessed",
            actor="red-team",
            metadata={"scenarios_assessed": 12},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-01T09:00:00Z",
            event_type="training_data_assessed",
            actor="data-science-team",
            metadata={"dataset_version": "v3.1"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-10T10:00:00Z",
            event_type="bias_evaluation_completed",
            actor="fairness-team",
            metadata={"metrics": "equalized-odds"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-15T09:00:00Z",
            event_type="data_quality_check_passed",
            actor="data-quality-service",
            metadata={"completeness": 0.998},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-20T10:00:00Z",
            event_type="technical_documentation_completed",
            actor="ai-governance-team",
            metadata={"doc_version": "1.2"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-25T09:00:00Z",
            event_type="ai_system_log_generated",
            actor="logging-service",
            metadata={"log_volume_mb": 2_400},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-01T09:00:00Z",
            event_type="transparency_documentation_updated",
            actor="ai-governance-team",
            metadata={"doc": "ifu-v1.3"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-05T14:00:00Z",
            event_type="human_override_exercised",
            actor="operator-team",
            metadata={"case_id": "OVR-0012"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-10T11:00:00Z",
            event_type="human_review_performed",
            actor="review-team",
            metadata={"reviewed_decisions": 48},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-18T09:00:00Z",
            event_type="robustness_test_passed",
            actor="test-team",
            metadata={"test_suite": "adversarial-v2"},
            outcome="success",
        ),
    ),
)


def main() -> None:
    mapper = ComplianceMapper()

    report = mapper.map(
        governance_config=GOVERNANCE_CONFIG,
        audit_log=AUDIT_LOG,
        frameworks=[SOC2Framework(), GDPRFramework(), EUAIActFramework()],
        options=MapperOptions(include_audit_event_gaps=True),
    )

    generator = ReportGenerator()

    # Write full Markdown report to disk.
    markdown = generator.to_markdown(
        report,
        MarkdownRendererOptions(
            report_title="Full Compliance Evidence Report — Q4 2025",
            include_control_details=True,
            include_gap_analysis=True,
        ),
    )
    output_md = pathlib.Path("compliance_report.md")
    output_md.write_text(markdown, encoding="utf-8")
    print(f"Markdown report written to: {output_md.resolve()}", file=sys.stderr)

    # Write compact JSON summary (no evidence arrays) to disk.
    report_json = generator.to_json(
        report,
        JsonRendererOptions(indent=2, include_evidence=False),
    )
    output_json = pathlib.Path("compliance_report_summary.json")
    output_json.write_text(report_json, encoding="utf-8")
    print(f"JSON summary written to: {output_json.resolve()}", file=sys.stderr)

    # Print framework-level results to stdout.
    summary = report.summary
    print(f"\nReport ID: {report.report_id}")
    print(f"Generated: {report.generated_at}")
    print(
        f"Overall compliance rate: {summary.overall_compliance_rate * 100:.1f}% "
        f"({summary.total_satisfied}/{summary.total_controls - sum(r.not_applicable_count for r in report.framework_results)} assessed)"
    )
    print(f"Critical gaps: {summary.critical_gaps_count}")

    print("\nFramework results:")
    for result in report.framework_results:
        rate = (
            result.satisfied_count / (result.total_count - result.not_applicable_count)
            if (result.total_count - result.not_applicable_count) > 0
            else 0.0
        )
        print(
            f"  {result.framework_name} ({result.framework_version}): "
            f"{rate * 100:.0f}% — "
            f"{result.satisfied_count} satisfied, "
            f"{result.gap_count} gaps, "
            f"{result.partial_count} partial"
        )


if __name__ == "__main__":
    main()
