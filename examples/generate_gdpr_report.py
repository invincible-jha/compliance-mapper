# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Example: Generate a GDPR compliance report.

Demonstrates how to assess a governance configuration and audit log against
Regulation (EU) 2016/679, render the report as JSON, and print a gap summary
to the console.

Run from the repository root::

    python examples/generate_gdpr_report.py
"""

from __future__ import annotations

import json
import sys
import pathlib

# Allow running from the repo root without installing the package.
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "python" / "src"))

from compliance_mapper import (
    AuditLog,
    AuditLogEntry,
    ComplianceMapper,
    GDPRFramework,
    JsonRendererOptions,
    MapperOptions,
    ReportGenerator,
)

# ── Sample governance configuration ──────────────────────────────────────────
# Partially configured — Art17 erasure process and Art35 DPIA register are gaps.

GOVERNANCE_CONFIG: dict = {
    "governance": {
        "privacy": {
            "processingPurposes": "service-delivery,analytics",
            "lawfulBasisRegister": "https://example.com/lawful-basis",
            "minimizationPolicy": "collect-only-required",
            "accountabilityRecord": "https://example.com/ropa",
            "consentManagement": "consent-platform-v2",
            "consentRecordRetention": "7-years",
            "withdrawalMechanism": "https://example.com/withdraw-consent",
            "granularConsentOptions": "marketing,analytics,essential",
            "dataSubjectAccessProcess": "privacy-portal",
            "accessResponseSLA": "30-days",
            "identityVerificationProcess": "id-plus-email",
            "accessFulfillmentProcess": "automated-export",
            "legitimateInterestAssessments": "https://example.com/lia",
            # erasureProcess intentionally absent (Art17 gap).
            "privacyByDesignProcess": "sdlc-privacy-checklist",
            # dpiaProcess intentionally absent (Art35 gap).
            "dpoContact": "dpo@example.com",
        },
        "data": {
            "retentionSchedule": "https://example.com/retention",
            "accuracyPolicy": "https://example.com/accuracy",
            "encryptionPolicy": "aes-256-at-rest",
            "pseudonymisationPolicy": "k-anonymity",
            "encryptionAtRestPolicy": "aes-256",
            "encryptionInTransitPolicy": "tls-1.3",
            # backupErasurePolicy intentionally absent (Art17 gap).
            "minimizationByDefault": "opt-in-by-default",
        },
        "sdlc": {
            "privacyReview": "mandatory-pbt",
        },
        "access": {
            "defaultAccessRestriction": "deny-all-except-granted",
        },
        "security": {
            "accessControlPolicy": "rbac",
            "penetrationTestingSchedule": "annual",
            "vulnerabilityManagementPolicy": "https://example.com/vuln-mgmt",
        },
        "business": {
            "bcpPolicy": "https://example.com/bcp",
        },
        "ai": {
            "automatedDecisionRegister": "https://example.com/adr",
            "humanOversightProcess": "human-in-the-loop",
            "profilingPolicy": "https://example.com/profiling",
            "explainabilityProcess": "shap-values",
        },
    }
}

# ── Sample audit log ──────────────────────────────────────────────────────────

AUDIT_LOG = AuditLog(
    start_period="2025-10-01T00:00:00Z",
    end_period="2025-12-31T23:59:59Z",
    entries=(
        AuditLogEntry(
            timestamp="2025-10-01T08:00:00Z",
            event_type="lawful_basis_documented",
            actor="privacy-officer",
            metadata={"ropa_version": "2025-Q4"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-10T09:00:00Z",
            event_type="lawful_basis_applied",
            actor="data-platform",
            metadata={"processing_activity": "analytics"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-12T10:00:00Z",
            event_type="lia_completed",
            actor="privacy-officer",
            metadata={"activity": "email-marketing"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-15T11:00:00Z",
            event_type="consent_recorded",
            actor="sign-up-flow",
            metadata={"consent_version": "v3"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-01T14:00:00Z",
            event_type="access_request_received",
            actor="privacy-portal",
            metadata={"request_id": "SAR-0088"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-28T16:00:00Z",
            event_type="access_request_fulfilled",
            actor="privacy-portal",
            metadata={"request_id": "SAR-0088"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-02T09:00:00Z",
            event_type="automated_decision_made",
            actor="recommendation-engine",
            metadata={"model_version": "v4.1"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-02T09:01:00Z",
            event_type="human_review_triggered",
            actor="oversight-service",
            metadata={"case_id": "ADR-0021"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-10T10:00:00Z",
            event_type="privacy_by_design_review_completed",
            actor="sdlc-gate",
            metadata={"feature": "profile-matching"},
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
            timestamp="2025-12-20T14:00:00Z",
            event_type="retention_enforced",
            actor="data-lifecycle-service",
            metadata={"records_purged": 4_210},
            outcome="success",
        ),
    ),
)


def main() -> None:
    mapper = ComplianceMapper()

    report = mapper.map(
        governance_config=GOVERNANCE_CONFIG,
        audit_log=AUDIT_LOG,
        frameworks=[GDPRFramework()],
        options=MapperOptions(include_audit_event_gaps=True),
    )

    generator = ReportGenerator()

    # Render compact JSON without evidence arrays for easy inspection.
    report_json = generator.to_json(
        report,
        JsonRendererOptions(indent=2, include_evidence=False),
    )
    print(report_json)

    # ── Gap summary to stderr ─────────────────────────────────────────────────
    print("\n--- Gap Summary ---", file=sys.stderr)
    for gap in report.gaps:
        severity = gap.severity.upper()
        print(
            f"[{severity}] {gap.framework_id}/{gap.control_id}: {gap.control_title}",
            file=sys.stderr,
        )
        print(f"  Recommendation: {gap.recommendation}", file=sys.stderr)

    summary = report.summary
    print(
        f"\n[Summary] Rate: {summary.overall_compliance_rate * 100:.1f}%  "
        f"Critical gaps: {summary.critical_gaps_count}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
