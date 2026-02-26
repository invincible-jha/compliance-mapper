# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Example: Generate a SOC 2 Type II evidence package.

Demonstrates how to assess a governance configuration and audit log against
the AICPA Trust Services Criteria (2017) and render the result as Markdown.

Run from the repository root::

    python examples/generate_soc2_evidence.py
"""

from __future__ import annotations

import sys
import pathlib

# Allow running from the repo root without installing the package.
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "python" / "src"))

from compliance_mapper import (
    AuditLog,
    AuditLogEntry,
    ComplianceMapper,
    MapperOptions,
    MarkdownRendererOptions,
    ReportGenerator,
    SOC2Framework,
)

# ── Sample governance configuration ──────────────────────────────────────────
# A partial configuration that satisfies several SOC 2 controls.

GOVERNANCE_CONFIG: dict = {
    "governance": {
        "ethics": {
            "codeOfConduct": "https://example.com/code-of-conduct",
            "conflictOfInterestPolicy": "https://example.com/coi-policy",
        },
        "access": {
            "authenticationPolicy": "password-plus-mfa",
            "mfaPolicy": "required",
            # networkSegmentationPolicy intentionally absent to demo a gap.
            "userProvisioningProcess": "ticketing-system",
            "approvalWorkflow": "manager-plus-security",
            "accessRequestPolicy": "https://example.com/access-request",
            "rbacPolicy": "least-privilege",
            "leastPrivilegePolicy": "periodic-review",
            "privilegedAccessPolicy": "pam-enforced",
        },
        "incident": {
            "responsePolicy": "https://example.com/irp",
            "responseTeam": "security-team@example.com",
            "communicationPlan": "https://example.com/comms-plan",
        },
        "changeManagement": {
            "changePolicy": "https://example.com/change-policy",
            "approvalWorkflow": "two-approver",
            "testingRequirements": "ci-pipeline",
            # rollbackProcedure intentionally absent.
        },
        "business": {
            "bcpPolicy": "https://example.com/bcp",
            "rtoRpoTargets": "rto=4h,rpo=1h",
            # drTestSchedule intentionally absent.
        },
        "data": {
            "classificationPolicy": "https://example.com/data-class",
            # confidentialDataInventory intentionally absent.
            "labelingPolicy": "auto-tagging",
        },
        "privacy": {
            "privacyNoticeUrl": "https://example.com/privacy",
            "noticeReviewSchedule": "annual",
            "noticeLanguages": "en,de,fr",
            "consentManagement": "consent-platform-v2",
            "optOutMechanism": "https://example.com/opt-out",
            "consentRecordRetention": "7-years",
        },
    }
}

# ── Sample audit log ──────────────────────────────────────────────────────────

AUDIT_LOG = AuditLog(
    start_period="2025-10-01T00:00:00Z",
    end_period="2025-12-31T23:59:59Z",
    entries=(
        AuditLogEntry(
            timestamp="2025-10-15T09:00:00Z",
            event_type="ethics_training_completed",
            actor="hr-system",
            metadata={"completion_rate": 0.97},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-10-16T10:30:00Z",
            event_type="policy_acknowledged",
            actor="employee-portal",
            metadata={"policy_version": "2025-Q4"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-01T08:00:00Z",
            event_type="mfa_enforced",
            actor="idp-service",
            metadata={"users_enrolled": 412},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-03T14:22:00Z",
            event_type="user_provisioned",
            actor="hr-system",
            metadata={"user_id": "u-8821", "role": "engineer"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-03T14:25:00Z",
            event_type="access_approved",
            actor="security-team",
            metadata={"ticket": "SEC-1042"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-11-20T16:00:00Z",
            event_type="role_assigned",
            actor="iam-service",
            metadata={"role": "read-only-prod"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-05T11:00:00Z",
            event_type="incident_response_initiated",
            actor="security-on-call",
            metadata={"incident_id": "INC-0042", "severity": "P2"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-06T09:00:00Z",
            event_type="incident_resolved",
            actor="security-on-call",
            metadata={"incident_id": "INC-0042", "resolution": "patch-applied"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-10T14:00:00Z",
            event_type="change_requested",
            actor="eng-deploy-bot",
            metadata={"change_id": "CHG-2201"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-10T15:00:00Z",
            event_type="change_approved",
            actor="release-manager",
            metadata={"change_id": "CHG-2201"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-10T16:00:00Z",
            event_type="change_deployed",
            actor="ci-cd-pipeline",
            metadata={"change_id": "CHG-2201", "environment": "production"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-15T10:00:00Z",
            event_type="bcp_tested",
            actor="dr-team",
            metadata={"test_scenario": "regional-failover"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-15T12:00:00Z",
            event_type="data_classified",
            actor="dlp-service",
            metadata={"records_classified": 12_400},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2025-12-20T09:00:00Z",
            event_type="consent_obtained",
            actor="sign-up-flow",
            metadata={"consent_version": "v3"},
            outcome="success",
        ),
    ),
)


def main() -> None:
    mapper = ComplianceMapper()

    report = mapper.map(
        governance_config=GOVERNANCE_CONFIG,
        audit_log=AUDIT_LOG,
        frameworks=[SOC2Framework()],
        options=MapperOptions(include_audit_event_gaps=True),
    )

    generator = ReportGenerator()

    markdown = generator.to_markdown(
        report,
        MarkdownRendererOptions(
            report_title="SOC 2 Type II Evidence Package — Q4 2025",
            include_control_details=True,
            include_gap_analysis=True,
        ),
    )

    print(markdown)

    # ── Summary to stderr ─────────────────────────────────────────────────────
    summary = report.summary
    print(
        f"\n[Summary] Rate: {summary.overall_compliance_rate * 100:.1f}%  "
        f"Satisfied: {summary.total_satisfied}  "
        f"Gaps: {summary.total_gaps}  "
        f"Partial: {summary.total_partial}  "
        f"Critical: {summary.critical_gaps_count}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
