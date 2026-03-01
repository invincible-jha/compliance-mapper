# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Shared pytest fixtures for compliance-mapper tests.
"""

from __future__ import annotations

import pytest

from compliance_mapper.types import AuditLog, AuditLogEntry, GovernanceConfig


@pytest.fixture
def minimal_governance_config() -> GovernanceConfig:
    """A minimal governance configuration with the most common paths set."""
    return {
        "governance": {
            "access": {
                "authenticationPolicy": "strict",
                "mfaPolicy": "enforced",
                "networkSegmentationPolicy": "enabled",
                "privilegedAccessManagement": "enabled",
            },
            "audit": {
                "enabled": True,
                "retentionDays": 365,
                "immutableStorage": True,
            },
            "ethics": {
                "codeOfConduct": "published",
                "conflictOfInterestPolicy": "active",
                "organization": {"leadershipAttestation": "signed"},
            },
            "dataProtection": {
                "encryptionAtRest": True,
                "encryptionInTransit": True,
                "dataClassificationPolicy": "active",
            },
            "incidentResponse": {
                "plan": "documented",
                "contactList": "maintained",
            },
        },
        "privacy": {
            "dataSubjectRightsPolicy": "active",
            "consentManagement": {"enabled": True},
            "dataMinimisation": {"enabled": True},
        },
        "agentGovernance": {
            "purposeLimitation": {"enabled": True},
            "humanOversight": {"enabled": True},
            "riskAssessment": {"required": True},
            "transparencyStatement": "published",
        },
    }


@pytest.fixture
def empty_governance_config() -> GovernanceConfig:
    """An empty governance configuration (no paths set)."""
    return {}


@pytest.fixture
def minimal_audit_log() -> AuditLog:
    """A minimal audit log with a few representative entries."""
    entries = (
        AuditLogEntry(
            timestamp="2026-01-01T10:00:00Z",
            event_type="mfa_enforced",
            actor="system",
            metadata={"policy": "TOTP"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2026-01-02T10:00:00Z",
            event_type="access_attempt",
            actor="user-001",
            metadata={"resource": "dashboard"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2026-01-03T10:00:00Z",
            event_type="audit_log_access",
            actor="admin",
            metadata={"target_log": "access_log"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2026-01-04T10:00:00Z",
            event_type="data_subject_request",
            actor="user-002",
            metadata={"request_type": "access"},
            outcome="success",
        ),
        AuditLogEntry(
            timestamp="2026-01-05T10:00:00Z",
            event_type="consent_recorded",
            actor="user-003",
            metadata={"purpose": "analytics"},
            outcome="success",
        ),
    )
    return AuditLog(
        start_period="2026-01-01T00:00:00Z",
        end_period="2026-01-31T23:59:59Z",
        entries=entries,
    )


@pytest.fixture
def empty_audit_log() -> AuditLog:
    """An audit log with no entries."""
    return AuditLog(
        start_period="2026-01-01T00:00:00Z",
        end_period="2026-01-31T23:59:59Z",
        entries=(),
    )
