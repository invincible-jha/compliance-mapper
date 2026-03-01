# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Tests for compliance_mapper.types — Pydantic models and data structures.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from compliance_mapper.types import (
    AuditLog,
    AuditLogEntry,
    ComplianceFrameworkId,
    ComplianceRunConfig,
    ControlAssessment,
    EvidenceItem,
    FrameworkResult,
    GapItem,
    MapperOptions,
    ReportSummary,
)


class TestComplianceRunConfig:
    def test_valid_config_with_required_fields(self) -> None:
        config = ComplianceRunConfig(
            framework=ComplianceFrameworkId.SOC2,
            organization_name="Acme Corp",
        )
        assert config.framework == ComplianceFrameworkId.SOC2
        assert config.organization_name == "Acme Corp"
        assert config.output_format == "json"
        assert config.include_evidence is True

    def test_all_framework_ids_are_valid(self) -> None:
        for framework_id in ComplianceFrameworkId:
            config = ComplianceRunConfig(
                framework=framework_id,
                organization_name="Test Org",
            )
            assert config.framework == framework_id

    def test_empty_organization_name_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            ComplianceRunConfig(
                framework=ComplianceFrameworkId.SOC2,
                organization_name="",
            )

    def test_invalid_output_format_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            ComplianceRunConfig(
                framework=ComplianceFrameworkId.GDPR,
                organization_name="Acme Corp",
                output_format="docx",  # invalid
            )

    def test_valid_output_formats(self) -> None:
        for fmt in ("json", "pdf", "html"):
            config = ComplianceRunConfig(
                framework=ComplianceFrameworkId.GDPR,
                organization_name="Acme Corp",
                output_format=fmt,
            )
            assert config.output_format == fmt

    def test_trust_level_threshold_out_of_range_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            ComplianceRunConfig(
                framework=ComplianceFrameworkId.SOC2,
                organization_name="Acme Corp",
                trust_level_threshold=1.5,  # > 1.0, invalid
            )

    def test_trust_level_threshold_at_boundaries(self) -> None:
        config_zero = ComplianceRunConfig(
            framework=ComplianceFrameworkId.SOC2,
            organization_name="Acme Corp",
            trust_level_threshold=0.0,
        )
        config_one = ComplianceRunConfig(
            framework=ComplianceFrameworkId.EU_AI_ACT,
            organization_name="Acme Corp",
            trust_level_threshold=1.0,
        )
        assert config_zero.trust_level_threshold == 0.0
        assert config_one.trust_level_threshold == 1.0

    def test_audit_period_fields_are_optional(self) -> None:
        config = ComplianceRunConfig(
            framework=ComplianceFrameworkId.SOC2,
            organization_name="Acme Corp",
            audit_period_start="2026-01-01T00:00:00Z",
            audit_period_end="2026-12-31T23:59:59Z",
        )
        assert config.audit_period_start is not None
        assert config.audit_period_end is not None


class TestAuditLogEntry:
    def test_valid_entry_construction(self) -> None:
        entry = AuditLogEntry(
            timestamp="2026-01-01T10:00:00Z",
            event_type="mfa_enforced",
            actor="system",
            metadata={"policy": "TOTP"},
            outcome="success",
        )
        assert entry.event_type == "mfa_enforced"
        assert entry.outcome == "success"

    def test_entry_is_frozen_dataclass(self) -> None:
        entry = AuditLogEntry(
            timestamp="2026-01-01T10:00:00Z",
            event_type="mfa_enforced",
            actor="system",
            metadata={},
            outcome="success",
        )
        with pytest.raises((AttributeError, TypeError)):
            entry.actor = "mutated"  # type: ignore[misc]

    def test_resource_id_is_optional(self) -> None:
        entry = AuditLogEntry(
            timestamp="2026-01-01T10:00:00Z",
            event_type="audit_log_access",
            actor="admin",
            metadata={},
            outcome="success",
        )
        assert entry.resource_id is None


class TestAuditLog:
    def test_valid_audit_log_construction(self) -> None:
        log = AuditLog(
            start_period="2026-01-01T00:00:00Z",
            end_period="2026-01-31T23:59:59Z",
            entries=(),
        )
        assert log.start_period == "2026-01-01T00:00:00Z"
        assert len(log.entries) == 0


class TestMapperOptions:
    def test_default_values(self) -> None:
        options = MapperOptions()
        assert options.report_timestamp is None
        assert options.include_audit_event_gaps is True
        assert options.exclude_control_ids == ()

    def test_custom_values(self) -> None:
        options = MapperOptions(
            report_timestamp="2026-01-01T00:00:00Z",
            include_audit_event_gaps=False,
            exclude_control_ids=("CC1.1", "CC6.1"),
        )
        assert options.report_timestamp == "2026-01-01T00:00:00Z"
        assert options.include_audit_event_gaps is False
        assert "CC1.1" in options.exclude_control_ids
