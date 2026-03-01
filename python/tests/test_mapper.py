# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Tests for ComplianceMapper — the main mapping engine.
"""

from __future__ import annotations

import pytest

from compliance_mapper.frameworks.soc2 import SOC2Framework
from compliance_mapper.frameworks.gdpr import GDPRFramework
from compliance_mapper.frameworks.eu_ai_act import EUAIActFramework
from compliance_mapper.mapper import ComplianceMapper
from compliance_mapper.types import AuditLog, ComplianceReport, GovernanceConfig, MapperOptions


class TestComplianceMapperBasic:
    def test_map_raises_value_error_when_no_frameworks_supplied(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        with pytest.raises(ValueError, match="at least one framework"):
            mapper.map(minimal_governance_config, minimal_audit_log, [])

    def test_map_returns_compliance_report(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report = mapper.map(minimal_governance_config, minimal_audit_log, [SOC2Framework()])
        assert isinstance(report, ComplianceReport)

    def test_report_has_unique_report_id(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report_a = mapper.map(minimal_governance_config, minimal_audit_log, [SOC2Framework()])
        report_b = mapper.map(minimal_governance_config, minimal_audit_log, [SOC2Framework()])
        assert report_a.report_id != report_b.report_id

    def test_report_contains_one_framework_result_for_soc2(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report = mapper.map(minimal_governance_config, minimal_audit_log, [SOC2Framework()])
        assert len(report.framework_results) == 1
        assert report.framework_results[0].framework_id == "soc2"

    def test_report_contains_multiple_framework_results(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report = mapper.map(
            minimal_governance_config,
            minimal_audit_log,
            [SOC2Framework(), GDPRFramework(), EUAIActFramework()],
        )
        assert len(report.framework_results) == 3

    def test_report_summary_total_frameworks_matches_input(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        frameworks = [SOC2Framework(), GDPRFramework()]
        report = mapper.map(minimal_governance_config, minimal_audit_log, frameworks)
        assert report.summary.total_frameworks == 2

    def test_report_has_generated_at_timestamp(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report = mapper.map(minimal_governance_config, minimal_audit_log, [SOC2Framework()])
        assert report.generated_at
        # Should be a non-empty ISO 8601 string
        assert len(report.generated_at) > 0

    def test_report_uses_provided_timestamp_from_options(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        fixed_time = "2026-06-15T12:00:00+00:00"
        mapper = ComplianceMapper()
        options = MapperOptions(report_timestamp=fixed_time)
        report = mapper.map(minimal_governance_config, minimal_audit_log, [SOC2Framework()], options)
        assert report.generated_at == fixed_time

    def test_assessment_period_is_taken_from_audit_log(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report = mapper.map(minimal_governance_config, minimal_audit_log, [SOC2Framework()])
        assert report.assessment_period_start == minimal_audit_log.start_period
        assert report.assessment_period_end == minimal_audit_log.end_period


class TestComplianceMapperWithEmptyConfig:
    def test_empty_config_produces_gaps(
        self,
        empty_governance_config: GovernanceConfig,
        empty_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report = mapper.map(empty_governance_config, empty_audit_log, [SOC2Framework()])
        assert report.summary.total_gaps > 0

    def test_gaps_are_sorted_by_severity_critical_first(
        self,
        empty_governance_config: GovernanceConfig,
        empty_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report = mapper.map(
            empty_governance_config, empty_audit_log, [SOC2Framework(), GDPRFramework()]
        )
        if len(report.gaps) >= 2:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            for index in range(len(report.gaps) - 1):
                current_sev = severity_order.get(report.gaps[index].severity, 99)
                next_sev = severity_order.get(report.gaps[index + 1].severity, 99)
                assert current_sev <= next_sev

    def test_overall_compliance_rate_is_zero_or_low_for_empty_config(
        self,
        empty_governance_config: GovernanceConfig,
        empty_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report = mapper.map(empty_governance_config, empty_audit_log, [SOC2Framework()])
        assert report.summary.overall_compliance_rate < 1.0

    def test_compliance_rate_between_zero_and_one(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report = mapper.map(minimal_governance_config, minimal_audit_log, [SOC2Framework()])
        assert 0.0 <= report.summary.overall_compliance_rate <= 1.0


class TestComplianceMapperOptions:
    def test_exclude_control_ids_marks_controls_not_applicable(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        options = MapperOptions(exclude_control_ids=("CC1.1",))
        report = mapper.map(minimal_governance_config, minimal_audit_log, [SOC2Framework()], options)
        # Find the CC1.1 control and verify it is not_applicable
        soc2_result = report.framework_results[0]
        cc11_controls = [c for c in soc2_result.controls if c.control_id == "CC1.1"]
        if cc11_controls:
            assert cc11_controls[0].status == "not_applicable"

    def test_mapper_is_reusable_across_multiple_invocations(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        mapper = ComplianceMapper()
        report_a = mapper.map(minimal_governance_config, minimal_audit_log, [SOC2Framework()])
        report_b = mapper.map(minimal_governance_config, minimal_audit_log, [GDPRFramework()])
        assert report_a.framework_results[0].framework_id == "soc2"
        assert report_b.framework_results[0].framework_id == "gdpr"
