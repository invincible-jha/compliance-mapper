# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Tests for SOC2Framework — SOC 2 TSC mapping implementation.
"""

from __future__ import annotations

from compliance_mapper.frameworks.soc2 import SOC2Framework
from compliance_mapper.types import AuditLog, GovernanceConfig, MapperOptions


class TestSOC2FrameworkMetadata:
    def test_framework_id_is_soc2(self) -> None:
        framework = SOC2Framework()
        assert framework.metadata.id == "soc2"

    def test_framework_has_non_empty_name(self) -> None:
        framework = SOC2Framework()
        assert len(framework.metadata.name) > 0

    def test_framework_has_non_empty_version(self) -> None:
        framework = SOC2Framework()
        assert len(framework.metadata.version) > 0


class TestSOC2FrameworkAssess:
    def test_assess_returns_tuple_of_control_assessments(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = SOC2Framework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        assert isinstance(controls, tuple)
        assert len(controls) > 0

    def test_each_control_has_an_id_and_title(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = SOC2Framework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        for control in controls:
            assert control.control_id
            assert control.title

    def test_control_status_is_one_of_expected_values(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = SOC2Framework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        valid_statuses = {"satisfied", "gap", "partial", "not_applicable"}
        for control in controls:
            assert control.status in valid_statuses

    def test_full_config_increases_satisfied_count_over_empty_config(
        self,
        minimal_governance_config: GovernanceConfig,
        empty_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = SOC2Framework()
        options = MapperOptions()
        full_controls = framework.assess(minimal_governance_config, minimal_audit_log, options)
        empty_controls = framework.assess(empty_governance_config, minimal_audit_log, options)

        full_satisfied = sum(1 for c in full_controls if c.status == "satisfied")
        empty_satisfied = sum(1 for c in empty_controls if c.status == "satisfied")
        assert full_satisfied >= empty_satisfied

    def test_excluded_control_is_marked_not_applicable(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = SOC2Framework()
        options = MapperOptions(exclude_control_ids=("CC6.1",))
        controls = framework.assess(minimal_governance_config, minimal_audit_log, options)
        cc61_controls = [c for c in controls if c.control_id == "CC6.1"]
        if cc61_controls:
            assert cc61_controls[0].status == "not_applicable"

    def test_evidence_is_attached_to_each_control(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = SOC2Framework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        for control in controls:
            assert isinstance(control.evidence, tuple)

    def test_assess_with_empty_config_produces_gap_controls(
        self,
        empty_governance_config: GovernanceConfig,
        empty_audit_log: AuditLog,
    ) -> None:
        framework = SOC2Framework()
        controls = framework.assess(empty_governance_config, empty_audit_log, MapperOptions())
        gap_controls = [c for c in controls if c.status in ("gap", "partial")]
        assert len(gap_controls) > 0
