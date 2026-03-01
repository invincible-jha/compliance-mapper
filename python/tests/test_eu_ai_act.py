# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Tests for EUAIActFramework — EU AI Act requirements mapping.
"""

from __future__ import annotations

from compliance_mapper.frameworks.eu_ai_act import EUAIActFramework
from compliance_mapper.types import AuditLog, GovernanceConfig, MapperOptions


class TestEUAIActFrameworkMetadata:
    def test_framework_id_is_eu_ai_act(self) -> None:
        framework = EUAIActFramework()
        assert framework.metadata.id == "eu_ai_act"

    def test_framework_has_non_empty_name(self) -> None:
        framework = EUAIActFramework()
        assert len(framework.metadata.name) > 0

    def test_framework_has_version(self) -> None:
        framework = EUAIActFramework()
        assert len(framework.metadata.version) > 0


class TestEUAIActFrameworkAssess:
    def test_assess_returns_non_empty_tuple(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = EUAIActFramework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        assert len(controls) > 0

    def test_all_controls_have_valid_statuses(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = EUAIActFramework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        valid_statuses = {"satisfied", "gap", "partial", "not_applicable"}
        for control in controls:
            assert control.status in valid_statuses

    def test_human_oversight_controls_appear_in_results(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = EUAIActFramework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        # EU AI Act requires human oversight — should be reflected in controls
        assert len(controls) > 0
        titles = [c.title.lower() for c in controls]
        has_oversight_or_transparency = any(
            "oversight" in title or "transparency" in title or "human" in title
            for title in titles
        )
        assert has_oversight_or_transparency

    def test_empty_config_produces_gaps_for_eu_ai_act(
        self,
        empty_governance_config: GovernanceConfig,
        empty_audit_log: AuditLog,
    ) -> None:
        framework = EUAIActFramework()
        controls = framework.assess(empty_governance_config, empty_audit_log, MapperOptions())
        gap_controls = [c for c in controls if c.status in ("gap", "partial")]
        assert len(gap_controls) > 0

    def test_minimal_config_with_agent_governance_paths_improves_compliance(
        self,
        minimal_governance_config: GovernanceConfig,
        empty_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = EUAIActFramework()
        options = MapperOptions()
        full_controls = framework.assess(minimal_governance_config, minimal_audit_log, options)
        empty_controls = framework.assess(empty_governance_config, minimal_audit_log, options)

        full_satisfied = sum(1 for c in full_controls if c.status == "satisfied")
        empty_satisfied = sum(1 for c in empty_controls if c.status == "satisfied")
        assert full_satisfied >= empty_satisfied

    def test_excluded_controls_are_not_applicable(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = EUAIActFramework()
        controls_default = framework.assess(
            minimal_governance_config, minimal_audit_log, MapperOptions()
        )
        if not controls_default:
            return

        first_control_id = controls_default[0].control_id
        options = MapperOptions(exclude_control_ids=(first_control_id,))
        controls_excluded = framework.assess(
            minimal_governance_config, minimal_audit_log, options
        )

        excluded = [c for c in controls_excluded if c.control_id == first_control_id]
        if excluded:
            assert excluded[0].status == "not_applicable"

    def test_evidence_attached_to_each_control(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = EUAIActFramework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        for control in controls:
            assert isinstance(control.evidence, tuple)
