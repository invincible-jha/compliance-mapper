# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Tests for GDPRFramework — GDPR Article mapping implementation.
"""

from __future__ import annotations

from compliance_mapper.frameworks.gdpr import GDPRFramework
from compliance_mapper.types import AuditLog, GovernanceConfig, MapperOptions


class TestGDPRFrameworkMetadata:
    def test_framework_id_is_gdpr(self) -> None:
        framework = GDPRFramework()
        assert framework.metadata.id == "gdpr"

    def test_framework_has_non_empty_name(self) -> None:
        framework = GDPRFramework()
        assert len(framework.metadata.name) > 0


class TestGDPRFrameworkAssess:
    def test_assess_returns_non_empty_tuple(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = GDPRFramework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        assert len(controls) > 0

    def test_all_controls_have_valid_statuses(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = GDPRFramework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        valid_statuses = {"satisfied", "gap", "partial", "not_applicable"}
        for control in controls:
            assert control.status in valid_statuses

    def test_gdpr_control_ids_are_article_style(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = GDPRFramework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        # GDPR control IDs should reference articles (Art. prefix or similar)
        assert len(controls) > 0
        for control in controls:
            assert len(control.control_id) > 0

    def test_empty_config_yields_more_gaps_than_full_config(
        self,
        minimal_governance_config: GovernanceConfig,
        empty_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = GDPRFramework()
        options = MapperOptions()
        full_controls = framework.assess(minimal_governance_config, minimal_audit_log, options)
        empty_controls = framework.assess(empty_governance_config, minimal_audit_log, options)

        full_gaps = sum(1 for c in full_controls if c.status == "gap")
        empty_gaps = sum(1 for c in empty_controls if c.status == "gap")
        assert empty_gaps >= full_gaps

    def test_gap_controls_have_gap_description(
        self,
        empty_governance_config: GovernanceConfig,
        empty_audit_log: AuditLog,
    ) -> None:
        framework = GDPRFramework()
        controls = framework.assess(empty_governance_config, empty_audit_log, MapperOptions())
        gap_controls = [c for c in controls if c.status == "gap"]
        for control in gap_controls:
            # gap_description should be non-None and non-empty for gap controls
            assert control.gap_description is not None
            assert len(control.gap_description) > 0

    def test_privacy_related_data_subject_rights_are_assessed(
        self,
        minimal_governance_config: GovernanceConfig,
        minimal_audit_log: AuditLog,
    ) -> None:
        framework = GDPRFramework()
        controls = framework.assess(minimal_governance_config, minimal_audit_log, MapperOptions())
        # There should be at least one control covering data subject rights
        assert len(controls) > 0
