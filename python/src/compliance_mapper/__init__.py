# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
compliance-mapper — Auto-generate SOC 2, GDPR, and EU AI Act compliance
evidence packages from governance configurations and structured audit logs.

Public API::

    from compliance_mapper import (
        ComplianceMapper,
        EvidenceCollector,
        EvidenceGenerator,
        SOC2Framework,
        GDPRFramework,
        EUAIActFramework,
        ReportGenerator,
    )

    # 1. Build your governance config and audit log.
    mapper = ComplianceMapper()
    report = mapper.map(
        governance_config,
        audit_log,
        [SOC2Framework(), GDPRFramework(), EUAIActFramework()],
    )

    # 2. Render to Markdown or JSON.
    generator = ReportGenerator()
    print(generator.to_markdown(report))
    print(generator.to_json(report))
"""

from __future__ import annotations

from compliance_mapper.evidence.collector import EvidenceCollector
from compliance_mapper.evidence.generator import EvidenceGenerator
from compliance_mapper.frameworks.eu_ai_act import EUAIActFramework
from compliance_mapper.frameworks.gdpr import GDPRFramework
from compliance_mapper.frameworks.interface import ComplianceFramework, FrameworkMetadata
from compliance_mapper.frameworks.soc2 import SOC2Framework
from compliance_mapper.mapper import ComplianceMapper
from compliance_mapper.report import (
    JsonRendererOptions,
    MarkdownRendererOptions,
    ReportGenerator,
)
from compliance_mapper.types import (
    AuditLog,
    AuditLogEntry,
    ComplianceReport,
    ControlAssessment,
    ControlStatus,
    EvidenceItem,
    EvidenceSourceKind,
    FrameworkResult,
    GapItem,
    GapSeverity,
    GovernanceConfig,
    MapperOptions,
    ReportSummary,
)

__all__ = [
    # ── Core ──────────────────────────────────────────────────────────────────
    "ComplianceMapper",
    # ── Frameworks ────────────────────────────────────────────────────────────
    "ComplianceFramework",
    "FrameworkMetadata",
    "SOC2Framework",
    "GDPRFramework",
    "EUAIActFramework",
    # ── Evidence ──────────────────────────────────────────────────────────────
    "EvidenceCollector",
    "EvidenceGenerator",
    # ── Reports ───────────────────────────────────────────────────────────────
    "ReportGenerator",
    "MarkdownRendererOptions",
    "JsonRendererOptions",
    # ── Types ─────────────────────────────────────────────────────────────────
    "GovernanceConfig",
    "AuditLog",
    "AuditLogEntry",
    "EvidenceItem",
    "EvidenceSourceKind",
    "ControlAssessment",
    "ControlStatus",
    "FrameworkResult",
    "GapItem",
    "GapSeverity",
    "ComplianceReport",
    "ReportSummary",
    "MapperOptions",
]
