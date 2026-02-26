# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
EU AI Act compliance framework implementation.

Maps Regulation (EU) 2024/1689 Chapter 2 requirements for high-risk AI
systems (Articles 8–15) to governance configuration paths and audit log events.

Scope is intentionally limited to high-risk AI system provider obligations.
GPAI model obligations (Chapter 5) are out of scope for this framework instance.

The framework loads the Chapter 2 article mapping from
``mappings/eu-ai-act-requirements.json`` at the repository root, falling back
to an inline subset if the file is unavailable.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from compliance_mapper.evidence.collector import EvidenceCollector
from compliance_mapper.evidence.generator import AssessmentGenerationParams, EvidenceGenerator
from compliance_mapper.frameworks.interface import ComplianceFramework, FrameworkMetadata
from compliance_mapper.evidence.types import ControlEvidenceCollection
from compliance_mapper.types import (
    AuditLog,
    ControlAssessment,
    GovernanceConfig,
    MapperOptions,
)


# ── Internal mapping dataclass ────────────────────────────────────────────────


@dataclass(frozen=True)
class _EuAiActArticle:
    id: str
    title: str
    description: str
    governance_config_paths: tuple[str, ...]
    audit_log_events: tuple[str, ...]


# ── Fallback inline mapping (Chapter 2 articles only) ────────────────────────

_INLINE_ARTICLES: tuple[_EuAiActArticle, ...] = (
    _EuAiActArticle(
        id="Art8",
        title="Compliance with the requirements",
        description=(
            "High-risk AI systems shall comply with the requirements established "
            "in Chapter 2."
        ),
        governance_config_paths=(
            "governance.ai.riskClassification",
            "governance.ai.complianceFramework",
            "governance.ai.highRiskDesignation",
        ),
        audit_log_events=(
            "ai_risk_classification_completed",
            "high_risk_designation_confirmed",
        ),
    ),
    _EuAiActArticle(
        id="Art9",
        title="Risk management system",
        description=(
            "A risk management system shall be established and maintained for high-risk "
            "AI systems throughout their lifecycle."
        ),
        governance_config_paths=(
            "governance.ai.riskManagementSystem",
            "governance.ai.riskRegister",
            "governance.ai.misuseScenariosRegister",
            "governance.ai.riskMitigationMeasures",
            "governance.ai.residualRiskAcceptanceCriteria",
            "governance.ai.postMarketMonitoringPlan",
        ),
        audit_log_events=(
            "ai_risk_review_completed",
            "misuse_scenario_assessed",
            "risk_mitigation_implemented",
        ),
    ),
    _EuAiActArticle(
        id="Art10",
        title="Data and data governance",
        description=(
            "Training, validation and testing datasets shall be subject to data "
            "governance practices."
        ),
        governance_config_paths=(
            "governance.ai.dataGovernancePolicy",
            "governance.ai.trainingDataRegister",
            "governance.ai.dataQualityPolicy",
            "governance.ai.biasAssessmentProcess",
            "governance.ai.dataLineageTracking",
            "governance.ai.dataGapsRegister",
            "governance.data.personalDataInTrainingPolicy",
        ),
        audit_log_events=(
            "training_data_assessed",
            "bias_evaluation_completed",
            "data_quality_check_passed",
        ),
    ),
    _EuAiActArticle(
        id="Art11",
        title="Technical documentation",
        description=(
            "Technical documentation shall be drawn up before the high-risk AI system "
            "is placed on the market."
        ),
        governance_config_paths=(
            "governance.ai.technicalDocumentationRegister",
            "governance.ai.systemArchitectureDocument",
            "governance.ai.modelCard",
            "governance.ai.validationResults",
            "governance.ai.standardsCompliance",
            "governance.ai.changeManagementPolicy",
        ),
        audit_log_events=(
            "technical_documentation_completed",
            "documentation_reviewed",
        ),
    ),
    _EuAiActArticle(
        id="Art12",
        title="Record-keeping",
        description=(
            "High-risk AI systems shall be designed with capabilities enabling "
            "automatic recording of events."
        ),
        governance_config_paths=(
            "governance.ai.auditLoggingPolicy",
            "governance.ai.logRetentionPolicy",
            "governance.ai.logIntegrityControls",
            "governance.ai.operationalLogFormat",
            "governance.ai.logAccessControls",
        ),
        audit_log_events=("ai_system_log_generated", "log_integrity_verified"),
    ),
    _EuAiActArticle(
        id="Art13",
        title="Transparency and provision of information to deployers",
        description=(
            "High-risk AI systems shall be designed to ensure their operation is "
            "sufficiently transparent to deployers."
        ),
        governance_config_paths=(
            "governance.ai.systemTransparencyDocument",
            "governance.ai.deployerInstructionsForUse",
            "governance.ai.capabilitiesLimitationsDocument",
            "governance.ai.performanceMetricsRegister",
            "governance.ai.knownRisksDocument",
            "governance.ai.humanOversightGuidance",
        ),
        audit_log_events=(
            "transparency_documentation_updated",
            "deployer_briefing_completed",
        ),
    ),
    _EuAiActArticle(
        id="Art14",
        title="Human oversight",
        description=(
            "High-risk AI systems shall be designed to allow effective oversight by "
            "natural persons during use."
        ),
        governance_config_paths=(
            "governance.ai.humanOversightProcess",
            "governance.ai.overrideCapability",
            "governance.ai.haltCapability",
            "governance.ai.humanReviewTriggers",
            "governance.ai.operatorTrainingRequirements",
            "governance.ai.automationBiasControls",
        ),
        audit_log_events=(
            "human_override_exercised",
            "system_halted_by_operator",
            "human_review_performed",
        ),
    ),
    _EuAiActArticle(
        id="Art15",
        title="Accuracy, robustness and cybersecurity",
        description=(
            "High-risk AI systems shall achieve an appropriate level of accuracy, "
            "robustness and cybersecurity."
        ),
        governance_config_paths=(
            "governance.ai.accuracyMetrics",
            "governance.ai.robustnessTesting",
            "governance.ai.adversarialTestingPolicy",
            "governance.security.aiSystemSecurityPolicy",
            "governance.ai.modelValidationPolicy",
            "governance.ai.driftMonitoringPolicy",
            "governance.ai.fallbackMechanisms",
        ),
        audit_log_events=(
            "accuracy_benchmark_completed",
            "robustness_test_passed",
            "adversarial_test_completed",
            "security_assessment_completed",
        ),
    ),
)


# ── JSON loading ──────────────────────────────────────────────────────────────

_MAPPING_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent.parent
    / "mappings"
    / "eu-ai-act-requirements.json"
)


def _parse_article(raw: dict[str, Any]) -> _EuAiActArticle:
    return _EuAiActArticle(
        id=raw["id"],
        title=raw["title"],
        description=raw["description"],
        governance_config_paths=tuple(raw.get("governanceConfigPaths", [])),
        audit_log_events=tuple(raw.get("auditLogEvents", [])),
    )


def _load_articles() -> tuple[_EuAiActArticle, ...]:
    """
    Attempt to load Chapter 2 articles from the JSON file on disk.
    Falls back to the inline set if the file is unavailable or malformed.
    """
    try:
        raw_text = _MAPPING_PATH.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(raw_text)
        # Only assess Chapter 2 (high-risk requirements) by default.
        chapter2 = next(
            (ch for ch in data.get("chapters", []) if ch.get("id") == "Chapter2"),
            None,
        )
        if chapter2 is None:
            return _INLINE_ARTICLES
        articles = [_parse_article(a) for a in chapter2.get("articles", [])]
        return tuple(articles) if articles else _INLINE_ARTICLES
    except (OSError, KeyError, json.JSONDecodeError):
        return _INLINE_ARTICLES


# ── Framework class ───────────────────────────────────────────────────────────


class EUAIActFramework(ComplianceFramework):
    """
    EU AI Act compliance framework.

    Covers Chapter 2 requirements (Articles 8–15) for high-risk AI systems as
    defined in Regulation (EU) 2024/1689 and Annex III.

    Example::

        from compliance_mapper.frameworks.eu_ai_act import EUAIActFramework
        from compliance_mapper.mapper import ComplianceMapper

        mapper = ComplianceMapper()
        report = mapper.map(governance_config, audit_log, [EUAIActFramework()])
    """

    def __init__(self) -> None:
        self._articles: tuple[_EuAiActArticle, ...] | None = None

    @property
    def metadata(self) -> FrameworkMetadata:
        return FrameworkMetadata(
            id="eu-ai-act",
            name="EU AI Act",
            version="2024/1689",
            source="Regulation (EU) 2024/1689 of the European Parliament and of the Council",
            scope_description=(
                "Chapter 2 requirements for high-risk AI systems: risk management, "
                "data governance, documentation, logging, transparency, human oversight, "
                "and robustness."
            ),
        )

    def _ensure_loaded(self) -> tuple[_EuAiActArticle, ...]:
        if self._articles is None:
            self._articles = _load_articles()
        return self._articles

    def list_control_ids(self) -> tuple[str, ...]:
        return tuple(a.id for a in self._ensure_loaded())

    def assess(
        self,
        governance_config: GovernanceConfig,
        audit_log: AuditLog,
        options: MapperOptions,
    ) -> tuple[ControlAssessment, ...]:
        """
        Assess all EU AI Act Chapter 2 articles against the governance config.

        Parameters
        ----------
        governance_config:
            Full governance configuration dict.
        audit_log:
            Structured audit log for the assessment period.
        options:
            Mapper options controlling exclusions and gap inclusion.

        Returns
        -------
        tuple[ControlAssessment, ...]
            One assessment per EU AI Act article.
        """
        articles = self._ensure_loaded()
        excluded_ids = set(options.exclude_control_ids)
        include_audit_event_gaps = options.include_audit_event_gaps
        report_timestamp = options.report_timestamp or datetime.now(tz=timezone.utc).isoformat()

        collector = EvidenceCollector(config=governance_config, audit_log=audit_log)
        generator = EvidenceGenerator()

        assessments: list[ControlAssessment] = []
        for article in articles:
            is_excluded = article.id in excluded_ids

            if is_excluded:
                collection = ControlEvidenceCollection(
                    control_id=article.id,
                    config_resolutions=(),
                    audit_event_resolutions=(),
                    collected_at=report_timestamp,
                )
            else:
                collection = collector.collect_for_control(
                    control_id=article.id,
                    required_config_paths=article.governance_config_paths,
                    required_audit_events=article.audit_log_events,
                )

            assessments.append(
                generator.generate_assessment(
                    AssessmentGenerationParams(
                        control_id=article.id,
                        title=article.title,
                        description=article.description,
                        framework_id=self.metadata.id,
                        collection=collection,
                        include_audit_event_gaps=include_audit_event_gaps,
                        is_excluded=is_excluded,
                    )
                )
            )

        return tuple(assessments)
