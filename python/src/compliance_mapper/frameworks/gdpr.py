# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
GDPR compliance framework implementation.

Maps Regulation (EU) 2016/679 Articles 5–22, 25, 30, 32, 33, and 35 to
governance configuration paths and audit log events.

The framework loads the full article mapping from
``mappings/gdpr-articles.json`` at the repository root, falling back to an
inline subset if the file is unavailable.
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
class _GdprArticle:
    id: str
    title: str
    description: str
    governance_config_paths: tuple[str, ...]
    audit_log_events: tuple[str, ...]


# ── Fallback inline mapping ───────────────────────────────────────────────────

_INLINE_ARTICLES: tuple[_GdprArticle, ...] = (
    _GdprArticle(
        id="Art5",
        title="Principles relating to processing of personal data",
        description=(
            "Personal data shall be processed lawfully, fairly, and transparently."
        ),
        governance_config_paths=(
            "governance.privacy.processingPurposes",
            "governance.privacy.lawfulBasisRegister",
            "governance.privacy.minimizationPolicy",
            "governance.data.retentionSchedule",
            "governance.data.accuracyPolicy",
            "governance.data.encryptionPolicy",
            "governance.privacy.accountabilityRecord",
        ),
        audit_log_events=(
            "lawful_basis_documented",
            "purpose_limitation_reviewed",
            "retention_enforced",
        ),
    ),
    _GdprArticle(
        id="Art6",
        title="Lawfulness of processing",
        description="Processing is lawful only if at least one lawful basis applies.",
        governance_config_paths=(
            "governance.privacy.lawfulBasisRegister",
            "governance.privacy.consentManagement",
            "governance.privacy.legitimateInterestAssessments",
        ),
        audit_log_events=("lawful_basis_applied", "lia_completed"),
    ),
    _GdprArticle(
        id="Art7",
        title="Conditions for consent",
        description=(
            "Where processing is based on consent, the controller must demonstrate "
            "that the data subject consented."
        ),
        governance_config_paths=(
            "governance.privacy.consentManagement",
            "governance.privacy.consentRecordRetention",
            "governance.privacy.withdrawalMechanism",
            "governance.privacy.granularConsentOptions",
        ),
        audit_log_events=("consent_recorded", "consent_withdrawn"),
    ),
    _GdprArticle(
        id="Art15",
        title="Right of access by the data subject",
        description=(
            "The data subject shall have the right to obtain confirmation of processing "
            "and a copy of personal data."
        ),
        governance_config_paths=(
            "governance.privacy.dataSubjectAccessProcess",
            "governance.privacy.accessResponseSLA",
            "governance.privacy.identityVerificationProcess",
            "governance.privacy.accessFulfillmentProcess",
        ),
        audit_log_events=("access_request_received", "access_request_fulfilled"),
    ),
    _GdprArticle(
        id="Art17",
        title="Right to erasure ('right to be forgotten')",
        description=(
            "The data subject shall have the right to obtain erasure of personal data "
            "without undue delay."
        ),
        governance_config_paths=(
            "governance.privacy.erasureProcess",
            "governance.data.disposalPolicy",
            "governance.data.backupErasurePolicy",
            "governance.privacy.erasureSLA",
            "governance.privacy.thirdPartyErasureNotification",
        ),
        audit_log_events=(
            "erasure_request_received",
            "data_erased",
            "third_party_erasure_notified",
        ),
    ),
    _GdprArticle(
        id="Art22",
        title="Automated individual decision-making, including profiling",
        description=(
            "The data subject shall have the right not to be subject to solely "
            "automated decisions without human review."
        ),
        governance_config_paths=(
            "governance.ai.automatedDecisionRegister",
            "governance.ai.humanOversightProcess",
            "governance.ai.profilingPolicy",
            "governance.ai.explainabilityProcess",
        ),
        audit_log_events=(
            "automated_decision_made",
            "human_review_triggered",
            "decision_challenged",
        ),
    ),
    _GdprArticle(
        id="Art25",
        title="Data protection by design and by default",
        description=(
            "The controller shall implement appropriate measures to give effect to "
            "data protection principles."
        ),
        governance_config_paths=(
            "governance.privacy.privacyByDesignProcess",
            "governance.data.pseudonymisationPolicy",
            "governance.data.minimizationByDefault",
            "governance.sdlc.privacyReview",
            "governance.access.defaultAccessRestriction",
        ),
        audit_log_events=(
            "privacy_by_design_review_completed",
            "pseudonymisation_applied",
        ),
    ),
    _GdprArticle(
        id="Art32",
        title="Security of processing",
        description=(
            "The controller and processor shall implement appropriate technical and "
            "organisational measures."
        ),
        governance_config_paths=(
            "governance.data.encryptionAtRestPolicy",
            "governance.data.encryptionInTransitPolicy",
            "governance.data.pseudonymisationPolicy",
            "governance.security.accessControlPolicy",
            "governance.business.bcpPolicy",
            "governance.security.penetrationTestingSchedule",
            "governance.security.vulnerabilityManagementPolicy",
        ),
        audit_log_events=(
            "security_assessment_completed",
            "encryption_verified",
            "pen_test_completed",
        ),
    ),
    _GdprArticle(
        id="Art35",
        title="Data protection impact assessment",
        description=(
            "Where processing is likely to result in high risk, the controller shall "
            "carry out a DPIA prior to processing."
        ),
        governance_config_paths=(
            "governance.privacy.dpiaProcess",
            "governance.privacy.dpiaThresholdCriteria",
            "governance.privacy.dpiaRegister",
            "governance.privacy.dpoReviewProcess",
            "governance.ai.automatedDecisionRegister",
        ),
        audit_log_events=("dpia_completed", "dpia_approved", "dpia_reviewed"),
    ),
)


# ── JSON loading ──────────────────────────────────────────────────────────────

_MAPPING_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent.parent
    / "mappings"
    / "gdpr-articles.json"
)


def _parse_article(raw: dict[str, Any]) -> _GdprArticle:
    return _GdprArticle(
        id=raw["id"],
        title=raw["title"],
        description=raw["description"],
        governance_config_paths=tuple(raw.get("governanceConfigPaths", [])),
        audit_log_events=tuple(raw.get("auditLogEvents", [])),
    )


def _load_articles() -> tuple[_GdprArticle, ...]:
    """
    Attempt to load the full GDPR mapping from the JSON file on disk.
    Falls back to the inline set if the file is unavailable or malformed.
    """
    try:
        raw_text = _MAPPING_PATH.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(raw_text)
        articles = [_parse_article(a) for a in data.get("articles", [])]
        return tuple(articles) if articles else _INLINE_ARTICLES
    except (OSError, KeyError, json.JSONDecodeError):
        return _INLINE_ARTICLES


# ── Framework class ───────────────────────────────────────────────────────────


class GDPRFramework(ComplianceFramework):
    """
    GDPR compliance framework.

    Covers Articles 5–22, 25, 30, 32, 33, and 35 of Regulation (EU) 2016/679,
    focusing on controller and processor obligations relevant to AI and digital
    service governance.

    Example::

        from compliance_mapper.frameworks.gdpr import GDPRFramework
        from compliance_mapper.mapper import ComplianceMapper

        mapper = ComplianceMapper()
        report = mapper.map(governance_config, audit_log, [GDPRFramework()])
    """

    def __init__(self) -> None:
        self._articles: tuple[_GdprArticle, ...] | None = None

    @property
    def metadata(self) -> FrameworkMetadata:
        return FrameworkMetadata(
            id="gdpr",
            name="GDPR",
            version="2016/679",
            source="Regulation (EU) 2016/679 of the European Parliament and of the Council",
            scope_description=(
                "General Data Protection Regulation — controller and processor "
                "obligations for personal data processing."
            ),
        )

    def _ensure_loaded(self) -> tuple[_GdprArticle, ...]:
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
        Assess all GDPR articles against the governance config and audit log.

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
            One assessment per GDPR article.
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
