# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
SOC 2 Type II compliance framework implementation.

Maps the AICPA Trust Services Criteria (2017) to governance config paths
and audit log events.  Covers Security (CC), Availability (A),
Confidentiality (C), Processing Integrity (PI), and Privacy (P) categories.

The framework attempts to load the full mapping from
``mappings/soc2-controls.json`` at the repository root.  If the file is
unavailable (e.g. installed as a library without the repo), it falls back to
an inline subset covering the most commonly assessed controls.
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
class _Soc2Control:
    id: str
    title: str
    description: str
    governance_config_paths: tuple[str, ...]
    audit_log_events: tuple[str, ...]


# ── Fallback inline mapping ───────────────────────────────────────────────────

_INLINE_CONTROLS: tuple[_Soc2Control, ...] = (
    _Soc2Control(
        id="CC1.1",
        title="Organizational Commitment to Integrity and Ethical Values",
        description="The entity demonstrates a commitment to integrity and ethical values.",
        governance_config_paths=(
            "governance.ethics.codeOfConduct",
            "governance.ethics.conflictOfInterestPolicy",
            "governance.organization.leadershipAttestation",
        ),
        audit_log_events=("ethics_training_completed", "policy_acknowledged"),
    ),
    _Soc2Control(
        id="CC6.1",
        title="Logical Access Security Software Infrastructure",
        description=(
            "The entity implements logical access security to protect against threats "
            "from external sources."
        ),
        governance_config_paths=(
            "governance.access.authenticationPolicy",
            "governance.access.mfaPolicy",
            "governance.access.networkSegmentationPolicy",
        ),
        audit_log_events=("mfa_enforced", "access_attempt", "network_policy_applied"),
    ),
    _Soc2Control(
        id="CC6.2",
        title="Prior to Issuing System Credentials",
        description=(
            "Prior to issuing system credentials and granting system access, the entity "
            "registers and authorizes new users."
        ),
        governance_config_paths=(
            "governance.access.userProvisioningProcess",
            "governance.access.approvalWorkflow",
            "governance.access.accessRequestPolicy",
        ),
        audit_log_events=("user_provisioned", "access_approved"),
    ),
    _Soc2Control(
        id="CC6.3",
        title="Role-Based Access and Least Privilege",
        description=(
            "The entity authorizes, modifies, or removes access based on roles, needs, "
            "and least privilege."
        ),
        governance_config_paths=(
            "governance.access.rbacPolicy",
            "governance.access.leastPrivilegePolicy",
            "governance.access.privilegedAccessPolicy",
        ),
        audit_log_events=("role_assigned", "privilege_reviewed", "access_removed"),
    ),
    _Soc2Control(
        id="CC7.4",
        title="Incident Response",
        description=(
            "The entity responds to identified security incidents by executing a defined "
            "incident management program."
        ),
        governance_config_paths=(
            "governance.incident.responsePolicy",
            "governance.incident.responseTeam",
            "governance.incident.communicationPlan",
        ),
        audit_log_events=(
            "incident_response_initiated",
            "incident_resolved",
            "postmortem_completed",
        ),
    ),
    _Soc2Control(
        id="CC8.1",
        title="Change Management Process",
        description=(
            "The entity authorizes, designs, develops or acquires, configures, documents, "
            "tests, approves, and implements changes."
        ),
        governance_config_paths=(
            "governance.changeManagement.changePolicy",
            "governance.changeManagement.approvalWorkflow",
            "governance.changeManagement.testingRequirements",
            "governance.changeManagement.rollbackProcedure",
        ),
        audit_log_events=(
            "change_requested",
            "change_approved",
            "change_tested",
            "change_deployed",
        ),
    ),
    _Soc2Control(
        id="A1.3",
        title="Recovery and Resumption",
        description=(
            "The entity tests recovery plan procedures to achieve timely recovery "
            "of commitments."
        ),
        governance_config_paths=(
            "governance.business.bcpPolicy",
            "governance.business.rtoRpoTargets",
            "governance.business.drTestSchedule",
        ),
        audit_log_events=("bcp_tested", "dr_exercise_completed"),
    ),
    _Soc2Control(
        id="C1.1",
        title="Confidentiality Commitments Identification",
        description="The entity identifies and maintains confidential information.",
        governance_config_paths=(
            "governance.data.classificationPolicy",
            "governance.data.confidentialDataInventory",
            "governance.data.labelingPolicy",
        ),
        audit_log_events=("data_classified", "confidential_data_accessed"),
    ),
    _Soc2Control(
        id="P1.0",
        title="Privacy Notice",
        description=(
            "The entity provides notice to data subjects about its privacy practices."
        ),
        governance_config_paths=(
            "governance.privacy.privacyNoticeUrl",
            "governance.privacy.noticeReviewSchedule",
            "governance.privacy.noticeLanguages",
        ),
        audit_log_events=("privacy_notice_updated", "notice_served"),
    ),
    _Soc2Control(
        id="P2.0",
        title="Choice and Consent",
        description=(
            "The entity communicates choices available for personal information and "
            "obtains consent."
        ),
        governance_config_paths=(
            "governance.privacy.consentManagement",
            "governance.privacy.optOutMechanism",
            "governance.privacy.consentRecordRetention",
        ),
        audit_log_events=("consent_obtained", "opt_out_processed"),
    ),
)


# ── JSON loading ──────────────────────────────────────────────────────────────

# Path resolution: four levels up from this file reaches the repo root.
_MAPPING_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent.parent
    / "mappings"
    / "soc2-controls.json"
)


def _parse_control(raw: dict[str, Any]) -> _Soc2Control:
    return _Soc2Control(
        id=raw["id"],
        title=raw["title"],
        description=raw["description"],
        governance_config_paths=tuple(raw.get("governanceConfigPaths", [])),
        audit_log_events=tuple(raw.get("auditLogEvents", [])),
    )


def _load_controls() -> tuple[_Soc2Control, ...]:
    """
    Attempt to load the full SOC 2 mapping from the JSON file on disk.
    Falls back to the inline set if the file is unavailable or malformed.
    """
    try:
        raw_text = _MAPPING_PATH.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(raw_text)
        controls: list[_Soc2Control] = []
        for category in data.get("categories", []):
            for control_raw in category.get("controls", []):
                controls.append(_parse_control(control_raw))
        return tuple(controls) if controls else _INLINE_CONTROLS
    except (OSError, KeyError, json.JSONDecodeError):
        return _INLINE_CONTROLS


# ── Framework class ───────────────────────────────────────────────────────────


class SOC2Framework(ComplianceFramework):
    """
    SOC 2 Type II compliance framework.

    Implements the AICPA Trust Services Criteria (2017) across all five
    categories: Security (CC), Availability (A), Confidentiality (C),
    Processing Integrity (PI), and Privacy (P).

    Controls are loaded once on first ``assess()`` call and cached for the
    lifetime of the instance.

    Example::

        from compliance_mapper.frameworks.soc2 import SOC2Framework
        from compliance_mapper.mapper import ComplianceMapper

        mapper = ComplianceMapper()
        report = mapper.map(governance_config, audit_log, [SOC2Framework()])
    """

    def __init__(self) -> None:
        self._controls: tuple[_Soc2Control, ...] | None = None

    @property
    def metadata(self) -> FrameworkMetadata:
        return FrameworkMetadata(
            id="soc2",
            name="SOC 2 Type II",
            version="2017",
            source="AICPA Trust Services Criteria",
            scope_description=(
                "Security, Availability, Confidentiality, Processing Integrity, and "
                "Privacy controls for service organizations."
            ),
        )

    def _ensure_loaded(self) -> tuple[_Soc2Control, ...]:
        if self._controls is None:
            self._controls = _load_controls()
        return self._controls

    def list_control_ids(self) -> tuple[str, ...]:
        return tuple(c.id for c in self._ensure_loaded())

    def assess(
        self,
        governance_config: GovernanceConfig,
        audit_log: AuditLog,
        options: MapperOptions,
    ) -> tuple[ControlAssessment, ...]:
        """
        Assess all SOC 2 controls against the governance config and audit log.

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
            One assessment per SOC 2 control.
        """
        controls = self._ensure_loaded()
        excluded_ids = set(options.exclude_control_ids)
        include_audit_event_gaps = options.include_audit_event_gaps
        report_timestamp = options.report_timestamp or datetime.now(tz=timezone.utc).isoformat()

        collector = EvidenceCollector(config=governance_config, audit_log=audit_log)
        generator = EvidenceGenerator()

        assessments: list[ControlAssessment] = []
        for control in controls:
            is_excluded = control.id in excluded_ids

            if is_excluded:
                collection = ControlEvidenceCollection(
                    control_id=control.id,
                    config_resolutions=(),
                    audit_event_resolutions=(),
                    collected_at=report_timestamp,
                )
            else:
                collection = collector.collect_for_control(
                    control_id=control.id,
                    required_config_paths=control.governance_config_paths,
                    required_audit_events=control.audit_log_events,
                )

            assessments.append(
                generator.generate_assessment(
                    AssessmentGenerationParams(
                        control_id=control.id,
                        title=control.title,
                        description=control.description,
                        framework_id=self.metadata.id,
                        collection=collection,
                        include_audit_event_gaps=include_audit_event_gaps,
                        is_excluded=is_excluded,
                    )
                )
            )

        return tuple(assessments)
