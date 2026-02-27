# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
EU AI Act Risk Classification Tool for the compliance-mapper package.

Classifies an AI system's risk level under Regulation (EU) 2024/1689 (EU AI Act)
and maps identified gaps to AumOS protocol sections for remediation.

Usage::

    from compliance_mapper.risk_classifier import (
        AISystemProfile,
        EUAIActRiskClassifier,
        RiskClassification,
        RiskLevel,
    )

    classifier = EUAIActRiskClassifier()
    profile = AISystemProfile(
        name="Loan Decision Engine",
        description="Automated credit scoring for retail banking customers.",
        use_cases=["essential_services_access"],
        data_types=["financial", "personal"],
        autonomy_level="semi_autonomous",
        deployment_context="customer_facing",
        sector="finance",
        existing_controls=["risk_management_system", "technical_documentation"],
    )
    result = classifier.classify(profile)
    print(result.level.value)      # "high_risk"
    print(result.gaps)             # controls not yet implemented
    print(result.recommendations)  # AumOS tool suggestions per gap
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Sequence


# ── Risk Levels ───────────────────────────────────────────────────────────────


class RiskLevel(Enum):
    """EU AI Act risk classification levels in descending order of severity."""

    PROHIBITED = "prohibited"
    HIGH_RISK = "high_risk"
    LIMITED_RISK = "limited_risk"
    MINIMAL_RISK = "minimal_risk"


# ── Data Models ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RiskClassification:
    """
    Point-in-time risk classification result for a single AI system.

    Immutable so it can be safely stored, logged, and compared across
    reassessment cycles without risk of accidental mutation.
    """

    level: RiskLevel
    """The assigned EU AI Act risk level."""

    confidence: float
    """
    Classifier confidence in the assigned level (0.0–1.0).

    Lower values indicate that the profile's criteria are ambiguous or
    borderline. Human review is recommended when confidence is below 0.75.
    """

    matching_criteria: tuple[str, ...]
    """
    Criteria identifiers from the risk-categories mapping that matched
    this AI system's profile.
    """

    applicable_articles: tuple[str, ...]
    """EU AI Act articles that apply to this classification."""

    required_controls: tuple[str, ...]
    """
    Controls mandated by the applicable articles for this risk level.
    These map 1:1 to the ``required_controls`` field in the JSON mapping.
    """

    gaps: tuple[str, ...]
    """
    Required controls that were NOT present in ``AISystemProfile.existing_controls``.
    An empty tuple means all mandatory controls are in place.
    """

    recommendations: tuple[str, ...]
    """
    Human-readable remediation guidance, one entry per gap, referencing
    the relevant AumOS protocol tools.
    """


@dataclass(frozen=True)
class AISystemProfile:
    """
    Describes the AI system to be classified.

    Callers populate this from their own system inventory or questionnaire.
    All fields influence which risk criteria are evaluated.
    """

    name: str
    """Human-readable name of the AI system."""

    description: str
    """Brief description of the system's purpose."""

    use_cases: Sequence[str]
    """
    List of use-case identifiers that apply to this system.

    Values should match criteria identifiers in ``eu-ai-act-risk-categories.json``
    (e.g. ``"biometric_identification"``, ``"chatbot_interaction"``).
    """

    data_types: Sequence[str]
    """
    Categories of data the system processes (e.g. ``"biometric"``, ``"financial"``).
    Used for informational purposes and future sector-specific expansions.
    """

    autonomy_level: str
    """
    Degree of autonomous decision-making.

    Accepted values: ``"advisory"`` | ``"semi_autonomous"`` | ``"autonomous"``
    """

    deployment_context: str
    """
    Where the system is deployed.

    Accepted values: ``"internal"`` | ``"customer_facing"`` | ``"public"``
    """

    sector: str
    """
    Industry sector of deployment. Used to apply sector-based criteria mapping.

    Recognised values: ``"healthcare"``, ``"finance"``, ``"education"``,
    ``"employment"``, ``"law_enforcement"``, ``"border_control"``, ``"infrastructure"``.
    Any other value is treated as a general-purpose sector.
    """

    existing_controls: Sequence[str] = field(default_factory=list)
    """
    Controls already implemented by the system owner.

    Values should match identifiers in the ``required_controls`` arrays of the
    risk categories JSON (e.g. ``"risk_management_system"``, ``"human_oversight"``).
    """


# ── Classifier ────────────────────────────────────────────────────────────────


class EUAIActRiskClassifier:
    """
    Classifies an AI system under EU AI Act (Regulation 2024/1689) risk categories.

    Risk determination follows a priority waterfall:
    1. Prohibited (Article 5) — checked first; any match is definitive.
    2. High-risk (Article 6 / Annex III) — checked if not prohibited.
    3. Limited risk (Article 50) — checked if not high-risk.
    4. Minimal risk (Article 95) — assigned as the default.

    The classifier is stateless after construction; ``classify()`` can be called
    any number of times concurrently with different profiles.

    Args:
        mappings_dir: Path to the directory containing ``eu-ai-act-risk-categories.json``.
            Defaults to the ``mappings/`` directory at the repository root, resolved
            relative to this source file's location.
    """

    def __init__(self, mappings_dir: str | Path | None = None) -> None:
        if mappings_dir is None:
            mappings_dir = Path(__file__).parent.parent.parent.parent / "mappings"
        self._mappings_dir = Path(mappings_dir)
        self._categories = self._load_categories()

    def _load_categories(self) -> dict:
        """Load and parse the risk categories JSON mapping."""
        path = self._mappings_dir / "eu-ai-act-risk-categories.json"
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    # ── Public API ────────────────────────────────────────────────────────────

    def classify(self, profile: AISystemProfile) -> RiskClassification:
        """
        Classify an AI system according to EU AI Act risk levels.

        Applies a priority waterfall — prohibited is evaluated first, then
        high-risk, then limited risk, falling back to minimal risk if no
        criteria match.

        Args:
            profile: The AI system profile to evaluate.

        Returns:
            A ``RiskClassification`` describing the assigned level, matched
            criteria, applicable articles, required controls, gaps, and
            AumOS-specific remediation recommendations.
        """
        all_criteria = self._extract_criteria(profile)

        prohibited_result = self._check_prohibited(all_criteria)
        if prohibited_result is not None:
            return prohibited_result

        high_risk_result = self._check_high_risk(all_criteria, profile)
        if high_risk_result is not None:
            return high_risk_result

        limited_risk_result = self._check_limited_risk(all_criteria, profile)
        if limited_risk_result is not None:
            return limited_risk_result

        return self._minimal_risk_result()

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _extract_criteria(self, profile: AISystemProfile) -> list[str]:
        """
        Derive a flat list of classification criteria from an AI system profile.

        Combines explicit use_cases with sector-inferred criteria and
        deployment-context-inferred criteria.
        """
        criteria: list[str] = list(profile.use_cases)

        sector_mapping: dict[str, list[str]] = {
            "healthcare": ["essential_services_access"],
            "finance": ["essential_services_access"],
            "education": ["education_vocational_access"],
            "employment": ["employment_worker_management"],
            "law_enforcement": ["law_enforcement"],
            "border_control": ["migration_asylum_border"],
            "infrastructure": ["critical_infrastructure_management"],
        }
        if profile.sector in sector_mapping:
            criteria.extend(sector_mapping[profile.sector])

        # Customer-facing and public deployments carry transparency obligations.
        if profile.deployment_context in ("customer_facing", "public"):
            criteria.append("chatbot_interaction")

        return criteria

    def _find_category(self, level: str) -> dict | None:
        """Return the category dict for the given level string, or None."""
        for category in self._categories["categories"]:
            if category["level"] == level:
                return category
        return None

    def _check_prohibited(self, criteria: list[str]) -> RiskClassification | None:
        """Return a prohibited classification if any criterion matches, else None."""
        category = self._find_category("prohibited")
        if category is None:
            return None

        matches = [c for c in criteria if c in category["criteria"]]
        if not matches:
            return None

        return RiskClassification(
            level=RiskLevel.PROHIBITED,
            confidence=0.9,
            matching_criteria=tuple(matches),
            applicable_articles=tuple(category["articles"]),
            required_controls=("system_must_not_be_deployed",),
            gaps=("system_is_prohibited",),
            recommendations=(
                "This AI system falls under prohibited use cases. "
                "Consult legal counsel immediately.",
            ),
        )

    def _check_high_risk(
        self,
        criteria: list[str],
        profile: AISystemProfile,
    ) -> RiskClassification | None:
        """Return a high-risk classification if any criterion matches, else None."""
        category = self._find_category("high_risk")
        if category is None:
            return None

        matches = [c for c in criteria if c in category["criteria"]]
        if not matches:
            return None

        required: list[str] = category.get("required_controls", [])
        existing = set(profile.existing_controls)
        gaps = [c for c in required if c not in existing]

        return RiskClassification(
            level=RiskLevel.HIGH_RISK,
            confidence=0.85,
            matching_criteria=tuple(matches),
            applicable_articles=tuple(category["articles"]),
            required_controls=tuple(required),
            gaps=tuple(gaps),
            recommendations=self._high_risk_recommendations(gaps),
        )

    def _check_limited_risk(
        self,
        criteria: list[str],
        profile: AISystemProfile,
    ) -> RiskClassification | None:
        """Return a limited-risk classification if any criterion matches, else None."""
        category = self._find_category("limited_risk")
        if category is None:
            return None

        matches = [c for c in criteria if c in category["criteria"]]
        if not matches:
            return None

        required: list[str] = category.get("required_controls", [])
        existing = set(profile.existing_controls)
        gaps = [c for c in required if c not in existing]

        return RiskClassification(
            level=RiskLevel.LIMITED_RISK,
            confidence=0.8,
            matching_criteria=tuple(matches),
            applicable_articles=tuple(category["articles"]),
            required_controls=tuple(required),
            gaps=tuple(gaps),
            recommendations=self._limited_risk_recommendations(gaps),
        )

    def _minimal_risk_result(self) -> RiskClassification:
        """Return the default minimal-risk classification."""
        return RiskClassification(
            level=RiskLevel.MINIMAL_RISK,
            confidence=0.7,
            matching_criteria=("default",),
            applicable_articles=("Article 95",),
            required_controls=("voluntary_code_of_conduct",),
            gaps=(),
            recommendations=(
                "Consider voluntary adoption of governance best practices.",
                "Use AumOS governance tools for competitive advantage.",
            ),
        )

    def _high_risk_recommendations(self, gaps: list[str]) -> tuple[str, ...]:
        """
        Map high-risk control gaps to AumOS tool recommendations.

        Each gap identifier is looked up in a static mapping that points to
        the most relevant AumOS open-source protocol tool.
        """
        control_to_aumos: dict[str, str] = {
            "risk_management_system": (
                "Use compliance-mapper for risk management documentation"
            ),
            "data_governance": (
                "Use context-firewall for data domain isolation"
            ),
            "technical_documentation": (
                "Use aumos-docs templates for technical documentation"
            ),
            "record_keeping": (
                "Use agent-audit-trail for comprehensive record keeping"
            ),
            "transparency_information": (
                "Use agents-md-spec for agent capability disclosure"
            ),
            "human_oversight": (
                "Use trust-ladder L0-L3 for human oversight requirements"
            ),
            "accuracy_robustness_cybersecurity": (
                "Use anomaly-sentinel + trust-test for robustness"
            ),
        }

        recommendations: list[str] = []
        for gap in gaps:
            if gap in control_to_aumos:
                recommendations.append(control_to_aumos[gap])

        if not recommendations:
            recommendations.append(
                "All required controls appear to be in place. Verify implementation depth."
            )

        return tuple(recommendations)

    def _limited_risk_recommendations(self, gaps: list[str]) -> tuple[str, ...]:
        """Map limited-risk control gaps to AumOS tool recommendations."""
        recommendations: list[str] = []

        if "disclosure_of_ai_interaction" in gaps:
            recommendations.append(
                "Add AI disclosure using agents-md-spec or explicit UI notification"
            )
        if "content_labeling" in gaps:
            recommendations.append(
                "Label AI-generated content per Article 50 requirements"
            )

        return tuple(recommendations) if recommendations else ("Transparency obligations met.",)
