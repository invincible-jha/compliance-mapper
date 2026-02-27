# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Example: EU AI Act Risk Classification.

Demonstrates how to use the EUAIActRiskClassifier to evaluate three sample
AI systems with different risk profiles:

1. A loan decision engine — classified as high-risk under Annex III.
2. A customer support chatbot — classified as limited risk under Article 50.
3. An internal content recommendation engine — classified as minimal risk.

Run from the repository root::

    python examples/risk-classification-example.py
"""

from __future__ import annotations

import pathlib
import sys

# Allow running directly from the repo root without installing the package.
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "python" / "src"))

from compliance_mapper.risk_classifier import (
    AISystemProfile,
    EUAIActRiskClassifier,
    RiskClassification,
    RiskLevel,
)

# ── Classifier setup ──────────────────────────────────────────────────────────

MAPPINGS_DIR = pathlib.Path(__file__).parent.parent / "mappings"
classifier = EUAIActRiskClassifier(mappings_dir=MAPPINGS_DIR)


# ── Sample AI systems ─────────────────────────────────────────────────────────

# System 1: Loan Decision Engine — finance sector, customer-facing.
# Expected: HIGH_RISK (essential_services_access from finance sector)
LOAN_ENGINE = AISystemProfile(
    name="Loan Decision Engine",
    description=(
        "Automated credit scoring system that evaluates retail banking customer "
        "applications and recommends loan approval or rejection."
    ),
    use_cases=["essential_services_access"],
    data_types=["financial", "personal", "credit_history"],
    autonomy_level="semi_autonomous",
    deployment_context="customer_facing",
    sector="finance",
    existing_controls=[
        "risk_management_system",
        "technical_documentation",
        "record_keeping",
    ],
)

# System 2: Customer Support Chatbot — public-facing, no existing disclosure.
# Expected: LIMITED_RISK (chatbot_interaction from public deployment context)
SUPPORT_CHATBOT = AISystemProfile(
    name="Customer Support Chatbot",
    description=(
        "LLM-powered chatbot that handles customer service queries on the public "
        "website. Does not make binding decisions."
    ),
    use_cases=[],
    data_types=["conversational_text"],
    autonomy_level="advisory",
    deployment_context="public",
    sector="retail",
    existing_controls=[
        "disclosure_of_ai_interaction",
    ],
)

# System 3: Internal Content Recommendation Engine — no high-risk criteria.
# Expected: MINIMAL_RISK
INTERNAL_RECOMMENDER = AISystemProfile(
    name="Internal Content Recommendation Engine",
    description=(
        "Suggests relevant internal knowledge-base articles to employees "
        "based on their current task context. Human agents always review suggestions."
    ),
    use_cases=[],
    data_types=["text", "usage_metadata"],
    autonomy_level="advisory",
    deployment_context="internal",
    sector="enterprise_productivity",
    existing_controls=[],
)


# ── Output helpers ────────────────────────────────────────────────────────────


def print_classification(name: str, result: RiskClassification) -> None:
    """Print a human-readable classification summary."""
    level_labels: dict[RiskLevel, str] = {
        RiskLevel.PROHIBITED: "PROHIBITED (Article 5)",
        RiskLevel.HIGH_RISK: "HIGH RISK (Annex III / Article 6)",
        RiskLevel.LIMITED_RISK: "LIMITED RISK (Article 50)",
        RiskLevel.MINIMAL_RISK: "MINIMAL RISK (Article 95)",
    }
    label = level_labels[result.level]

    print(f"\n{'=' * 60}")
    print(f"  System: {name}")
    print(f"{'=' * 60}")
    print(f"  Risk level    : {label}")
    print(f"  Confidence    : {result.confidence:.0%}")
    print(f"  Matched on    : {', '.join(result.matching_criteria)}")
    print(f"  Articles      : {', '.join(result.applicable_articles)}")

    if result.required_controls and result.required_controls != ("voluntary_code_of_conduct",):
        print(f"  Required      : {', '.join(result.required_controls)}")

    if result.gaps:
        print(f"\n  GAPS ({len(result.gaps)} missing control(s)):")
        for gap in result.gaps:
            print(f"    - {gap}")
        print("\n  Recommendations:")
        for rec in result.recommendations:
            print(f"    -> {rec}")
    else:
        print(f"\n  No gaps identified.")
        if result.recommendations:
            print("  Notes:")
            for rec in result.recommendations:
                print(f"    -> {rec}")


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    print("\nEU AI Act Risk Classification — AumOS compliance-mapper")
    print(f"Regulation: EU AI Act (Regulation 2024/1689)")
    print(f"Effective date: 2026-08-02")

    samples: list[tuple[str, AISystemProfile]] = [
        ("Loan Decision Engine", LOAN_ENGINE),
        ("Customer Support Chatbot", SUPPORT_CHATBOT),
        ("Internal Content Recommendation Engine", INTERNAL_RECOMMENDER),
    ]

    for system_name, profile in samples:
        result = classifier.classify(profile)
        print_classification(system_name, result)

    print(f"\n{'=' * 60}")
    print("  Classification complete.")
    print(f"  Use compliance-mapper.classify() in your CI pipeline to")
    print(f"  continuously verify EU AI Act risk level as your system evolves.")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
