# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Multi-standard efficiency analyzer.

Identifies AumOS controls that satisfy requirements across multiple compliance
standards simultaneously, providing organizations with a clear view of control
reuse and overall governance efficiency.

Supported standards: SOC 2, GDPR, EU AI Act, ISO 42001, NIST AI RMF.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from compliance_mapper.frameworks.iso42001 import _load_controls as _load_iso42001
from compliance_mapper.frameworks.nist_ai_rmf import _load_subcategories as _load_nist_rmf


# ── Pydantic v2 models ───────────────────────────────────────────────────────


class SharedControl(BaseModel):
    """An AumOS control that satisfies requirements in multiple standards."""

    control_id: str = Field(description="AumOS control identifier")
    standards_satisfied: list[str] = Field(description="Standards satisfied by this control")
    standard_count: int = Field(description="Number of standards satisfied")
    clause_mappings: dict[str, list[str]] = Field(
        description="Per-standard list of clause/control IDs satisfied"
    )


class StandardSummary(BaseModel):
    """Summary of a single standard's coverage within the shared analysis."""

    standard_id: str = Field(description="Standard identifier")
    total_clauses: int = Field(description="Total clauses in this standard")
    covered_clauses: int = Field(description="Clauses covered by provided GBOM controls")
    coverage_percentage: float = Field(description="Coverage percentage (0.0–100.0)")


class SharedControlReport(BaseModel):
    """Report showing how AumOS controls satisfy multiple standards simultaneously."""

    standards_analyzed: list[str] = Field(description="Standards included in the analysis")
    total_unique_controls: int = Field(description="Total unique AumOS controls in GBOM")
    multi_standard_controls: int = Field(
        description="Controls satisfying 2+ standards"
    )
    efficiency_percentage: float = Field(
        description="Percentage of controls that serve multiple standards (0.0–100.0)"
    )
    shared_controls: list[SharedControl] = Field(
        description="Controls sorted by number of standards satisfied (descending)"
    )
    standard_summaries: list[StandardSummary] = Field(
        description="Per-standard coverage summary"
    )
    generated_at: str = Field(description="ISO 8601 timestamp of report generation")


# ── Standard registry ─────────────────────────────────────────────────────────

# Each entry maps a standard identifier to a function that returns
# a dict of { aumos_control_id: [clause_ids] }.

_SUPPORTED_STANDARDS = ("soc2", "gdpr", "eu-ai-act", "iso-42001", "nist-ai-rmf")


def _build_iso42001_control_map() -> dict[str, list[str]]:
    """Build a map from AumOS control IDs to ISO 42001 clause IDs."""
    controls = _load_iso42001()
    result: dict[str, list[str]] = {}
    for control in controls:
        for aumos_id in control.aumos_controls:
            result.setdefault(aumos_id, []).append(control.id)
    return result


def _build_nist_rmf_control_map() -> dict[str, list[str]]:
    """Build a map from AumOS control IDs to NIST AI RMF subcategory IDs."""
    subcategories = _load_nist_rmf()
    result: dict[str, list[str]] = {}
    for sub in subcategories:
        for aumos_id in sub.aumos_controls:
            result.setdefault(aumos_id, []).append(sub.id)
    return result


def _get_control_map_for_standard(standard: str) -> dict[str, list[str]]:
    """
    Return a mapping of AumOS control IDs to clause IDs for a given standard.

    For standards without native AumOS control mappings (SOC 2, GDPR, EU AI Act),
    a static mapping of representative controls is returned.
    """
    if standard == "iso-42001":
        return _build_iso42001_control_map()
    if standard == "nist-ai-rmf":
        return _build_nist_rmf_control_map()

    # Static representative mappings for the original three frameworks.
    # These map the core AumOS protocol controls to the framework's requirements.
    static_maps: dict[str, dict[str, list[str]]] = {
        "soc2": {
            "ATP-001": ["CC1.1", "CC1.2"],
            "ATP-005": ["CC5.3"],
            "ATP-006": ["CC1.3", "CC6.3"],
            "ATP-007": ["CC3.1", "CC3.2"],
            "AOAP-001": ["CC1.1", "CC4.1"],
            "AOAP-004": ["CC3.1", "CC9.1"],
            "ALP-001": ["CC2.1", "CC2.2"],
            "ALP-002": ["CC4.1", "CC7.2"],
            "ALP-007": ["CC4.1", "CC4.2"],
        },
        "gdpr": {
            "ATP-001": ["Art5", "Art24"],
            "ATP-007": ["Art35"],
            "AOAP-001": ["Art5", "Art25"],
            "AOAP-004": ["Art32"],
            "ALP-001": ["Art30"],
            "ALP-002": ["Art5"],
            "ALP-007": ["Art5", "Art32"],
        },
        "eu-ai-act": {
            "ATP-001": ["Art8"],
            "ATP-007": ["Art9"],
            "ATP-014": ["Art9"],
            "AOAP-001": ["Art14"],
            "AOAP-007": ["Art9", "Art14"],
            "ALP-001": ["Art12"],
            "ALP-002": ["Art15"],
            "ALP-007": ["Art12"],
        },
    }

    return static_maps.get(standard, {})


# ── Public API ────────────────────────────────────────────────────────────────


def analyze_shared_controls(
    standards: list[str],
    gbom_controls: list[str],
) -> SharedControlReport:
    """
    Analyze which AumOS controls satisfy multiple compliance standards
    simultaneously, showing governance efficiency.

    Parameters
    ----------
    standards:
        List of standard identifiers to include in the analysis.
        Valid values: ``"soc2"``, ``"gdpr"``, ``"eu-ai-act"``,
        ``"iso-42001"``, ``"nist-ai-rmf"``.
    gbom_controls:
        List of AumOS control identifiers present in the Governance BOM.

    Returns
    -------
    SharedControlReport
        Report showing control reuse across standards with efficiency metrics.
    """
    gbom_set = set(gbom_controls)
    validated_standards = [s for s in standards if s in _SUPPORTED_STANDARDS]

    # Build per-standard control maps.
    standard_maps: dict[str, dict[str, list[str]]] = {}
    for std in validated_standards:
        standard_maps[std] = _get_control_map_for_standard(std)

    # For each GBOM control, determine which standards it satisfies.
    control_to_standards: dict[str, dict[str, list[str]]] = {}

    for control_id in gbom_set:
        clause_mappings: dict[str, list[str]] = {}
        for std in validated_standards:
            std_map = standard_maps[std]
            if control_id in std_map:
                clause_mappings[std] = std_map[control_id]
        if clause_mappings:
            control_to_standards[control_id] = clause_mappings

    # Build shared controls list.
    shared_controls: list[SharedControl] = []
    for control_id, clause_mappings in control_to_standards.items():
        shared_controls.append(
            SharedControl(
                control_id=control_id,
                standards_satisfied=list(clause_mappings.keys()),
                standard_count=len(clause_mappings),
                clause_mappings=clause_mappings,
            )
        )

    # Sort by standard_count descending, then by control_id.
    shared_controls.sort(key=lambda sc: (-sc.standard_count, sc.control_id))

    multi_count = sum(1 for sc in shared_controls if sc.standard_count >= 2)
    total_unique = len(gbom_set)
    efficiency_pct = (multi_count / total_unique * 100.0) if total_unique > 0 else 0.0

    # Build per-standard summaries.
    standard_summaries: list[StandardSummary] = []
    for std in validated_standards:
        std_map = standard_maps[std]
        all_clauses: set[str] = set()
        covered_clauses: set[str] = set()

        for aumos_id, clause_ids in std_map.items():
            all_clauses.update(clause_ids)
            if aumos_id in gbom_set:
                covered_clauses.update(clause_ids)

        total_cl = len(all_clauses)
        covered_cl = len(covered_clauses)
        pct = (covered_cl / total_cl * 100.0) if total_cl > 0 else 0.0

        standard_summaries.append(
            StandardSummary(
                standard_id=std,
                total_clauses=total_cl,
                covered_clauses=covered_cl,
                coverage_percentage=round(pct, 2),
            )
        )

    return SharedControlReport(
        standards_analyzed=validated_standards,
        total_unique_controls=total_unique,
        multi_standard_controls=multi_count,
        efficiency_percentage=round(efficiency_pct, 2),
        shared_controls=shared_controls,
        standard_summaries=standard_summaries,
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
    )
