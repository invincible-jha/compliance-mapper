# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
ReportGenerator — renders a ``ComplianceReport`` as Markdown or JSON.

Both renderers are pure functions with no I/O.  The ``ReportGenerator`` class
groups them with a shared options interface for convenience.

Example::

    from compliance_mapper.report import ReportGenerator

    generator = ReportGenerator()
    markdown = generator.to_markdown(report)
    json_str = generator.to_json(report, indent=2)
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from typing import Any

from compliance_mapper.types import (
    ComplianceReport,
    ControlAssessment,
    ControlStatus,
    FrameworkResult,
    GapItem,
)

# ── Status display helpers ────────────────────────────────────────────────────

_STATUS_BADGE: dict[ControlStatus, str] = {
    "satisfied": "PASS",
    "gap": "GAP",
    "partial": "PARTIAL",
    "not_applicable": "N/A",
}

_STATUS_INDICATOR: dict[ControlStatus, str] = {
    "satisfied": "✓",
    "gap": "✗",
    "partial": "~",
    "not_applicable": "-",
}

_SEVERITY_LABEL: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def _fmt_status(status: ControlStatus) -> str:
    return f"**[{_STATUS_BADGE[status]}]** {_STATUS_INDICATOR[status]}"


# ── Markdown section builders ─────────────────────────────────────────────────


def _build_executive_summary(report: ComplianceReport) -> str:
    summary = report.summary
    rate = f"{summary.overall_compliance_rate * 100:.1f}%"
    lines = [
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Assessment Period | {report.assessment_period_start} — {report.assessment_period_end} |",
        f"| Frameworks Assessed | {summary.total_frameworks} |",
        f"| Total Controls | {summary.total_controls} |",
        f"| Satisfied | {summary.total_satisfied} |",
        f"| Gaps | {summary.total_gaps} |",
        f"| Partial | {summary.total_partial} |",
        f"| Overall Compliance Rate | {rate} |",
        f"| Critical Gaps | {summary.critical_gaps_count} |",
        "",
    ]
    return "\n".join(lines)


def _build_control_table(controls: tuple[ControlAssessment, ...]) -> str:
    lines = [
        "| Control ID | Title | Status | Satisfied Paths | Gap Paths |",
        "|-----------|-------|--------|-----------------|-----------|",
    ]
    for control in controls:
        title = (
            control.title[:47] + "..." if len(control.title) > 50 else control.title
        )
        lines.append(
            f"| {control.control_id} | {title} | {_fmt_status(control.status)} "
            f"| {len(control.satisfied_paths)} | {len(control.gap_paths)} |"
        )
    return "\n".join(lines)


def _build_control_detail(control: ControlAssessment) -> str:
    lines = [
        f"### {control.control_id} — {control.title}",
        "",
        f"> {control.description}",
        "",
        f"**Status:** {_fmt_status(control.status)}",
        "",
    ]

    if control.satisfied_paths:
        lines.append("**Satisfied configuration paths:**")
        for path in control.satisfied_paths:
            lines.append(f"- `{path}`")
        lines.append("")

    if control.gap_paths:
        lines.append("**Missing configuration paths:**")
        for path in control.gap_paths:
            lines.append(f"- `{path}`")
        lines.append("")

    if control.satisfied_events:
        lines.append("**Audit log events observed:**")
        for event_type in control.satisfied_events:
            lines.append(f"- `{event_type}`")
        lines.append("")

    if control.missing_events:
        lines.append("**Missing audit log events:**")
        for event_type in control.missing_events:
            lines.append(f"- `{event_type}`")
        lines.append("")

    if control.gap_description:
        lines.append(f"**Gap description:** {control.gap_description}")
        lines.append("")

    if control.evidence:
        lines.append(f"**Evidence items collected:** {len(control.evidence)}")
        lines.append("")

    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _build_framework_section(
    framework_result: FrameworkResult,
    include_control_details: bool,
) -> str:
    lines = [
        f"## {framework_result.framework_name} ({framework_result.framework_version})",
        "",
        "| Category | Count |",
        "|----------|-------|",
        f"| Satisfied | {framework_result.satisfied_count} |",
        f"| Gaps | {framework_result.gap_count} |",
        f"| Partial | {framework_result.partial_count} |",
        f"| Not Applicable | {framework_result.not_applicable_count} |",
        f"| **Total** | **{framework_result.total_count}** |",
        "",
        "### Control Summary",
        "",
        _build_control_table(framework_result.controls),
        "",
    ]

    if include_control_details:
        lines.append("### Control Details")
        lines.append("")
        for control in framework_result.controls:
            lines.append(_build_control_detail(control))

    return "\n".join(lines)


def _build_gap_analysis(gaps: tuple[GapItem, ...]) -> str:
    if not gaps:
        return "## Gap Analysis\n\nNo gaps identified across all frameworks.\n"

    lines = [
        "## Gap Analysis",
        "",
        f"{len(gaps)} gap(s) identified across all frameworks.",
        "",
        "| Framework | Control | Severity | Missing Config Paths | Recommendation |",
        "|-----------|---------|----------|---------------------|----------------|",
    ]

    for gap in gaps:
        missing_paths_preview = (
            ", ".join(gap.missing_config_paths[:2])
            + ("…" if len(gap.missing_config_paths) > 2 else "")
            if gap.missing_config_paths
            else "—"
        )
        rec = (
            gap.recommendation[:57] + "…"
            if len(gap.recommendation) > 60
            else gap.recommendation
        )
        severity = _SEVERITY_LABEL.get(gap.severity, gap.severity)
        lines.append(
            f"| {gap.framework_id} | {gap.control_id} | {severity} "
            f"| `{missing_paths_preview}` | {rec} |"
        )

    lines.append("")
    lines.append("### Gap Details")
    lines.append("")

    for gap in gaps:
        severity = _SEVERITY_LABEL.get(gap.severity, gap.severity)
        lines.append(
            f"#### [{severity}] {gap.framework_id} — {gap.control_id}: {gap.control_title}"
        )
        lines.append("")
        if gap.missing_config_paths:
            lines.append("**Missing governance configuration paths:**")
            for path in gap.missing_config_paths:
                lines.append(f"- `{path}`")
            lines.append("")
        if gap.missing_audit_events:
            lines.append("**Missing audit log events:**")
            for event_type in gap.missing_audit_events:
                lines.append(f"- `{event_type}`")
            lines.append("")
        lines.append(f"**Recommendation:** {gap.recommendation}")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ── JSON serialisation helper ─────────────────────────────────────────────────


def _report_to_dict(
    report: ComplianceReport,
    include_evidence: bool,
) -> dict[str, Any]:
    """Recursively convert the ``ComplianceReport`` dataclass tree to a plain dict."""

    def _convert(obj: Any) -> Any:
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return {k: _convert(v) for k, v in dataclasses.asdict(obj).items()}
        if isinstance(obj, (list, tuple)):
            return [_convert(item) for item in obj]
        return obj

    raw: dict[str, Any] = _convert(report)

    if not include_evidence:
        for framework_result in raw.get("framework_results", []):
            for control in framework_result.get("controls", []):
                control["evidence"] = []

    return raw


# ── Options dataclasses ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MarkdownRendererOptions:
    """Options for Markdown report rendering."""

    report_title: str = "Compliance Evidence Report"
    """Title to use as the top-level heading."""

    include_control_details: bool = True
    """Whether to include per-control detail sections."""

    include_gap_analysis: bool = True
    """Whether to include the gap analysis section."""


@dataclass(frozen=True)
class JsonRendererOptions:
    """Options for JSON report rendering."""

    indent: int = 2
    """Number of spaces for indentation. Use ``0`` for compact output."""

    include_evidence: bool = True
    """Whether to include individual evidence items in the output."""


# ── ReportGenerator ───────────────────────────────────────────────────────────


class ReportGenerator:
    """
    Render a ``ComplianceReport`` as Markdown or JSON.

    Both ``to_markdown()`` and ``to_json()`` are pure — they read from the
    report only and produce a string with no side effects.

    Example::

        from compliance_mapper.report import ReportGenerator, MarkdownRendererOptions

        generator = ReportGenerator()

        # Full report with all control details:
        md = generator.to_markdown(report)

        # Summary-only (no per-control sections):
        md_summary = generator.to_markdown(
            report,
            MarkdownRendererOptions(include_control_details=False),
        )

        # Compact JSON without evidence arrays:
        compact_json = generator.to_json(
            report,
            JsonRendererOptions(indent=0, include_evidence=False),
        )
    """

    def to_markdown(
        self,
        report: ComplianceReport,
        options: MarkdownRendererOptions | None = None,
    ) -> str:
        """
        Render a ``ComplianceReport`` as a Markdown document.

        Parameters
        ----------
        report:
            The compliance report to render.
        options:
            Rendering options.  Defaults to ``MarkdownRendererOptions()``.

        Returns
        -------
        str
            Markdown string suitable for saving as ``.md`` or displaying inline.
        """
        opts = options if options is not None else MarkdownRendererOptions()

        sections: list[str] = [
            f"# {opts.report_title}",
            "",
            f"**Report ID:** `{report.report_id}`",
            f"**Generated:** {report.generated_at}",
            f"**Assessment Period:** "
            f"{report.assessment_period_start} — {report.assessment_period_end}",
            "",
            _build_executive_summary(report),
        ]

        for framework_result in report.framework_results:
            sections.append(
                _build_framework_section(framework_result, opts.include_control_details)
            )

        if opts.include_gap_analysis:
            sections.append(_build_gap_analysis(report.gaps))

        sections.append("---")
        sections.append(
            "*Generated by aumos/compliance-mapper — point-in-time evidence snapshot.*"
        )
        sections.append("")

        return "\n".join(sections)

    def to_json(
        self,
        report: ComplianceReport,
        options: JsonRendererOptions | None = None,
    ) -> str:
        """
        Render a ``ComplianceReport`` as a JSON string.

        Parameters
        ----------
        report:
            The compliance report to render.
        options:
            Rendering options.  Defaults to ``JsonRendererOptions()``.

        Returns
        -------
        str
            JSON string representation of the report.
        """
        opts = options if options is not None else JsonRendererOptions()
        report_dict = _report_to_dict(report, opts.include_evidence)
        indent: int | None = opts.indent if opts.indent > 0 else None
        return json.dumps(report_dict, indent=indent, ensure_ascii=False)
