// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview Markdown report renderer.
 *
 * Produces human-readable compliance evidence reports in Markdown format,
 * suitable for audit packages, GitHub comments, or Notion/Confluence imports.
 */

import type {
  ComplianceReport,
  FrameworkResult,
  ControlAssessment,
  GapItem,
  ControlStatus,
} from "../types.js";

// ── Status formatting ────────────────────────────────────────────────────────

const STATUS_BADGE: Record<ControlStatus, string> = {
  satisfied: "PASS",
  gap: "GAP",
  partial: "PARTIAL",
  not_applicable: "N/A",
};

const STATUS_INDICATOR: Record<ControlStatus, string> = {
  satisfied: "✓",
  gap: "✗",
  partial: "~",
  not_applicable: "-",
};

function formatStatus(status: ControlStatus): string {
  return `**[${STATUS_BADGE[status]}]** ${STATUS_INDICATOR[status]}`;
}

function severityLabel(severity: GapItem["severity"]): string {
  const labels: Record<GapItem["severity"], string> = {
    critical: "CRITICAL",
    high: "HIGH",
    medium: "MEDIUM",
    low: "LOW",
  };
  return labels[severity];
}

// ── Section builders ─────────────────────────────────────────────────────────

function buildExecutiveSummary(report: ComplianceReport): string {
  const { summary } = report;
  const compliancePercent = (summary.overallComplianceRate * 100).toFixed(1);

  const lines: string[] = [
    "## Executive Summary",
    "",
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Assessment Period | ${report.assessmentPeriodStart} — ${report.assessmentPeriodEnd} |`,
    `| Frameworks Assessed | ${summary.totalFrameworks} |`,
    `| Total Controls | ${summary.totalControls} |`,
    `| Satisfied | ${summary.totalSatisfied} |`,
    `| Gaps | ${summary.totalGaps} |`,
    `| Partial | ${summary.totalPartial} |`,
    `| Overall Compliance Rate | ${compliancePercent}% |`,
    `| Critical Gaps | ${summary.criticalGapsCount} |`,
    "",
  ];

  return lines.join("\n");
}

function buildControlTable(controls: readonly ControlAssessment[]): string {
  const lines: string[] = [
    "| Control ID | Title | Status | Satisfied Paths | Gap Paths |",
    "|-----------|-------|--------|-----------------|-----------|",
  ];

  for (const control of controls) {
    const title = control.title.length > 50
      ? `${control.title.slice(0, 47)}...`
      : control.title;
    lines.push(
      `| ${control.controlId} | ${title} | ${formatStatus(control.status)} | ${control.satisfiedPaths.length} | ${control.gapPaths.length} |`,
    );
  }

  return lines.join("\n");
}

function buildControlDetail(control: ControlAssessment): string {
  const lines: string[] = [
    `### ${control.controlId} — ${control.title}`,
    "",
    `> ${control.description}`,
    "",
    `**Status:** ${formatStatus(control.status)}`,
    "",
  ];

  if (control.satisfiedPaths.length > 0) {
    lines.push("**Satisfied configuration paths:**");
    for (const path of control.satisfiedPaths) {
      lines.push(`- \`${path}\``);
    }
    lines.push("");
  }

  if (control.gapPaths.length > 0) {
    lines.push("**Missing configuration paths:**");
    for (const path of control.gapPaths) {
      lines.push(`- \`${path}\``);
    }
    lines.push("");
  }

  if (control.satisfiedEvents.length > 0) {
    lines.push("**Audit log events observed:**");
    for (const eventType of control.satisfiedEvents) {
      lines.push(`- \`${eventType}\``);
    }
    lines.push("");
  }

  if (control.missingEvents.length > 0) {
    lines.push("**Missing audit log events:**");
    for (const eventType of control.missingEvents) {
      lines.push(`- \`${eventType}\``);
    }
    lines.push("");
  }

  if (control.gapDescription !== undefined) {
    lines.push(`**Gap description:** ${control.gapDescription}`);
    lines.push("");
  }

  if (control.evidence.length > 0) {
    lines.push(`**Evidence items collected:** ${control.evidence.length}`);
    lines.push("");
  }

  lines.push("---");
  lines.push("");

  return lines.join("\n");
}

function buildFrameworkSection(frameworkResult: FrameworkResult): string {
  const lines: string[] = [
    `## ${frameworkResult.frameworkName} (${frameworkResult.frameworkVersion})`,
    "",
    `| Category | Count |`,
    `|----------|-------|`,
    `| Satisfied | ${frameworkResult.satisfiedCount} |`,
    `| Gaps | ${frameworkResult.gapCount} |`,
    `| Partial | ${frameworkResult.partialCount} |`,
    `| Not Applicable | ${frameworkResult.notApplicableCount} |`,
    `| **Total** | **${frameworkResult.totalCount}** |`,
    "",
    "### Control Summary",
    "",
    buildControlTable(frameworkResult.controls),
    "",
    "### Control Details",
    "",
  ];

  for (const control of frameworkResult.controls) {
    lines.push(buildControlDetail(control));
  }

  return lines.join("\n");
}

function buildGapAnalysis(gaps: readonly GapItem[]): string {
  if (gaps.length === 0) {
    return "## Gap Analysis\n\nNo gaps identified across all frameworks.\n";
  }

  const lines: string[] = [
    "## Gap Analysis",
    "",
    `${gaps.length} gap(s) identified across all frameworks.`,
    "",
    "| Framework | Control | Severity | Missing Config Paths | Recommendation |",
    "|-----------|---------|----------|---------------------|----------------|",
  ];

  for (const gap of gaps) {
    const missingPaths = gap.missingConfigPaths.length > 0
      ? gap.missingConfigPaths.slice(0, 2).join(", ") + (gap.missingConfigPaths.length > 2 ? "…" : "")
      : "—";
    const recommendation = gap.recommendation.length > 60
      ? `${gap.recommendation.slice(0, 57)}…`
      : gap.recommendation;
    lines.push(
      `| ${gap.frameworkId} | ${gap.controlId} | ${severityLabel(gap.severity)} | \`${missingPaths}\` | ${recommendation} |`,
    );
  }

  lines.push("");
  lines.push("### Gap Details");
  lines.push("");

  for (const gap of gaps) {
    lines.push(`#### [${severityLabel(gap.severity)}] ${gap.frameworkId} — ${gap.controlId}: ${gap.controlTitle}`);
    lines.push("");
    if (gap.missingConfigPaths.length > 0) {
      lines.push("**Missing governance configuration paths:**");
      for (const path of gap.missingConfigPaths) {
        lines.push(`- \`${path}\``);
      }
      lines.push("");
    }
    if (gap.missingAuditEvents.length > 0) {
      lines.push("**Missing audit log events:**");
      for (const eventType of gap.missingAuditEvents) {
        lines.push(`- \`${eventType}\``);
      }
      lines.push("");
    }
    lines.push(`**Recommendation:** ${gap.recommendation}`);
    lines.push("");
    lines.push("---");
    lines.push("");
  }

  return lines.join("\n");
}

// ── Public renderer ──────────────────────────────────────────────────────────

/**
 * Options for Markdown report rendering.
 */
export interface MarkdownRendererOptions {
  /**
   * Title to use as the top-level heading.
   * Defaults to "Compliance Evidence Report".
   */
  readonly reportTitle?: string;
  /**
   * Whether to include per-control detail sections.
   * Set to `false` for a summary-only report.
   * Defaults to `true`.
   */
  readonly includeControlDetails?: boolean;
  /**
   * Whether to include the gap analysis section.
   * Defaults to `true`.
   */
  readonly includeGapAnalysis?: boolean;
}

/**
 * Renders a ComplianceReport as a Markdown document.
 *
 * @param report - The compliance report to render.
 * @param options - Rendering options.
 * @returns A Markdown string suitable for saving as `.md` or displaying inline.
 */
export function renderMarkdownReport(
  report: ComplianceReport,
  options: MarkdownRendererOptions = {},
): string {
  const reportTitle = options.reportTitle ?? "Compliance Evidence Report";
  const includeControlDetails = options.includeControlDetails ?? true;
  const includeGapAnalysis = options.includeGapAnalysis ?? true;

  const sections: string[] = [
    `# ${reportTitle}`,
    "",
    `**Report ID:** \`${report.reportId}\``,
    `**Generated:** ${report.generatedAt}`,
    `**Assessment Period:** ${report.assessmentPeriodStart} — ${report.assessmentPeriodEnd}`,
    "",
    buildExecutiveSummary(report),
  ];

  for (const frameworkResult of report.frameworkResults) {
    if (includeControlDetails) {
      sections.push(buildFrameworkSection(frameworkResult));
    } else {
      sections.push(
        `## ${frameworkResult.frameworkName} (${frameworkResult.frameworkVersion})`,
        "",
        buildControlTable(frameworkResult.controls),
        "",
      );
    }
  }

  if (includeGapAnalysis) {
    sections.push(buildGapAnalysis(report.gaps));
  }

  sections.push("---");
  sections.push("*Generated by @aumos/compliance-mapper — point-in-time evidence snapshot.*");
  sections.push("");

  return sections.join("\n");
}
