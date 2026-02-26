// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview ComplianceMapper — the main engine of @aumos/compliance-mapper.
 *
 * Orchestrates multiple ComplianceFramework implementations against a
 * GovernanceConfig and AuditLog, producing a single ComplianceReport.
 *
 * All state is created fresh per `map()` invocation — the mapper itself is
 * intentionally stateless and safe to reuse across calls.
 */

import { randomUUID } from "node:crypto";
import type { ComplianceFramework } from "./frameworks/interface.js";
import type {
  GovernanceConfig,
  AuditLog,
  ComplianceReport,
  FrameworkResult,
  GapItem,
  ReportSummary,
  MapperOptions,
  ControlAssessment,
} from "./types.js";
import { EvidenceGenerator } from "./evidence/generator.js";

/**
 * Derives aggregate statistics for a single framework's control assessments.
 */
function deriveFrameworkResult(
  frameworkId: string,
  frameworkName: string,
  frameworkVersion: string,
  controls: readonly ControlAssessment[],
): FrameworkResult {
  let satisfiedCount = 0;
  let gapCount = 0;
  let partialCount = 0;
  let notApplicableCount = 0;

  for (const control of controls) {
    switch (control.status) {
      case "satisfied":
        satisfiedCount++;
        break;
      case "gap":
        gapCount++;
        break;
      case "partial":
        partialCount++;
        break;
      case "not_applicable":
        notApplicableCount++;
        break;
    }
  }

  return {
    frameworkId,
    frameworkName,
    frameworkVersion,
    controls,
    satisfiedCount,
    gapCount,
    partialCount,
    notApplicableCount,
    totalCount: controls.length,
  };
}

/**
 * Computes the overall report summary from all framework results and gaps.
 */
function deriveReportSummary(
  frameworkResults: readonly FrameworkResult[],
  gaps: readonly GapItem[],
): ReportSummary {
  let totalControls = 0;
  let totalSatisfied = 0;
  let totalGaps = 0;
  let totalPartial = 0;

  for (const frameworkResult of frameworkResults) {
    totalControls += frameworkResult.totalCount;
    totalSatisfied += frameworkResult.satisfiedCount;
    totalGaps += frameworkResult.gapCount;
    totalPartial += frameworkResult.partialCount;
  }

  const assessedControls = totalControls - frameworkResults.reduce(
    (sum, frameworkResult) => sum + frameworkResult.notApplicableCount,
    0,
  );

  const overallComplianceRate = assessedControls > 0
    ? totalSatisfied / assessedControls
    : 0;

  const criticalGapsCount = gaps.filter((gap) => gap.severity === "critical").length;

  return {
    totalFrameworks: frameworkResults.length,
    totalControls,
    totalSatisfied,
    totalGaps,
    totalPartial,
    overallComplianceRate,
    criticalGapsCount,
  };
}

/**
 * ComplianceMapper is the primary entry point for generating compliance
 * evidence reports from governance configurations and audit logs.
 *
 * It is intentionally stateless — each `map()` call produces an independent
 * ComplianceReport snapshot.
 *
 * @example
 * ```typescript
 * const mapper = new ComplianceMapper();
 * const report = await mapper.map(
 *   governanceConfig,
 *   auditLog,
 *   [new SOC2Framework(), new GDPRFramework(), new EUAIActFramework()],
 *   { includeAuditEventGaps: true }
 * );
 * ```
 */
export class ComplianceMapper {
  private readonly generator: EvidenceGenerator;

  constructor() {
    this.generator = new EvidenceGenerator();
  }

  /**
   * Maps a governance configuration and audit log against one or more
   * compliance frameworks, returning a structured evidence report.
   *
   * @param governanceConfig - The governance configuration to assess.
   * @param auditLog - Structured audit log covering the assessment period.
   * @param frameworks - One or more ComplianceFramework implementations to assess against.
   * @param options - Optional mapping behaviour overrides.
   * @returns A ComplianceReport containing assessments, gaps, and summary statistics.
   *
   * @throws {Error} If `frameworks` is empty.
   */
  async map(
    governanceConfig: GovernanceConfig,
    auditLog: AuditLog,
    frameworks: readonly ComplianceFramework[],
    options: MapperOptions = {},
  ): Promise<ComplianceReport> {
    if (frameworks.length === 0) {
      throw new Error(
        "ComplianceMapper.map() requires at least one framework. Pass instances of SOC2Framework, GDPRFramework, EUAIActFramework, or a custom ComplianceFramework implementation.",
      );
    }

    const reportTimestamp = options.reportTimestamp ?? new Date().toISOString();
    const resolvedOptions: MapperOptions = {
      ...options,
      reportTimestamp,
    };

    // Run all framework assessments concurrently.
    const frameworkAssessmentPairs = await Promise.all(
      frameworks.map(async (framework) => {
        const controls = await framework.assess(
          governanceConfig,
          auditLog,
          resolvedOptions,
        );
        return { framework, controls };
      }),
    );

    // Build FrameworkResult objects and collect all gaps.
    const frameworkResults: FrameworkResult[] = [];
    const allGaps: GapItem[] = [];

    for (const { framework, controls } of frameworkAssessmentPairs) {
      const frameworkResult = deriveFrameworkResult(
        framework.metadata.id,
        framework.metadata.name,
        framework.metadata.version,
        controls,
      );
      frameworkResults.push(frameworkResult);

      for (const control of controls) {
        const gap = this.generator.generateGapItem(framework.metadata.id, control);
        if (gap !== null) {
          allGaps.push(gap);
        }
      }
    }

    // Sort gaps by severity (critical first).
    const severityOrder: Record<GapItem["severity"], number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
    };
    allGaps.sort((gapA, gapB) => severityOrder[gapA.severity] - severityOrder[gapB.severity]);

    const summary = deriveReportSummary(frameworkResults, allGaps);

    return {
      reportId: randomUUID(),
      generatedAt: reportTimestamp,
      assessmentPeriodStart: auditLog.startPeriod,
      assessmentPeriodEnd: auditLog.endPeriod,
      frameworkResults,
      gaps: allGaps,
      summary,
    };
  }
}
