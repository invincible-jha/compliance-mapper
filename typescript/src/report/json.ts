// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview JSON report renderer.
 *
 * Serialises a ComplianceReport to a structured JSON string suitable for
 * storage, API responses, or downstream processing.
 */

import type { ComplianceReport } from "../types.js";

/**
 * Options for JSON report rendering.
 */
export interface JsonRendererOptions {
  /**
   * Number of spaces for indentation.
   * Use `0` for compact output. Defaults to `2`.
   */
  readonly indent?: number;
  /**
   * Whether to include individual evidence items in the output.
   * Set to `false` to produce a leaner summary-only report.
   * Defaults to `true`.
   */
  readonly includeEvidence?: boolean;
}

/**
 * Renders a ComplianceReport as a JSON string.
 *
 * @param report - The compliance report to render.
 * @param options - Rendering options.
 * @returns A JSON string representation of the report.
 */
export function renderJsonReport(
  report: ComplianceReport,
  options: JsonRendererOptions = {},
): string {
  const indent = options.indent ?? 2;
  const includeEvidence = options.includeEvidence ?? true;

  if (includeEvidence) {
    return JSON.stringify(report, null, indent);
  }

  // Strip evidence arrays to produce a leaner output.
  const stripped = {
    ...report,
    frameworkResults: report.frameworkResults.map((frameworkResult) => ({
      ...frameworkResult,
      controls: frameworkResult.controls.map((control) => ({
        ...control,
        evidence: [],
      })),
    })),
  };

  return JSON.stringify(stripped, null, indent);
}
