// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview EvidenceGenerator — converts raw ControlEvidenceCollections into
 * structured ControlAssessments, EvidenceItems, and GapItems.
 *
 * All logic here is pure and deterministic given the same inputs.
 */

import { randomUUID } from "node:crypto";
import type {
  ControlAssessment,
  ControlStatus,
  EvidenceItem,
  GapItem,
} from "../types.js";
import type { ControlEvidenceCollection } from "./types.js";

/**
 * Parameters needed to generate a ControlAssessment from collected evidence.
 */
export interface AssessmentGenerationParams {
  readonly controlId: string;
  readonly title: string;
  readonly description: string;
  readonly frameworkId: string;
  readonly collection: ControlEvidenceCollection;
  readonly includeAuditEventGaps: boolean;
  readonly isExcluded: boolean;
}

/**
 * Derives a ControlStatus from the count of satisfied and gap paths/events.
 */
function deriveStatus(
  satisfiedPaths: readonly string[],
  gapPaths: readonly string[],
  satisfiedEvents: readonly string[],
  missingEvents: readonly string[],
  includeAuditEventGaps: boolean,
): ControlStatus {
  const totalConfig = satisfiedPaths.length + gapPaths.length;
  const satisfiedConfig = satisfiedPaths.length;

  const totalAudit = includeAuditEventGaps
    ? satisfiedEvents.length + missingEvents.length
    : satisfiedEvents.length + missingEvents.length;

  const hasAuditRequirements = totalAudit > 0 && includeAuditEventGaps;

  if (totalConfig === 0 && !hasAuditRequirements) {
    // No requirements defined — treat as not assessed.
    return "not_applicable";
  }

  const configSatisfied = totalConfig === 0 || satisfiedConfig === totalConfig;
  const auditSatisfied = !hasAuditRequirements || missingEvents.length === 0;

  if (configSatisfied && auditSatisfied) {
    return "satisfied";
  }

  // All config paths missing and no audit events = full gap.
  if (satisfiedConfig === 0 && (!hasAuditRequirements || satisfiedEvents.length === 0)) {
    return "gap";
  }

  return "partial";
}

/**
 * Derives gap severity from the ratio of missing items.
 */
function deriveSeverity(
  gapPaths: readonly string[],
  missingEvents: readonly string[],
  totalPaths: number,
  totalEvents: number,
): GapItem["severity"] {
  const totalMissing = gapPaths.length + missingEvents.length;
  const totalRequired = totalPaths + totalEvents;

  if (totalRequired === 0) {
    return "low";
  }

  const missingRatio = totalMissing / totalRequired;

  if (missingRatio >= 0.8) return "critical";
  if (missingRatio >= 0.5) return "high";
  if (missingRatio >= 0.25) return "medium";
  return "low";
}

/**
 * Builds a human-readable gap description.
 */
function buildGapDescription(
  gapPaths: readonly string[],
  missingEvents: readonly string[],
): string {
  const parts: string[] = [];

  if (gapPaths.length > 0) {
    parts.push(
      `Missing governance configuration: ${gapPaths.slice(0, 3).join(", ")}${gapPaths.length > 3 ? ` and ${gapPaths.length - 3} more` : ""}.`,
    );
  }

  if (missingEvents.length > 0) {
    parts.push(
      `No audit log evidence for: ${missingEvents.slice(0, 3).join(", ")}${missingEvents.length > 3 ? ` and ${missingEvents.length - 3} more` : ""}.`,
    );
  }

  return parts.join(" ");
}

/**
 * Builds a remediation recommendation from the gap description.
 */
function buildRecommendation(
  gapPaths: readonly string[],
  missingEvents: readonly string[],
  controlTitle: string,
): string {
  if (gapPaths.length > 0 && missingEvents.length > 0) {
    return `Establish governance policies for "${controlTitle}" and ensure relevant operations are captured in audit logs. Start by populating: ${gapPaths[0] ?? ""}.`;
  }
  if (gapPaths.length > 0) {
    return `Populate the governance configuration paths for "${controlTitle}". Start with: ${gapPaths[0] ?? ""}.`;
  }
  return `Ensure operations related to "${controlTitle}" generate audit log entries, particularly: ${missingEvents[0] ?? ""}.`;
}

/**
 * EvidenceGenerator converts raw ControlEvidenceCollections into fully
 * structured compliance assessment objects.
 */
export class EvidenceGenerator {
  /**
   * Generates a ControlAssessment from a raw evidence collection.
   */
  generateAssessment(params: AssessmentGenerationParams): ControlAssessment {
    const {
      controlId,
      title,
      description,
      collection,
      includeAuditEventGaps,
      isExcluded,
    } = params;

    if (isExcluded) {
      return {
        controlId,
        title,
        description,
        status: "not_applicable",
        evidence: [],
        satisfiedPaths: [],
        gapPaths: [],
        satisfiedEvents: [],
        missingEvents: [],
      };
    }

    const satisfiedPaths = collection.configResolutions
      .filter((resolution) => resolution.found)
      .map((resolution) => resolution.path);

    const gapPaths = collection.configResolutions
      .filter((resolution) => !resolution.found)
      .map((resolution) => resolution.path);

    const satisfiedEvents = collection.auditEventResolutions
      .filter((resolution) => resolution.found)
      .map((resolution) => resolution.eventType);

    const missingEvents = includeAuditEventGaps
      ? collection.auditEventResolutions
          .filter((resolution) => !resolution.found)
          .map((resolution) => resolution.eventType)
      : [];

    const status = deriveStatus(
      satisfiedPaths,
      gapPaths,
      satisfiedEvents,
      missingEvents,
      includeAuditEventGaps,
    );

    // Build evidence items from config resolutions.
    const configEvidence: EvidenceItem[] = collection.configResolutions
      .filter((resolution) => resolution.found)
      .map((resolution) => ({
        evidenceId: randomUUID(),
        title: `Config: ${resolution.path}`,
        description: `Governance configuration path "${resolution.path}" is populated.`,
        sourceKind: "governance_config" as const,
        sourcePath: resolution.path,
        value: resolution.value,
        collectedAt: collection.collectedAt,
        isPresent: true,
      }));

    // Build evidence items from audit log resolutions.
    const auditEvidence: EvidenceItem[] = collection.auditEventResolutions
      .filter((resolution) => resolution.found)
      .map((resolution) => ({
        evidenceId: randomUUID(),
        title: `Audit: ${resolution.eventType}`,
        description: `Audit log event "${resolution.eventType}" was observed ${resolution.occurrenceCount} time(s). Most recent: ${resolution.lastSeenAt ?? "unknown"}.`,
        sourceKind: "audit_log" as const,
        sourcePath: resolution.eventType,
        value: resolution.occurrenceCount,
        collectedAt: collection.collectedAt,
        isPresent: true,
      }));

    const evidence = [...configEvidence, ...auditEvidence];

    const gapDescription =
      status !== "satisfied" && status !== "not_applicable"
        ? buildGapDescription(gapPaths, missingEvents)
        : undefined;

    return {
      controlId,
      title,
      description,
      status,
      evidence,
      satisfiedPaths,
      gapPaths,
      satisfiedEvents,
      missingEvents,
      ...(gapDescription !== undefined ? { gapDescription } : {}),
    };
  }

  /**
   * Generates a GapItem from a ControlAssessment that has gaps.
   * Returns `null` if the assessment is fully satisfied or not applicable.
   */
  generateGapItem(
    frameworkId: string,
    assessment: ControlAssessment,
  ): GapItem | null {
    if (assessment.status === "satisfied" || assessment.status === "not_applicable") {
      return null;
    }

    const totalPaths = assessment.satisfiedPaths.length + assessment.gapPaths.length;
    const totalEvents = assessment.satisfiedEvents.length + assessment.missingEvents.length;

    const severity = deriveSeverity(
      assessment.gapPaths,
      assessment.missingEvents,
      totalPaths,
      totalEvents,
    );

    const recommendation = buildRecommendation(
      assessment.gapPaths,
      assessment.missingEvents,
      assessment.title,
    );

    return {
      frameworkId,
      controlId: assessment.controlId,
      controlTitle: assessment.title,
      missingConfigPaths: assessment.gapPaths,
      missingAuditEvents: assessment.missingEvents,
      severity,
      recommendation,
    };
  }
}
