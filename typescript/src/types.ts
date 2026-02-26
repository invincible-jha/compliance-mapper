// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview Core type definitions for @aumos/compliance-mapper.
 *
 * All types are designed for point-in-time compliance evidence generation.
 * No mutable state is held between mapper invocations.
 */

// ── Governance Configuration ─────────────────────────────────────────────────

/**
 * A nested configuration object representing governance settings.
 * Keys are dot-separated path segments at each nesting level.
 * Values are configuration entries or further nested objects.
 */
export type GovernanceConfigValue =
  | string
  | number
  | boolean
  | null
  | readonly GovernanceConfigValue[]
  | GovernanceConfigRecord;

export type GovernanceConfigRecord = {
  readonly [key: string]: GovernanceConfigValue;
};

/**
 * Top-level governance configuration passed into the mapper.
 * Mirrors the structure referenced by `governanceConfigPaths` in the mapping JSONs.
 *
 * @example
 * ```json
 * {
 *   "governance": {
 *     "access": { "mfaPolicy": "required", "rbacPolicy": "least-privilege" },
 *     "privacy": { "dpoContact": "dpo@example.com" }
 *   }
 * }
 * ```
 */
export type GovernanceConfig = GovernanceConfigRecord;

// ── Audit Log ────────────────────────────────────────────────────────────────

/**
 * A single structured audit log entry.
 */
export interface AuditLogEntry {
  /** ISO 8601 timestamp of the event. */
  readonly timestamp: string;
  /** Machine-readable event identifier matching mapping `auditLogEvents`. */
  readonly eventType: string;
  /** Actor that triggered the event (user ID, service name, etc.). */
  readonly actor: string;
  /** Free-form metadata specific to the event type. */
  readonly metadata: GovernanceConfigRecord;
  /** Outcome of the event. */
  readonly outcome: "success" | "failure" | "partial";
  /** Optional reference to the resource affected. */
  readonly resourceId?: string;
}

/**
 * Structured audit log containing time-ordered entries.
 */
export interface AuditLog {
  /** ISO 8601 timestamp marking the start of the log window. */
  readonly startPeriod: string;
  /** ISO 8601 timestamp marking the end of the log window. */
  readonly endPeriod: string;
  readonly entries: readonly AuditLogEntry[];
}

// ── Evidence ─────────────────────────────────────────────────────────────────

/** Classification of the evidence source. */
export type EvidenceSourceKind = "governance_config" | "audit_log" | "generated_document";

/**
 * A discrete piece of compliance evidence tied to a control or article.
 */
export interface EvidenceItem {
  /** Unique identifier for this evidence item within a report. */
  readonly evidenceId: string;
  /** Human-readable label. */
  readonly title: string;
  /** Description of what this evidence demonstrates. */
  readonly description: string;
  /** How the evidence was obtained. */
  readonly sourceKind: EvidenceSourceKind;
  /** Dot-separated config path or audit log event type that sourced this item. */
  readonly sourcePath: string;
  /** The raw value or summary retrieved from the source. */
  readonly value: GovernanceConfigValue;
  /** ISO 8601 timestamp when this evidence was collected. */
  readonly collectedAt: string;
  /** Whether this evidence is present and meaningful. */
  readonly isPresent: boolean;
}

// ── Control / Article Assessment ─────────────────────────────────────────────

/** Pass/fail/gap status of a single compliance control or article. */
export type ControlStatus = "satisfied" | "gap" | "partial" | "not_applicable";

/**
 * Assessment of a single framework control or regulatory article.
 */
export interface ControlAssessment {
  /** Framework-specific control or article identifier (e.g. "CC6.1", "Art32"). */
  readonly controlId: string;
  /** Human-readable title from the mapping JSON. */
  readonly title: string;
  /** Narrative description of the control's intent. */
  readonly description: string;
  /** Aggregate status based on collected evidence. */
  readonly status: ControlStatus;
  /** Evidence items collected for this control. */
  readonly evidence: readonly EvidenceItem[];
  /** Config paths that were present in the governance config. */
  readonly satisfiedPaths: readonly string[];
  /** Config paths that were missing or empty. */
  readonly gapPaths: readonly string[];
  /** Audit log events that were found in the log window. */
  readonly satisfiedEvents: readonly string[];
  /** Audit log events that were not found. */
  readonly missingEvents: readonly string[];
  /** Human-readable gap description if status is "gap" or "partial". */
  readonly gapDescription?: string;
}

// ── Framework Result ─────────────────────────────────────────────────────────

/**
 * Full results for one regulatory framework within a report.
 */
export interface FrameworkResult {
  /** Machine-readable framework identifier (e.g. "soc2", "gdpr", "eu-ai-act"). */
  readonly frameworkId: string;
  /** Display name of the framework. */
  readonly frameworkName: string;
  /** Version or regulation number. */
  readonly frameworkVersion: string;
  /** All control/article assessments for this framework. */
  readonly controls: readonly ControlAssessment[];
  /** Number of controls with status "satisfied". */
  readonly satisfiedCount: number;
  /** Number of controls with status "gap". */
  readonly gapCount: number;
  /** Number of controls with status "partial". */
  readonly partialCount: number;
  /** Number of controls with status "not_applicable". */
  readonly notApplicableCount: number;
  /** Total controls assessed. */
  readonly totalCount: number;
}

// ── Gap Analysis ─────────────────────────────────────────────────────────────

/**
 * Aggregated gap identified across frameworks.
 */
export interface GapItem {
  /** The framework this gap belongs to. */
  readonly frameworkId: string;
  /** The control or article with the gap. */
  readonly controlId: string;
  /** Title of the control. */
  readonly controlTitle: string;
  /** Missing governance config paths. */
  readonly missingConfigPaths: readonly string[];
  /** Missing audit log event types. */
  readonly missingAuditEvents: readonly string[];
  /** Severity derived from gap completeness. */
  readonly severity: "critical" | "high" | "medium" | "low";
  /** Suggested remediation action. */
  readonly recommendation: string;
}

// ── Compliance Report ─────────────────────────────────────────────────────────

/**
 * Top-level output of `ComplianceMapper.map()`.
 * Immutable, serialisable, and timestamped for audit trail purposes.
 */
export interface ComplianceReport {
  /** Unique report identifier. */
  readonly reportId: string;
  /** ISO 8601 timestamp when the report was generated. */
  readonly generatedAt: string;
  /** ISO 8601 start of the audit log window assessed. */
  readonly assessmentPeriodStart: string;
  /** ISO 8601 end of the audit log window assessed. */
  readonly assessmentPeriodEnd: string;
  /** Results per framework. */
  readonly frameworkResults: readonly FrameworkResult[];
  /** All gaps identified across all frameworks. */
  readonly gaps: readonly GapItem[];
  /** High-level summary statistics. */
  readonly summary: ReportSummary;
}

/**
 * High-level statistics surfaced in a compliance report.
 */
export interface ReportSummary {
  readonly totalFrameworks: number;
  readonly totalControls: number;
  readonly totalSatisfied: number;
  readonly totalGaps: number;
  readonly totalPartial: number;
  readonly overallComplianceRate: number;
  readonly criticalGapsCount: number;
}

// ── Mapper Options ────────────────────────────────────────────────────────────

/**
 * Options passed to `ComplianceMapper.map()`.
 */
export interface MapperOptions {
  /**
   * ISO 8601 timestamp to use as the report's "generated at" value.
   * Defaults to `new Date().toISOString()`.
   */
  readonly reportTimestamp?: string;
  /**
   * Whether to include audit log events that were not found as explicit gap items.
   * Defaults to `true`.
   */
  readonly includeAuditEventGaps?: boolean;
  /**
   * Controls with these IDs will be marked "not_applicable" rather than assessed.
   */
  readonly excludeControlIds?: readonly string[];
}
