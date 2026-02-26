// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview Public API surface of @aumos/compliance-mapper.
 *
 * @example Basic usage:
 * ```typescript
 * import {
 *   ComplianceMapper,
 *   SOC2Framework,
 *   GDPRFramework,
 *   EUAIActFramework,
 *   renderMarkdownReport,
 *   renderJsonReport,
 * } from "@aumos/compliance-mapper";
 *
 * const mapper = new ComplianceMapper();
 * const report = await mapper.map(config, auditLog, [
 *   new SOC2Framework(),
 *   new GDPRFramework(),
 *   new EUAIActFramework(),
 * ]);
 *
 * const markdown = renderMarkdownReport(report);
 * const json = renderJsonReport(report);
 * ```
 */

// ── Core ──────────────────────────────────────────────────────────────────────

export { ComplianceMapper } from "./mapper.js";

// ── Frameworks ────────────────────────────────────────────────────────────────

export type { ComplianceFramework, FrameworkMetadata } from "./frameworks/interface.js";
export { SOC2Framework } from "./frameworks/soc2.js";
export { GDPRFramework } from "./frameworks/gdpr.js";
export { EUAIActFramework } from "./frameworks/eu-ai-act.js";

// ── Evidence ─────────────────────────────────────────────────────────────────

export { EvidenceCollector } from "./evidence/collector.js";
export { EvidenceGenerator } from "./evidence/generator.js";
export type { AssessmentGenerationParams } from "./evidence/generator.js";
export type {
  ConfigPathResolution,
  AuditEventResolution,
  ControlEvidenceCollection,
} from "./evidence/types.js";

// ── Reports ───────────────────────────────────────────────────────────────────

export { renderMarkdownReport } from "./report/markdown.js";
export type { MarkdownRendererOptions } from "./report/markdown.js";
export { renderJsonReport } from "./report/json.js";
export type { JsonRendererOptions } from "./report/json.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export type {
  // Configuration inputs
  GovernanceConfig,
  GovernanceConfigRecord,
  GovernanceConfigValue,
  AuditLog,
  AuditLogEntry,
  // Evidence
  EvidenceItem,
  EvidenceSourceKind,
  // Assessments
  ControlAssessment,
  ControlStatus,
  // Results
  FrameworkResult,
  GapItem,
  // Report
  ComplianceReport,
  ReportSummary,
  // Options
  MapperOptions,
} from "./types.js";
