// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview ComplianceFramework interface.
 *
 * Implement this interface to add a new regulatory framework to the mapper.
 * Built-in implementations: SOC2Framework, GDPRFramework, EUAIActFramework.
 */

import type { ControlAssessment, GovernanceConfig, AuditLog, MapperOptions } from "../types.js";

/**
 * Metadata describing a compliance framework.
 */
export interface FrameworkMetadata {
  /** Stable machine-readable identifier, lowercase with hyphens. */
  readonly id: string;
  /** Human-readable display name (e.g. "SOC 2 Type II"). */
  readonly name: string;
  /** Regulation version or year (e.g. "2017", "2016/679"). */
  readonly version: string;
  /** Issuing body or reference (e.g. "AICPA", "EU Official Journal"). */
  readonly source: string;
  /** Brief scope description shown in reports. */
  readonly scopeDescription: string;
}

/**
 * Pluggable compliance framework interface.
 *
 * Each framework knows its own controls and how to assess them against a
 * governance configuration and audit log. The mapper orchestrates collection
 * across multiple framework instances.
 *
 * @example Implementing a custom framework:
 * ```typescript
 * import type { ComplianceFramework, FrameworkMetadata } from "@aumos/compliance-mapper";
 *
 * export class ISO27001Framework implements ComplianceFramework {
 *   get metadata(): FrameworkMetadata {
 *     return {
 *       id: "iso27001",
 *       name: "ISO/IEC 27001:2022",
 *       version: "2022",
 *       source: "ISO/IEC",
 *       scopeDescription: "Information security management system controls",
 *     };
 *   }
 *
 *   listControlIds(): readonly string[] {
 *     return ["A.5.1", "A.5.2", /* ... * /];
 *   }
 *
 *   async assess(
 *     governanceConfig: GovernanceConfig,
 *     auditLog: AuditLog,
 *     options: MapperOptions
 *   ): Promise<readonly ControlAssessment[]> {
 *     // ... your assessment logic
 *   }
 * }
 * ```
 */
export interface ComplianceFramework {
  /** Framework identification and metadata. */
  readonly metadata: FrameworkMetadata;

  /**
   * Returns all control or article IDs this framework can assess.
   * Used by the mapper to apply `excludeControlIds` filtering.
   */
  listControlIds(): readonly string[];

  /**
   * Assesses all controls against the provided governance config and audit log.
   *
   * @param governanceConfig - The full governance configuration object.
   * @param auditLog - The structured audit log for the assessment period.
   * @param options - Mapper options (e.g. exclusion list, timestamp).
   * @returns An array of control assessments — one per control/article.
   */
  assess(
    governanceConfig: GovernanceConfig,
    auditLog: AuditLog,
    options: MapperOptions,
  ): Promise<readonly ControlAssessment[]>;
}
