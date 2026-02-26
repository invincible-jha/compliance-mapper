// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview Internal types for the evidence collection and generation pipeline.
 */

import type { GovernanceConfigValue } from "../types.js";

/**
 * Result of resolving a single dot-separated config path against a governance config.
 */
export interface ConfigPathResolution {
  /** The dot-separated path that was resolved. */
  readonly path: string;
  /** Whether the path existed and had a non-null, non-empty value. */
  readonly found: boolean;
  /** The resolved value, or `null` if not found. */
  readonly value: GovernanceConfigValue | null;
}

/**
 * Result of searching the audit log for a specific event type.
 */
export interface AuditEventResolution {
  /** The event type that was searched for. */
  readonly eventType: string;
  /** Whether at least one matching entry was found. */
  readonly found: boolean;
  /** The most recent matching entry's timestamp, if found. */
  readonly lastSeenAt: string | null;
  /** Total number of matching entries found. */
  readonly occurrenceCount: number;
}

/**
 * Aggregated collection result for a single control or article.
 */
export interface ControlEvidenceCollection {
  /** Framework-specific control or article identifier. */
  readonly controlId: string;
  /** Resolutions for each required governance config path. */
  readonly configResolutions: readonly ConfigPathResolution[];
  /** Resolutions for each required audit log event. */
  readonly auditEventResolutions: readonly AuditEventResolution[];
  /** ISO 8601 timestamp when collection ran. */
  readonly collectedAt: string;
}
