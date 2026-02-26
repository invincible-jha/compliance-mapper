// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview EvidenceCollector — resolves governance config paths and audit
 * log event lookups for a given set of control requirements.
 */

import type {
  GovernanceConfig,
  GovernanceConfigValue,
  AuditLog,
  AuditLogEntry,
} from "../types.js";
import type {
  ConfigPathResolution,
  AuditEventResolution,
  ControlEvidenceCollection,
} from "./types.js";

/**
 * Resolves a dot-separated path (e.g. `"governance.access.mfaPolicy"`) against
 * a nested configuration object.
 *
 * Returns `null` if any segment in the path is missing or the terminal value
 * is `null` / empty string.
 */
function resolveConfigPath(
  config: GovernanceConfig,
  path: string,
): GovernanceConfigValue | null {
  const segments = path.split(".");
  let current: GovernanceConfigValue = config;

  for (const segment of segments) {
    if (
      current === null ||
      typeof current !== "object" ||
      Array.isArray(current)
    ) {
      return null;
    }
    const record = current as Record<string, GovernanceConfigValue>;
    if (!(segment in record)) {
      return null;
    }
    const next = record[segment];
    if (next === undefined) {
      return null;
    }
    current = next;
  }

  // Treat empty string as missing — a config path must have a meaningful value.
  if (current === "" || current === null) {
    return null;
  }
  return current;
}

/**
 * EvidenceCollector gathers raw evidence from a governance config and an audit
 * log for a set of control requirements.
 *
 * This class is stateless — each `collectForControl` call is independent.
 */
export class EvidenceCollector {
  private readonly config: GovernanceConfig;
  private readonly auditLog: AuditLog;

  constructor(config: GovernanceConfig, auditLog: AuditLog) {
    this.config = config;
    this.auditLog = auditLog;
  }

  /**
   * Resolves all required config paths for a single control.
   */
  resolveConfigPaths(paths: readonly string[]): readonly ConfigPathResolution[] {
    return paths.map((path) => {
      const value = resolveConfigPath(this.config, path);
      return {
        path,
        found: value !== null,
        value,
      } satisfies ConfigPathResolution;
    });
  }

  /**
   * Searches the audit log for occurrences of each required event type.
   */
  resolveAuditEvents(eventTypes: readonly string[]): readonly AuditEventResolution[] {
    return eventTypes.map((eventType) => {
      const matches: AuditLogEntry[] = this.auditLog.entries.filter(
        (entry) => entry.eventType === eventType,
      );

      if (matches.length === 0) {
        return {
          eventType,
          found: false,
          lastSeenAt: null,
          occurrenceCount: 0,
        } satisfies AuditEventResolution;
      }

      // Entries are assumed time-ordered; last match has the most recent timestamp.
      const lastEntry = matches[matches.length - 1];
      const lastSeenAt = lastEntry !== undefined ? lastEntry.timestamp : null;

      return {
        eventType,
        found: true,
        lastSeenAt,
        occurrenceCount: matches.length,
      } satisfies AuditEventResolution;
    });
  }

  /**
   * Collects all evidence for a single control or article.
   *
   * @param controlId - The framework-specific control identifier.
   * @param requiredConfigPaths - Governance config paths that should be present.
   * @param requiredAuditEvents - Audit log event types that should appear in the log.
   */
  collectForControl(
    controlId: string,
    requiredConfigPaths: readonly string[],
    requiredAuditEvents: readonly string[],
  ): ControlEvidenceCollection {
    const configResolutions = this.resolveConfigPaths(requiredConfigPaths);
    const auditEventResolutions = this.resolveAuditEvents(requiredAuditEvents);

    return {
      controlId,
      configResolutions,
      auditEventResolutions,
      collectedAt: new Date().toISOString(),
    };
  }
}
