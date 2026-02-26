// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview SOC 2 Type II compliance framework implementation.
 *
 * Maps the AICPA Trust Services Criteria (2017) to governance config paths
 * and audit log events. Covers Security (CC), Availability (A),
 * Confidentiality (C), Processing Integrity (PI), and Privacy (P) categories.
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import type { ComplianceFramework, FrameworkMetadata } from "./interface.js";
import type { ControlAssessment, GovernanceConfig, AuditLog, MapperOptions } from "../types.js";
import { EvidenceCollector } from "../evidence/collector.js";
import { EvidenceGenerator } from "../evidence/generator.js";

// ── Mapping types (mirrors soc2-controls.json structure) ─────────────────────

interface Soc2ControlMapping {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly governanceConfigPaths: readonly string[];
  readonly auditLogEvents: readonly string[];
  readonly evidenceTypes: readonly string[];
}

interface Soc2CategoryMapping {
  readonly id: string;
  readonly name: string;
  readonly controls: readonly Soc2ControlMapping[];
}

interface Soc2MappingFile {
  readonly framework: string;
  readonly version: string;
  readonly source: string;
  readonly categories: readonly Soc2CategoryMapping[];
}

// ── Fallback inline mapping (used when the JSON file is not available) ────────

const INLINE_CONTROLS: readonly Soc2ControlMapping[] = [
  {
    id: "CC1.1",
    title: "Organizational Commitment to Integrity and Ethical Values",
    description: "The entity demonstrates a commitment to integrity and ethical values.",
    governanceConfigPaths: [
      "governance.ethics.codeOfConduct",
      "governance.ethics.conflictOfInterestPolicy",
      "governance.organization.leadershipAttestation",
    ],
    auditLogEvents: ["ethics_training_completed", "policy_acknowledged"],
    evidenceTypes: ["policy_document", "training_record", "attestation"],
  },
  {
    id: "CC6.1",
    title: "Logical Access Security Software Infrastructure",
    description: "The entity implements logical access security to protect against threats from external sources.",
    governanceConfigPaths: [
      "governance.access.authenticationPolicy",
      "governance.access.mfaPolicy",
      "governance.access.networkSegmentationPolicy",
    ],
    auditLogEvents: ["mfa_enforced", "access_attempt", "network_policy_applied"],
    evidenceTypes: ["access_policy", "mfa_configuration", "network_diagram"],
  },
  {
    id: "CC6.2",
    title: "Prior to Issuing System Credentials",
    description: "Prior to issuing system credentials and granting system access, the entity registers and authorizes new users.",
    governanceConfigPaths: [
      "governance.access.userProvisioningProcess",
      "governance.access.approvalWorkflow",
      "governance.access.accessRequestPolicy",
    ],
    auditLogEvents: ["user_provisioned", "access_approved"],
    evidenceTypes: ["provisioning_record", "access_approval"],
  },
  {
    id: "CC6.3",
    title: "Role-Based Access and Least Privilege",
    description: "The entity authorizes, modifies, or removes access based on roles, needs, and least privilege.",
    governanceConfigPaths: [
      "governance.access.rbacPolicy",
      "governance.access.leastPrivilegePolicy",
      "governance.access.privilegedAccessPolicy",
    ],
    auditLogEvents: ["role_assigned", "privilege_reviewed", "access_removed"],
    evidenceTypes: ["rbac_configuration", "access_review_record"],
  },
  {
    id: "CC7.4",
    title: "Incident Response",
    description: "The entity responds to identified security incidents by executing a defined incident management program.",
    governanceConfigPaths: [
      "governance.incident.responsePolicy",
      "governance.incident.responseTeam",
      "governance.incident.communicationPlan",
    ],
    auditLogEvents: ["incident_response_initiated", "incident_resolved", "postmortem_completed"],
    evidenceTypes: ["incident_response_plan", "incident_record", "postmortem_report"],
  },
  {
    id: "CC8.1",
    title: "Change Management Process",
    description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes.",
    governanceConfigPaths: [
      "governance.changeManagement.changePolicy",
      "governance.changeManagement.approvalWorkflow",
      "governance.changeManagement.testingRequirements",
      "governance.changeManagement.rollbackProcedure",
    ],
    auditLogEvents: ["change_requested", "change_approved", "change_tested", "change_deployed"],
    evidenceTypes: ["change_request", "change_approval", "test_result", "deployment_record"],
  },
  {
    id: "A1.3",
    title: "Recovery and Resumption",
    description: "The entity tests recovery plan procedures to achieve timely recovery of commitments.",
    governanceConfigPaths: [
      "governance.business.bcpPolicy",
      "governance.business.rtoRpoTargets",
      "governance.business.drTestSchedule",
    ],
    auditLogEvents: ["bcp_tested", "dr_exercise_completed"],
    evidenceTypes: ["bcp_document", "dr_test_report", "rto_rpo_measurement"],
  },
  {
    id: "C1.1",
    title: "Confidentiality Commitments Identification",
    description: "The entity identifies and maintains confidential information.",
    governanceConfigPaths: [
      "governance.data.classificationPolicy",
      "governance.data.confidentialDataInventory",
      "governance.data.labelingPolicy",
    ],
    auditLogEvents: ["data_classified", "confidential_data_accessed"],
    evidenceTypes: ["data_classification_policy", "data_inventory"],
  },
  {
    id: "P1.0",
    title: "Privacy Notice",
    description: "The entity provides notice to data subjects about its privacy practices.",
    governanceConfigPaths: [
      "governance.privacy.privacyNoticeUrl",
      "governance.privacy.noticeReviewSchedule",
      "governance.privacy.noticeLanguages",
    ],
    auditLogEvents: ["privacy_notice_updated", "notice_served"],
    evidenceTypes: ["privacy_notice", "notice_delivery_record"],
  },
  {
    id: "P2.0",
    title: "Choice and Consent",
    description: "The entity communicates choices available for personal information and obtains consent.",
    governanceConfigPaths: [
      "governance.privacy.consentManagement",
      "governance.privacy.optOutMechanism",
      "governance.privacy.consentRecordRetention",
    ],
    auditLogEvents: ["consent_obtained", "opt_out_processed"],
    evidenceTypes: ["consent_record", "opt_out_record"],
  },
];

/**
 * Attempts to load the full SOC 2 mapping from the JSON file on disk.
 * Falls back to the inline minimal set if the file is unavailable.
 */
async function loadControls(): Promise<readonly Soc2ControlMapping[]> {
  try {
    const currentDir = dirname(fileURLToPath(import.meta.url));
    const mappingPath = join(currentDir, "../../../../mappings/soc2-controls.json");
    const raw = await readFile(mappingPath, "utf8");
    const parsed = JSON.parse(raw) as Soc2MappingFile;
    return parsed.categories.flatMap((category) => category.controls);
  } catch {
    // JSON file unavailable — use inline controls.
    return INLINE_CONTROLS;
  }
}

/**
 * SOC 2 Type II compliance framework.
 *
 * Implements the AICPA Trust Services Criteria (2017) across all five
 * categories: Security (CC), Availability (A), Confidentiality (C),
 * Processing Integrity (PI), and Privacy (P).
 */
export class SOC2Framework implements ComplianceFramework {
  private controls: readonly Soc2ControlMapping[] = [];
  private loaded = false;

  readonly metadata: FrameworkMetadata = {
    id: "soc2",
    name: "SOC 2 Type II",
    version: "2017",
    source: "AICPA Trust Services Criteria",
    scopeDescription:
      "Security, Availability, Confidentiality, Processing Integrity, and Privacy controls for service organizations.",
  };

  private async ensureLoaded(): Promise<void> {
    if (!this.loaded) {
      this.controls = await loadControls();
      this.loaded = true;
    }
  }

  listControlIds(): readonly string[] {
    return this.controls.map((control) => control.id);
  }

  async assess(
    governanceConfig: GovernanceConfig,
    auditLog: AuditLog,
    options: MapperOptions,
  ): Promise<readonly ControlAssessment[]> {
    await this.ensureLoaded();

    const excludedIds = new Set(options.excludeControlIds ?? []);
    const includeAuditEventGaps = options.includeAuditEventGaps ?? true;

    const collector = new EvidenceCollector(governanceConfig, auditLog);
    const generator = new EvidenceGenerator();

    return this.controls.map((control) => {
      const isExcluded = excludedIds.has(control.id);

      const collection = isExcluded
        ? {
            controlId: control.id,
            configResolutions: [],
            auditEventResolutions: [],
            collectedAt: options.reportTimestamp ?? new Date().toISOString(),
          }
        : collector.collectForControl(
            control.id,
            control.governanceConfigPaths,
            control.auditLogEvents,
          );

      return generator.generateAssessment({
        controlId: control.id,
        title: control.title,
        description: control.description,
        frameworkId: this.metadata.id,
        collection,
        includeAuditEventGaps,
        isExcluded,
      });
    });
  }
}
