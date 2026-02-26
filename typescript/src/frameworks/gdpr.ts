// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview GDPR compliance framework implementation.
 *
 * Maps Regulation (EU) 2016/679 Articles 5–22, 25, 30, 32, 33, and 35
 * to governance configuration paths and audit log events.
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import type { ComplianceFramework, FrameworkMetadata } from "./interface.js";
import type { ControlAssessment, GovernanceConfig, AuditLog, MapperOptions } from "../types.js";
import { EvidenceCollector } from "../evidence/collector.js";
import { EvidenceGenerator } from "../evidence/generator.js";

// ── Mapping types (mirrors gdpr-articles.json structure) ─────────────────────

interface GdprArticleMapping {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly governanceConfigPaths: readonly string[];
  readonly auditLogEvents: readonly string[];
  readonly evidenceTypes: readonly string[];
}

interface GdprMappingFile {
  readonly framework: string;
  readonly version: string;
  readonly source: string;
  readonly articles: readonly GdprArticleMapping[];
}

// ── Fallback inline mapping ───────────────────────────────────────────────────

const INLINE_ARTICLES: readonly GdprArticleMapping[] = [
  {
    id: "Art5",
    title: "Principles relating to processing of personal data",
    description: "Personal data shall be processed lawfully, fairly, and transparently.",
    governanceConfigPaths: [
      "governance.privacy.processingPurposes",
      "governance.privacy.lawfulBasisRegister",
      "governance.privacy.minimizationPolicy",
      "governance.data.retentionSchedule",
      "governance.data.accuracyPolicy",
      "governance.data.encryptionPolicy",
      "governance.privacy.accountabilityRecord",
    ],
    auditLogEvents: ["lawful_basis_documented", "purpose_limitation_reviewed", "retention_enforced"],
    evidenceTypes: ["ropa", "lawful_basis_record", "retention_schedule", "privacy_policy"],
  },
  {
    id: "Art6",
    title: "Lawfulness of processing",
    description: "Processing is lawful only if at least one lawful basis applies.",
    governanceConfigPaths: [
      "governance.privacy.lawfulBasisRegister",
      "governance.privacy.consentManagement",
      "governance.privacy.legitimateInterestAssessments",
    ],
    auditLogEvents: ["lawful_basis_applied", "lia_completed"],
    evidenceTypes: ["lawful_basis_register", "lia_document", "consent_record"],
  },
  {
    id: "Art7",
    title: "Conditions for consent",
    description: "Where processing is based on consent, the controller must demonstrate that the data subject consented.",
    governanceConfigPaths: [
      "governance.privacy.consentManagement",
      "governance.privacy.consentRecordRetention",
      "governance.privacy.withdrawalMechanism",
      "governance.privacy.granularConsentOptions",
    ],
    auditLogEvents: ["consent_recorded", "consent_withdrawn"],
    evidenceTypes: ["consent_record", "withdrawal_log", "consent_mechanism_screenshot"],
  },
  {
    id: "Art15",
    title: "Right of access by the data subject",
    description: "The data subject shall have the right to obtain confirmation of processing and a copy of personal data.",
    governanceConfigPaths: [
      "governance.privacy.dataSubjectAccessProcess",
      "governance.privacy.accessResponseSLA",
      "governance.privacy.identityVerificationProcess",
      "governance.privacy.accessFulfillmentProcess",
    ],
    auditLogEvents: ["access_request_received", "access_request_fulfilled"],
    evidenceTypes: ["sar_log", "sar_response", "fulfillment_record"],
  },
  {
    id: "Art17",
    title: "Right to erasure ('right to be forgotten')",
    description: "The data subject shall have the right to obtain erasure of personal data without undue delay.",
    governanceConfigPaths: [
      "governance.privacy.erasureProcess",
      "governance.data.disposalPolicy",
      "governance.data.backupErasurePolicy",
      "governance.privacy.erasureSLA",
      "governance.privacy.thirdPartyErasureNotification",
    ],
    auditLogEvents: ["erasure_request_received", "data_erased", "third_party_erasure_notified"],
    evidenceTypes: ["erasure_log", "deletion_certificate", "third_party_notification"],
  },
  {
    id: "Art22",
    title: "Automated individual decision-making, including profiling",
    description: "The data subject shall have the right not to be subject to solely automated decisions without human review.",
    governanceConfigPaths: [
      "governance.ai.automatedDecisionRegister",
      "governance.ai.humanOversightProcess",
      "governance.ai.profilingPolicy",
      "governance.ai.explainabilityProcess",
    ],
    auditLogEvents: ["automated_decision_made", "human_review_triggered", "decision_challenged"],
    evidenceTypes: ["automated_decision_register", "human_review_record", "explainability_documentation"],
  },
  {
    id: "Art25",
    title: "Data protection by design and by default",
    description: "The controller shall implement appropriate measures to give effect to data protection principles.",
    governanceConfigPaths: [
      "governance.privacy.privacyByDesignProcess",
      "governance.data.pseudonymisationPolicy",
      "governance.data.minimizationByDefault",
      "governance.sdlc.privacyReview",
      "governance.access.defaultAccessRestriction",
    ],
    auditLogEvents: ["privacy_by_design_review_completed", "pseudonymisation_applied"],
    evidenceTypes: ["pbd_checklist", "sdlc_privacy_review", "pseudonymisation_configuration"],
  },
  {
    id: "Art32",
    title: "Security of processing",
    description: "The controller and processor shall implement appropriate technical and organisational measures.",
    governanceConfigPaths: [
      "governance.data.encryptionAtRestPolicy",
      "governance.data.encryptionInTransitPolicy",
      "governance.data.pseudonymisationPolicy",
      "governance.security.accessControlPolicy",
      "governance.business.bcpPolicy",
      "governance.security.penetrationTestingSchedule",
      "governance.security.vulnerabilityManagementPolicy",
    ],
    auditLogEvents: ["security_assessment_completed", "encryption_verified", "pen_test_completed"],
    evidenceTypes: ["security_assessment", "encryption_configuration", "pen_test_report", "bcp_document"],
  },
  {
    id: "Art35",
    title: "Data protection impact assessment",
    description: "Where processing is likely to result in high risk, the controller shall carry out a DPIA prior to processing.",
    governanceConfigPaths: [
      "governance.privacy.dpiaProcess",
      "governance.privacy.dpiaThresholdCriteria",
      "governance.privacy.dpiaRegister",
      "governance.privacy.dpoReviewProcess",
      "governance.ai.automatedDecisionRegister",
    ],
    auditLogEvents: ["dpia_completed", "dpia_approved", "dpia_reviewed"],
    evidenceTypes: ["dpia_document", "dpia_register", "dpo_review_record"],
  },
];

/**
 * Attempts to load the full GDPR mapping from the JSON file on disk.
 * Falls back to the inline minimal set if the file is unavailable.
 */
async function loadArticles(): Promise<readonly GdprArticleMapping[]> {
  try {
    const currentDir = dirname(fileURLToPath(import.meta.url));
    const mappingPath = join(currentDir, "../../../../mappings/gdpr-articles.json");
    const raw = await readFile(mappingPath, "utf8");
    const parsed = JSON.parse(raw) as GdprMappingFile;
    return parsed.articles;
  } catch {
    return INLINE_ARTICLES;
  }
}

/**
 * GDPR compliance framework.
 *
 * Covers Articles 5–22, 25, 30, 32, 33, and 35 of Regulation (EU) 2016/679,
 * focusing on controller and processor obligations relevant to AI and digital
 * service governance.
 */
export class GDPRFramework implements ComplianceFramework {
  private articles: readonly GdprArticleMapping[] = [];
  private loaded = false;

  readonly metadata: FrameworkMetadata = {
    id: "gdpr",
    name: "GDPR",
    version: "2016/679",
    source: "Regulation (EU) 2016/679 of the European Parliament and of the Council",
    scopeDescription:
      "General Data Protection Regulation — controller and processor obligations for personal data processing.",
  };

  private async ensureLoaded(): Promise<void> {
    if (!this.loaded) {
      this.articles = await loadArticles();
      this.loaded = true;
    }
  }

  listControlIds(): readonly string[] {
    return this.articles.map((article) => article.id);
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

    return this.articles.map((article) => {
      const isExcluded = excludedIds.has(article.id);

      const collection = isExcluded
        ? {
            controlId: article.id,
            configResolutions: [],
            auditEventResolutions: [],
            collectedAt: options.reportTimestamp ?? new Date().toISOString(),
          }
        : collector.collectForControl(
            article.id,
            article.governanceConfigPaths,
            article.auditLogEvents,
          );

      return generator.generateAssessment({
        controlId: article.id,
        title: article.title,
        description: article.description,
        frameworkId: this.metadata.id,
        collection,
        includeAuditEventGaps,
        isExcluded,
      });
    });
  }
}
