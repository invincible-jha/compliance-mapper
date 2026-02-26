// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview EU AI Act compliance framework implementation.
 *
 * Maps Regulation (EU) 2024/1689 Chapter 2 requirements for high-risk AI
 * systems (Articles 8–15) to governance configuration paths and audit log events.
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import type { ComplianceFramework, FrameworkMetadata } from "./interface.js";
import type { ControlAssessment, GovernanceConfig, AuditLog, MapperOptions } from "../types.js";
import { EvidenceCollector } from "../evidence/collector.js";
import { EvidenceGenerator } from "../evidence/generator.js";

// ── Mapping types (mirrors eu-ai-act-requirements.json structure) ─────────────

interface EuAiActArticleMapping {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly governanceConfigPaths: readonly string[];
  readonly auditLogEvents: readonly string[];
  readonly evidenceTypes: readonly string[];
}

interface EuAiActChapterMapping {
  readonly id: string;
  readonly title: string;
  readonly articles: readonly EuAiActArticleMapping[];
}

interface EuAiActMappingFile {
  readonly framework: string;
  readonly version: string;
  readonly source: string;
  readonly chapters: readonly EuAiActChapterMapping[];
}

// ── Fallback inline mapping ───────────────────────────────────────────────────

const INLINE_ARTICLES: readonly EuAiActArticleMapping[] = [
  {
    id: "Art8",
    title: "Compliance with the requirements",
    description: "High-risk AI systems shall comply with the requirements established in Chapter 2.",
    governanceConfigPaths: [
      "governance.ai.riskClassification",
      "governance.ai.complianceFramework",
      "governance.ai.highRiskDesignation",
    ],
    auditLogEvents: ["ai_risk_classification_completed", "high_risk_designation_confirmed"],
    evidenceTypes: ["risk_classification_record", "compliance_framework_document"],
  },
  {
    id: "Art9",
    title: "Risk management system",
    description: "A risk management system shall be established and maintained for high-risk AI systems throughout their lifecycle.",
    governanceConfigPaths: [
      "governance.ai.riskManagementSystem",
      "governance.ai.riskRegister",
      "governance.ai.misuseScenariosRegister",
      "governance.ai.riskMitigationMeasures",
      "governance.ai.residualRiskAcceptanceCriteria",
      "governance.ai.postMarketMonitoringPlan",
    ],
    auditLogEvents: ["ai_risk_review_completed", "misuse_scenario_assessed", "risk_mitigation_implemented"],
    evidenceTypes: ["ai_risk_management_plan", "risk_register", "mitigation_record", "monitoring_report"],
  },
  {
    id: "Art10",
    title: "Data and data governance",
    description: "Training, validation and testing datasets shall be subject to data governance practices.",
    governanceConfigPaths: [
      "governance.ai.dataGovernancePolicy",
      "governance.ai.trainingDataRegister",
      "governance.ai.dataQualityPolicy",
      "governance.ai.biasAssessmentProcess",
      "governance.ai.dataLineageTracking",
      "governance.ai.dataGapsRegister",
      "governance.data.personalDataInTrainingPolicy",
    ],
    auditLogEvents: ["training_data_assessed", "bias_evaluation_completed", "data_quality_check_passed"],
    evidenceTypes: ["data_governance_policy", "training_data_card", "bias_assessment_report", "data_quality_report"],
  },
  {
    id: "Art11",
    title: "Technical documentation",
    description: "Technical documentation shall be drawn up before the high-risk AI system is placed on the market.",
    governanceConfigPaths: [
      "governance.ai.technicalDocumentationRegister",
      "governance.ai.systemArchitectureDocument",
      "governance.ai.modelCard",
      "governance.ai.validationResults",
      "governance.ai.standardsCompliance",
      "governance.ai.changeManagementPolicy",
    ],
    auditLogEvents: ["technical_documentation_completed", "documentation_reviewed"],
    evidenceTypes: ["technical_documentation_package", "model_card", "validation_report", "architecture_document"],
  },
  {
    id: "Art12",
    title: "Record-keeping",
    description: "High-risk AI systems shall be designed with capabilities enabling automatic recording of events.",
    governanceConfigPaths: [
      "governance.ai.auditLoggingPolicy",
      "governance.ai.logRetentionPolicy",
      "governance.ai.logIntegrityControls",
      "governance.ai.operationalLogFormat",
      "governance.ai.logAccessControls",
    ],
    auditLogEvents: ["ai_system_log_generated", "log_integrity_verified"],
    evidenceTypes: ["logging_configuration", "log_sample", "log_retention_policy", "log_access_record"],
  },
  {
    id: "Art13",
    title: "Transparency and provision of information to deployers",
    description: "High-risk AI systems shall be designed to ensure their operation is sufficiently transparent to deployers.",
    governanceConfigPaths: [
      "governance.ai.systemTransparencyDocument",
      "governance.ai.deployerInstructionsForUse",
      "governance.ai.capabilitiesLimitationsDocument",
      "governance.ai.performanceMetricsRegister",
      "governance.ai.knownRisksDocument",
      "governance.ai.humanOversightGuidance",
    ],
    auditLogEvents: ["transparency_documentation_updated", "deployer_briefing_completed"],
    evidenceTypes: ["instructions_for_use", "transparency_declaration", "performance_metrics_report"],
  },
  {
    id: "Art14",
    title: "Human oversight",
    description: "High-risk AI systems shall be designed to allow effective oversight by natural persons during use.",
    governanceConfigPaths: [
      "governance.ai.humanOversightProcess",
      "governance.ai.overrideCapability",
      "governance.ai.haltCapability",
      "governance.ai.humanReviewTriggers",
      "governance.ai.operatorTrainingRequirements",
      "governance.ai.automationBiasControls",
    ],
    auditLogEvents: ["human_override_exercised", "system_halted_by_operator", "human_review_performed"],
    evidenceTypes: ["human_oversight_procedure", "override_log", "operator_training_record", "halt_mechanism_test"],
  },
  {
    id: "Art15",
    title: "Accuracy, robustness and cybersecurity",
    description: "High-risk AI systems shall achieve an appropriate level of accuracy, robustness and cybersecurity.",
    governanceConfigPaths: [
      "governance.ai.accuracyMetrics",
      "governance.ai.robustnessTesting",
      "governance.ai.adversarialTestingPolicy",
      "governance.security.aiSystemSecurityPolicy",
      "governance.ai.modelValidationPolicy",
      "governance.ai.driftMonitoringPolicy",
      "governance.ai.fallbackMechanisms",
    ],
    auditLogEvents: [
      "accuracy_benchmark_completed",
      "robustness_test_passed",
      "adversarial_test_completed",
      "security_assessment_completed",
    ],
    evidenceTypes: [
      "accuracy_benchmark_report",
      "robustness_test_report",
      "adversarial_test_report",
      "security_assessment",
    ],
  },
];

/**
 * Attempts to load the full EU AI Act mapping from the JSON file on disk.
 * Falls back to the inline set (Chapter 2 articles only) if unavailable.
 */
async function loadArticles(): Promise<readonly EuAiActArticleMapping[]> {
  try {
    const currentDir = dirname(fileURLToPath(import.meta.url));
    const mappingPath = join(currentDir, "../../../../mappings/eu-ai-act-requirements.json");
    const raw = await readFile(mappingPath, "utf8");
    const parsed = JSON.parse(raw) as EuAiActMappingFile;
    // Only assess Chapter 2 (high-risk requirements) by default.
    const chapter2 = parsed.chapters.find((chapter) => chapter.id === "Chapter2");
    return chapter2 ? chapter2.articles : INLINE_ARTICLES;
  } catch {
    return INLINE_ARTICLES;
  }
}

/**
 * EU AI Act compliance framework.
 *
 * Covers Chapter 2 requirements (Articles 8–15) for high-risk AI systems
 * as defined in Regulation (EU) 2024/1689 and Annex III.
 *
 * Scope is intentionally limited to high-risk AI system provider obligations.
 * GPAI model obligations (Chapter 5) are out of scope for this framework instance.
 */
export class EUAIActFramework implements ComplianceFramework {
  private articles: readonly EuAiActArticleMapping[] = [];
  private loaded = false;

  readonly metadata: FrameworkMetadata = {
    id: "eu-ai-act",
    name: "EU AI Act",
    version: "2024/1689",
    source: "Regulation (EU) 2024/1689 of the European Parliament and of the Council",
    scopeDescription:
      "Chapter 2 requirements for high-risk AI systems: risk management, data governance, documentation, logging, transparency, human oversight, and robustness.",
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
