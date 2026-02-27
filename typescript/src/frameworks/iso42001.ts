// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview ISO/IEC 42001:2023 AI Management System compliance framework.
 *
 * Maps ISO/IEC 42001 clauses (4–10) and Annex A controls (A.2–A.10) to
 * governance configuration paths and audit log events.  Provides coverage
 * reporting, evidence requirement lookup, and gap analysis against a
 * Governance Bill of Materials (GBOM) control list.
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { z } from "zod";
import type { ComplianceFramework, FrameworkMetadata } from "./interface.js";
import type { ControlAssessment, GovernanceConfig, AuditLog, MapperOptions } from "../types.js";
import { EvidenceCollector } from "../evidence/collector.js";
import { EvidenceGenerator } from "../evidence/generator.js";

// ── Zod schemas ──────────────────────────────────────────────────────────────

const EvidenceRequirementSchema = z.object({
  clauseId: z.string(),
  evidenceType: z.string(),
  governanceConfigPaths: z.array(z.string()),
  auditLogEvents: z.array(z.string()),
  description: z.string(),
});

const ClauseCoverageSchema = z.object({
  clauseId: z.string(),
  title: z.string(),
  category: z.string(),
  status: z.enum(["covered", "partial", "gap"]),
  matchedControls: z.array(z.string()),
  missingControls: z.array(z.string()),
});

const CoverageReportSchema = z.object({
  standard: z.string().default("ISO/IEC 42001:2023"),
  totalClauses: z.number(),
  coveredCount: z.number(),
  partialCount: z.number(),
  gapCount: z.number(),
  coveragePercentage: z.number(),
  clauses: z.array(ClauseCoverageSchema),
  generatedAt: z.string(),
});

const GapDetailSchema = z.object({
  clauseId: z.string(),
  title: z.string(),
  category: z.string(),
  missingAumosControls: z.array(z.string()),
  recommendation: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
});

const GapAnalysisSchema = z.object({
  standard: z.string().default("ISO/IEC 42001:2023"),
  totalGaps: z.number(),
  criticalGaps: z.number(),
  highGaps: z.number(),
  gaps: z.array(GapDetailSchema),
  generatedAt: z.string(),
});

// ── Exported types ───────────────────────────────────────────────────────────

export type EvidenceRequirement = z.infer<typeof EvidenceRequirementSchema>;
export type ClauseCoverage = z.infer<typeof ClauseCoverageSchema>;
export type CoverageReport = z.infer<typeof CoverageReportSchema>;
export type GapDetail = z.infer<typeof GapDetailSchema>;
export type GapAnalysis = z.infer<typeof GapAnalysisSchema>;

// ── Mapping types ────────────────────────────────────────────────────────────

interface ISO42001ControlMapping {
  readonly id: string;
  readonly title: string;
  readonly category: string;
  readonly aumos_protocols: readonly string[];
  readonly aumos_controls: readonly string[];
  readonly coverage: string;
  readonly evidence_type: string;
  readonly notes: string;
  readonly governanceConfigPaths: readonly string[];
  readonly auditLogEvents: readonly string[];
}

interface ISO42001MappingFile {
  readonly standard: string;
  readonly version: string;
  readonly controls: readonly ISO42001ControlMapping[];
}

// ── Fallback inline mapping ──────────────────────────────────────────────────

const INLINE_CONTROLS: readonly ISO42001ControlMapping[] = [
  {
    id: "5.1",
    title: "Leadership and commitment",
    category: "Leadership",
    aumos_protocols: ["ATP", "AOAP"],
    aumos_controls: ["ATP-001", "AOAP-001"],
    coverage: "full",
    evidence_type: "governance_config",
    notes: "Trust level assignments demonstrate AI governance commitment",
    governanceConfigPaths: [
      "governance.ai.leadershipCommitment",
      "governance.ai.managementReview",
      "governance.organization.aiGovernanceCharter",
    ],
    auditLogEvents: ["leadership_commitment_attested", "management_review_completed"],
  },
  {
    id: "5.2",
    title: "AI policy",
    category: "Leadership",
    aumos_protocols: ["ATP", "ALP"],
    aumos_controls: ["ATP-005", "ALP-002"],
    coverage: "full",
    evidence_type: "policy_document",
    notes: "AI policy established and communicated via trust and logging protocols",
    governanceConfigPaths: [
      "governance.ai.aiPolicy",
      "governance.ai.aiPolicyObjectives",
      "governance.ai.aiPolicyCommunication",
    ],
    auditLogEvents: ["ai_policy_approved", "ai_policy_communicated"],
  },
  {
    id: "6.1",
    title: "Actions to address risks and opportunities",
    category: "Planning",
    aumos_protocols: ["ATP", "AOAP"],
    aumos_controls: ["ATP-007", "AOAP-004"],
    coverage: "full",
    evidence_type: "risk_assessment",
    notes: "Risk and opportunity actions planned through governance framework",
    governanceConfigPaths: [
      "governance.ai.riskOpportunityRegister",
      "governance.ai.riskTreatmentPlan",
      "governance.ai.aiImpactAssessment",
    ],
    auditLogEvents: ["ai_risk_assessment_completed", "risk_treatment_plan_approved"],
  },
  {
    id: "8.2",
    title: "AI risk assessment",
    category: "Operation",
    aumos_protocols: ["ATP", "AOAP"],
    aumos_controls: ["ATP-014", "AOAP-007"],
    coverage: "full",
    evidence_type: "risk_assessment",
    notes: "AI-specific risk assessments conducted at planned intervals",
    governanceConfigPaths: [
      "governance.ai.riskAssessmentMethodology",
      "governance.ai.riskAssessmentSchedule",
      "governance.ai.riskCriteria",
    ],
    auditLogEvents: ["ai_risk_assessment_conducted", "risk_level_determined"],
  },
  {
    id: "9.2",
    title: "Internal audit",
    category: "Performance evaluation",
    aumos_protocols: ["ALP", "AOAP"],
    aumos_controls: ["ALP-007", "AOAP-011"],
    coverage: "full",
    evidence_type: "audit_report",
    notes: "Internal audits of the AIMS conducted at planned intervals",
    governanceConfigPaths: [
      "governance.ai.internalAuditPlan",
      "governance.ai.auditProgramSchedule",
      "governance.ai.auditCriteria",
    ],
    auditLogEvents: ["internal_audit_completed", "audit_findings_reported"],
  },
  {
    id: "A.5.2",
    title: "AI impact assessment",
    category: "Annex A — Assessing impacts of AI systems",
    aumos_protocols: ["ATP", "AOAP"],
    aumos_controls: ["ATP-024", "AOAP-016"],
    coverage: "full",
    evidence_type: "impact_assessment",
    notes: "Impact assessments conducted before deployment and at intervals",
    governanceConfigPaths: [
      "governance.ai.impactAssessmentPolicy",
      "governance.ai.socialImpactAssessment",
      "governance.ai.environmentalImpactAssessment",
    ],
    auditLogEvents: ["impact_assessment_initiated", "impact_results_documented"],
  },
];

// ── JSON loading ─────────────────────────────────────────────────────────────

async function loadControls(): Promise<readonly ISO42001ControlMapping[]> {
  try {
    const currentDir = dirname(fileURLToPath(import.meta.url));
    const mappingPath = join(currentDir, "../../../../mappings/iso-42001-controls.json");
    const raw = await readFile(mappingPath, "utf8");
    const parsed = JSON.parse(raw) as ISO42001MappingFile;
    return parsed.controls.length > 0 ? parsed.controls : INLINE_CONTROLS;
  } catch {
    return INLINE_CONTROLS;
  }
}

// ── Helper functions ─────────────────────────────────────────────────────────

function deriveGapSeverity(missingCount: number, totalCount: number): "critical" | "high" | "medium" | "low" {
  if (totalCount === 0) return "low";
  const ratio = missingCount / totalCount;
  if (ratio >= 0.8) return "critical";
  if (ratio >= 0.5) return "high";
  if (ratio >= 0.25) return "medium";
  return "low";
}

// ── Public API functions ─────────────────────────────────────────────────────

/**
 * Generate a coverage report showing which ISO 42001 clauses are satisfied
 * by the provided GBOM control identifiers.
 */
export async function getCoverageReport(gbomControls: readonly string[]): Promise<CoverageReport> {
  const controls = await loadControls();
  const gbomSet = new Set(gbomControls);

  const clauses: ClauseCoverage[] = [];
  let coveredCount = 0;
  let partialCount = 0;
  let gapCount = 0;

  for (const control of controls) {
    const matched = control.aumos_controls.filter((c) => gbomSet.has(c));
    const missing = control.aumos_controls.filter((c) => !gbomSet.has(c));

    let status: "covered" | "partial" | "gap";
    if (matched.length === control.aumos_controls.length && matched.length > 0) {
      status = "covered";
      coveredCount++;
    } else if (matched.length > 0) {
      status = "partial";
      partialCount++;
    } else {
      status = "gap";
      gapCount++;
    }

    clauses.push({
      clauseId: control.id,
      title: control.title,
      category: control.category,
      status,
      matchedControls: [...matched],
      missingControls: [...missing],
    });
  }

  const total = controls.length;
  const coveragePercentage = total > 0 ? Math.round((coveredCount / total) * 10000) / 100 : 0;

  const report: CoverageReport = {
    standard: "ISO/IEC 42001:2023",
    totalClauses: total,
    coveredCount,
    partialCount,
    gapCount,
    coveragePercentage,
    clauses,
    generatedAt: new Date().toISOString(),
  };

  return CoverageReportSchema.parse(report);
}

/**
 * Return the evidence requirements for a specific ISO 42001 clause.
 */
export async function getEvidenceRequirements(clauseId: string): Promise<EvidenceRequirement[]> {
  const controls = await loadControls();
  const results: EvidenceRequirement[] = [];

  for (const control of controls) {
    if (control.id === clauseId) {
      const requirement: EvidenceRequirement = {
        clauseId: control.id,
        evidenceType: control.evidence_type,
        governanceConfigPaths: [...control.governanceConfigPaths],
        auditLogEvents: [...control.auditLogEvents],
        description: `${control.title}: ${control.notes}`,
      };
      results.push(EvidenceRequirementSchema.parse(requirement));
    }
  }

  return results;
}

/**
 * Generate a gap analysis identifying ISO 42001 clauses not satisfied
 * by the provided GBOM controls.
 */
export async function generateGapAnalysis(gbomControls: readonly string[]): Promise<GapAnalysis> {
  const controls = await loadControls();
  const gbomSet = new Set(gbomControls);

  const gaps: GapDetail[] = [];

  for (const control of controls) {
    const missing = control.aumos_controls.filter((c) => !gbomSet.has(c));
    if (missing.length === 0) continue;

    const severity = deriveGapSeverity(missing.length, control.aumos_controls.length);
    const firstMissing = missing[0] ?? "";
    const configPathsPreview = control.governanceConfigPaths.slice(0, 2).join(", ");
    const recommendation =
      `Implement ${firstMissing} to address "${control.title}" requirements. ` +
      `Configure governance paths: ${configPathsPreview}.`;

    gaps.push({
      clauseId: control.id,
      title: control.title,
      category: control.category,
      missingAumosControls: [...missing],
      recommendation,
      severity,
    });
  }

  const criticalGaps = gaps.filter((g) => g.severity === "critical").length;
  const highGaps = gaps.filter((g) => g.severity === "high").length;

  const analysis: GapAnalysis = {
    standard: "ISO/IEC 42001:2023",
    totalGaps: gaps.length,
    criticalGaps,
    highGaps,
    gaps,
    generatedAt: new Date().toISOString(),
  };

  return GapAnalysisSchema.parse(analysis);
}

// ── Framework class ──────────────────────────────────────────────────────────

/**
 * ISO/IEC 42001:2023 AI Management System compliance framework.
 *
 * Covers clauses 4–10 (management system requirements) and Annex A controls
 * (A.2–A.10) for AI-specific management system objectives.
 */
export class ISO42001Framework implements ComplianceFramework {
  private controls: readonly ISO42001ControlMapping[] = [];
  private loaded = false;

  readonly metadata: FrameworkMetadata = {
    id: "iso-42001",
    name: "ISO/IEC 42001:2023",
    version: "2023",
    source: "ISO/IEC",
    scopeDescription:
      "AI Management System standard covering governance, risk management, lifecycle management, data governance, transparency, and continual improvement for AI systems.",
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
        description: control.notes,
        frameworkId: this.metadata.id,
        collection,
        includeAuditEventGaps,
        isExcluded,
      });
    });
  }
}
