// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @fileoverview EU AI Act Risk Classification Tool — TypeScript mirror of
 * `python/src/compliance_mapper/risk_classifier.py`.
 *
 * Classifies an AI system's risk level under Regulation (EU) 2024/1689
 * (EU AI Act) and maps identified gaps to AumOS protocol sections for
 * remediation.
 *
 * @example
 * ```typescript
 * import { EUAIActRiskClassifier } from "@aumos/compliance-mapper/risk-classifier";
 *
 * const classifier = new EUAIActRiskClassifier();
 * const result = classifier.classify({
 *   name: "Loan Decision Engine",
 *   description: "Automated credit scoring for retail banking customers.",
 *   useCases: ["essential_services_access"],
 *   dataTypes: ["financial", "personal"],
 *   autonomyLevel: "semi_autonomous",
 *   deploymentContext: "customer_facing",
 *   sector: "finance",
 *   existingControls: ["risk_management_system", "technical_documentation"],
 * });
 * console.log(result.level);         // "high_risk"
 * console.log(result.gaps);          // controls not yet implemented
 * console.log(result.recommendations); // AumOS tool suggestions per gap
 * ```
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ── Risk Levels ───────────────────────────────────────────────────────────────

/** EU AI Act risk classification levels in descending order of severity. */
export type RiskLevel = "prohibited" | "high_risk" | "limited_risk" | "minimal_risk";

// ── Autonomy and Deployment Enumerations ──────────────────────────────────────

/** Degree of autonomous decision-making for the AI system. */
export type AutonomyLevel = "advisory" | "semi_autonomous" | "autonomous";

/** Where the AI system is deployed. */
export type DeploymentContext = "internal" | "customer_facing" | "public";

// ── Data Models ───────────────────────────────────────────────────────────────

/**
 * Describes the AI system to be classified.
 *
 * Callers populate this from their own system inventory or questionnaire.
 * All fields influence which risk criteria are evaluated.
 */
export interface AISystemProfile {
  /** Human-readable name of the AI system. */
  readonly name: string;

  /** Brief description of the system's purpose. */
  readonly description: string;

  /**
   * List of use-case identifiers that apply to this system.
   *
   * Values should match criteria identifiers in `eu-ai-act-risk-categories.json`
   * (e.g. `"biometric_identification"`, `"chatbot_interaction"`).
   */
  readonly useCases: readonly string[];

  /**
   * Categories of data the system processes (e.g. `"biometric"`, `"financial"`).
   * Used for informational purposes and future sector-specific expansions.
   */
  readonly dataTypes: readonly string[];

  /**
   * Degree of autonomous decision-making.
   * Accepted values: `"advisory"` | `"semi_autonomous"` | `"autonomous"`
   */
  readonly autonomyLevel: AutonomyLevel;

  /**
   * Where the system is deployed.
   * Accepted values: `"internal"` | `"customer_facing"` | `"public"`
   */
  readonly deploymentContext: DeploymentContext;

  /**
   * Industry sector of deployment. Used to apply sector-based criteria mapping.
   *
   * Recognised values: `"healthcare"`, `"finance"`, `"education"`,
   * `"employment"`, `"law_enforcement"`, `"border_control"`, `"infrastructure"`.
   * Any other value is treated as a general-purpose sector.
   */
  readonly sector: string;

  /**
   * Controls already implemented by the system owner.
   *
   * Values should match identifiers in the `required_controls` arrays of the
   * risk categories JSON (e.g. `"risk_management_system"`, `"human_oversight"`).
   */
  readonly existingControls?: readonly string[];
}

/**
 * Point-in-time risk classification result for a single AI system.
 *
 * All properties are readonly to prevent accidental mutation after creation.
 */
export interface RiskClassification {
  /** The assigned EU AI Act risk level. */
  readonly level: RiskLevel;

  /**
   * Classifier confidence in the assigned level (0.0–1.0).
   *
   * Lower values indicate that the profile's criteria are ambiguous or
   * borderline. Human review is recommended when confidence is below 0.75.
   */
  readonly confidence: number;

  /**
   * Criteria identifiers from the risk-categories mapping that matched
   * this AI system's profile.
   */
  readonly matchingCriteria: readonly string[];

  /** EU AI Act articles that apply to this classification. */
  readonly applicableArticles: readonly string[];

  /**
   * Controls mandated by the applicable articles for this risk level.
   * These map 1:1 to the `required_controls` field in the JSON mapping.
   */
  readonly requiredControls: readonly string[];

  /**
   * Required controls that were NOT present in `AISystemProfile.existingControls`.
   * An empty array means all mandatory controls are in place.
   */
  readonly gaps: readonly string[];

  /**
   * Human-readable remediation guidance, one entry per gap, referencing
   * the relevant AumOS protocol tools.
   */
  readonly recommendations: readonly string[];
}

// ── Internal JSON shape (loaded from mapping file) ────────────────────────────

interface RiskCategoryEntry {
  readonly level: string;
  readonly description: string;
  readonly articles: readonly string[];
  readonly criteria: readonly string[];
  readonly required_controls?: readonly string[];
}

interface RiskCategoriesJson {
  readonly version: string;
  readonly framework: string;
  readonly effectiveDate: string;
  readonly categories: readonly RiskCategoryEntry[];
}

// ── Classifier ────────────────────────────────────────────────────────────────

/**
 * Classifies an AI system under EU AI Act (Regulation 2024/1689) risk categories.
 *
 * Risk determination follows a priority waterfall:
 * 1. Prohibited (Article 5) — checked first; any match is definitive.
 * 2. High-risk (Article 6 / Annex III) — checked if not prohibited.
 * 3. Limited risk (Article 50) — checked if not high-risk.
 * 4. Minimal risk (Article 95) — assigned as the default.
 *
 * The classifier is stateless after construction; `classify()` can be called
 * any number of times concurrently with different profiles.
 */
export class EUAIActRiskClassifier {
  private readonly categories: RiskCategoriesJson;

  /**
   * @param mappingFilePath - Absolute path to `eu-ai-act-risk-categories.json`.
   *   Defaults to the `mappings/` directory at the repository root, resolved
   *   relative to this source file's location.
   */
  constructor(mappingFilePath?: string) {
    const resolvedPath =
      mappingFilePath ??
      join(
        dirname(fileURLToPath(import.meta.url)),
        "..",
        "..",
        "..",
        "mappings",
        "eu-ai-act-risk-categories.json",
      );
    this.categories = JSON.parse(readFileSync(resolvedPath, "utf-8")) as RiskCategoriesJson;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Classify an AI system according to EU AI Act risk levels.
   *
   * Applies a priority waterfall — prohibited is evaluated first, then
   * high-risk, then limited risk, falling back to minimal risk if no
   * criteria match.
   *
   * @param profile - The AI system profile to evaluate.
   * @returns A `RiskClassification` describing the assigned level, matched
   *   criteria, applicable articles, required controls, gaps, and
   *   AumOS-specific remediation recommendations.
   */
  classify(profile: AISystemProfile): RiskClassification {
    const allCriteria = this.extractCriteria(profile);

    const prohibitedResult = this.checkProhibited(allCriteria);
    if (prohibitedResult !== null) return prohibitedResult;

    const highRiskResult = this.checkHighRisk(allCriteria, profile);
    if (highRiskResult !== null) return highRiskResult;

    const limitedRiskResult = this.checkLimitedRisk(allCriteria, profile);
    if (limitedRiskResult !== null) return limitedRiskResult;

    return this.minimalRiskResult();
  }

  // ── Private Helpers ────────────────────────────────────────────────────────

  /**
   * Derive a flat list of classification criteria from an AI system profile.
   *
   * Combines explicit useCases with sector-inferred criteria and
   * deployment-context-inferred criteria.
   */
  private extractCriteria(profile: AISystemProfile): string[] {
    const criteria: string[] = [...profile.useCases];

    const sectorMapping: Record<string, string[]> = {
      healthcare: ["essential_services_access"],
      finance: ["essential_services_access"],
      education: ["education_vocational_access"],
      employment: ["employment_worker_management"],
      law_enforcement: ["law_enforcement"],
      border_control: ["migration_asylum_border"],
      infrastructure: ["critical_infrastructure_management"],
    };

    const sectorCriteria = sectorMapping[profile.sector];
    if (sectorCriteria !== undefined) {
      criteria.push(...sectorCriteria);
    }

    // Customer-facing and public deployments carry transparency obligations.
    if (profile.deploymentContext === "customer_facing" || profile.deploymentContext === "public") {
      criteria.push("chatbot_interaction");
    }

    return criteria;
  }

  /** Return the category entry for the given level string, or undefined. */
  private findCategory(level: string): RiskCategoryEntry | undefined {
    return this.categories.categories.find((c) => c.level === level);
  }

  /** Return a prohibited classification if any criterion matches, else null. */
  private checkProhibited(criteria: string[]): RiskClassification | null {
    const category = this.findCategory("prohibited");
    if (category === undefined) return null;

    const matches = criteria.filter((c) => category.criteria.includes(c));
    if (matches.length === 0) return null;

    return {
      level: "prohibited",
      confidence: 0.9,
      matchingCriteria: matches,
      applicableArticles: [...category.articles],
      requiredControls: ["system_must_not_be_deployed"],
      gaps: ["system_is_prohibited"],
      recommendations: [
        "This AI system falls under prohibited use cases. Consult legal counsel immediately.",
      ],
    };
  }

  /** Return a high-risk classification if any criterion matches, else null. */
  private checkHighRisk(criteria: string[], profile: AISystemProfile): RiskClassification | null {
    const category = this.findCategory("high_risk");
    if (category === undefined) return null;

    const matches = criteria.filter((c) => category.criteria.includes(c));
    if (matches.length === 0) return null;

    const required: string[] = [...(category.required_controls ?? [])];
    const existing = new Set(profile.existingControls ?? []);
    const gaps = required.filter((c) => !existing.has(c));

    return {
      level: "high_risk",
      confidence: 0.85,
      matchingCriteria: matches,
      applicableArticles: [...category.articles],
      requiredControls: required,
      gaps,
      recommendations: this.highRiskRecommendations(gaps),
    };
  }

  /** Return a limited-risk classification if any criterion matches, else null. */
  private checkLimitedRisk(
    criteria: string[],
    profile: AISystemProfile,
  ): RiskClassification | null {
    const category = this.findCategory("limited_risk");
    if (category === undefined) return null;

    const matches = criteria.filter((c) => category.criteria.includes(c));
    if (matches.length === 0) return null;

    const required: string[] = [...(category.required_controls ?? [])];
    const existing = new Set(profile.existingControls ?? []);
    const gaps = required.filter((c) => !existing.has(c));

    return {
      level: "limited_risk",
      confidence: 0.8,
      matchingCriteria: matches,
      applicableArticles: [...category.articles],
      requiredControls: required,
      gaps,
      recommendations: this.limitedRiskRecommendations(gaps),
    };
  }

  /** Return the default minimal-risk classification. */
  private minimalRiskResult(): RiskClassification {
    return {
      level: "minimal_risk",
      confidence: 0.7,
      matchingCriteria: ["default"],
      applicableArticles: ["Article 95"],
      requiredControls: ["voluntary_code_of_conduct"],
      gaps: [],
      recommendations: [
        "Consider voluntary adoption of governance best practices.",
        "Use AumOS governance tools for competitive advantage.",
      ],
    };
  }

  /**
   * Map high-risk control gaps to AumOS tool recommendations.
   *
   * Each gap identifier is looked up in a static mapping that points to
   * the most relevant AumOS open-source protocol tool.
   */
  private highRiskRecommendations(gaps: string[]): string[] {
    const controlToAumos: Record<string, string> = {
      risk_management_system: "Use compliance-mapper for risk management documentation",
      data_governance: "Use context-firewall for data domain isolation",
      technical_documentation: "Use aumos-docs templates for technical documentation",
      record_keeping: "Use agent-audit-trail for comprehensive record keeping",
      transparency_information: "Use agents-md-spec for agent capability disclosure",
      human_oversight: "Use trust-ladder L0-L3 for human oversight requirements",
      accuracy_robustness_cybersecurity: "Use anomaly-sentinel + trust-test for robustness",
    };

    const recommendations = gaps
      .map((gap) => controlToAumos[gap])
      .filter((rec): rec is string => rec !== undefined);

    if (recommendations.length === 0) {
      return ["All required controls appear to be in place. Verify implementation depth."];
    }

    return recommendations;
  }

  /** Map limited-risk control gaps to AumOS tool recommendations. */
  private limitedRiskRecommendations(gaps: string[]): string[] {
    const recommendations: string[] = [];

    if (gaps.includes("disclosure_of_ai_interaction")) {
      recommendations.push(
        "Add AI disclosure using agents-md-spec or explicit UI notification",
      );
    }
    if (gaps.includes("content_labeling")) {
      recommendations.push("Label AI-generated content per Article 50 requirements");
    }

    return recommendations.length > 0 ? recommendations : ["Transparency obligations met."];
  }
}
