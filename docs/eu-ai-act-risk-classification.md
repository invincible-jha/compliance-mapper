# EU AI Act Risk Classification

The `EUAIActRiskClassifier` classifies an AI system's risk level under
**Regulation (EU) 2024/1689** (the EU AI Act) and maps identified control
gaps to AumOS protocol tools for remediation.

## Background

The EU AI Act assigns every AI system to one of four risk levels:

| Level | Legal basis | Obligation |
|---|---|---|
| **Prohibited** | Article 5 | System must not be deployed |
| **High risk** | Article 6 + Annex III | Mandatory controls before market placement |
| **Limited risk** | Article 50 | Transparency disclosures to users |
| **Minimal risk** | Article 95 | Voluntary codes of conduct only |

The classifier implements a **priority waterfall** — prohibited is evaluated
first, then high-risk, then limited risk, with minimal risk as the default.

## Quick Start

### Python

```python
from compliance_mapper.risk_classifier import (
    AISystemProfile,
    EUAIActRiskClassifier,
)

classifier = EUAIActRiskClassifier()

profile = AISystemProfile(
    name="Loan Decision Engine",
    description="Automated credit scoring for retail banking customers.",
    use_cases=["essential_services_access"],
    data_types=["financial", "personal"],
    autonomy_level="semi_autonomous",
    deployment_context="customer_facing",
    sector="finance",
    existing_controls=["risk_management_system", "technical_documentation"],
)

result = classifier.classify(profile)

print(result.level.value)        # "high_risk"
print(result.gaps)               # ("data_governance", "record_keeping", ...)
print(result.recommendations)    # ("Use context-firewall for data domain isolation", ...)
```

### TypeScript

```typescript
import { EUAIActRiskClassifier } from "@aumos/compliance-mapper/risk-classifier";

const classifier = new EUAIActRiskClassifier();

const result = classifier.classify({
  name: "Loan Decision Engine",
  description: "Automated credit scoring for retail banking customers.",
  useCases: ["essential_services_access"],
  dataTypes: ["financial", "personal"],
  autonomyLevel: "semi_autonomous",
  deploymentContext: "customer_facing",
  sector: "finance",
  existingControls: ["risk_management_system", "technical_documentation"],
});

console.log(result.level);            // "high_risk"
console.log(result.gaps);             // ["data_governance", "record_keeping", ...]
console.log(result.recommendations);  // ["Use context-firewall ...", ...]
```

## Building an AI System Profile

The `AISystemProfile` (Python) / `AISystemProfile` interface (TypeScript)
describes the system under assessment. All fields affect classification.

### `use_cases` / `useCases`

Explicit use-case identifiers that directly match risk criteria in the
mapping JSON. Use these to override or supplement sector-inferred criteria.

**Prohibited-tier criteria** (Article 5):

| Identifier | Description |
|---|---|
| `social_scoring_by_public_authorities` | Social credit scoring by government bodies |
| `real_time_biometric_identification_in_public` | Real-time remote biometric ID in public spaces |
| `emotion_recognition_in_workplace_education` | Emotion recognition in workplace or educational settings |
| `predictive_policing_based_solely_on_profiling` | Predictive policing using profiling alone |
| `untargeted_facial_image_scraping` | Bulk facial image scraping from the internet |
| `subliminal_manipulation_causing_harm` | Subliminal techniques that cause psychological harm |
| `exploitation_of_vulnerabilities` | Exploiting vulnerabilities of protected groups |

**High-risk criteria** (Annex III):

| Identifier | Description |
|---|---|
| `biometric_identification` | Remote biometric identification systems |
| `critical_infrastructure_management` | Management of critical infrastructure |
| `education_vocational_access` | Decisions on access to educational institutions |
| `employment_worker_management` | Recruitment, promotion, and performance monitoring |
| `essential_services_access` | Access to credit, insurance, healthcare, public services |
| `law_enforcement` | Risk assessment, evidence evaluation in law enforcement |
| `migration_asylum_border` | Polygraph-style tools, risk assessment at borders |
| `justice_democratic_processes` | AI in administration of justice or elections |
| `safety_component_of_regulated_product` | Safety component in machinery, medical devices, etc. |

**Limited-risk criteria** (Article 50):

| Identifier | Description |
|---|---|
| `chatbot_interaction` | Chatbots interacting with natural persons |
| `emotion_recognition` | Emotion recognition systems |
| `biometric_categorization` | Biometric categorization systems |
| `deep_fake_generation` | Generating synthetic audio/image/video |
| `ai_generated_content` | Any AI-generated content requiring labeling |

### `sector`

The sector field triggers automatic inference of criteria:

| Sector value | Inferred criterion |
|---|---|
| `healthcare` | `essential_services_access` |
| `finance` | `essential_services_access` |
| `education` | `education_vocational_access` |
| `employment` | `employment_worker_management` |
| `law_enforcement` | `law_enforcement` |
| `border_control` | `migration_asylum_border` |
| `infrastructure` | `critical_infrastructure_management` |

### `deployment_context`

Systems deployed as `"customer_facing"` or `"public"` automatically receive
the `chatbot_interaction` criterion, triggering at minimum limited-risk
transparency obligations under Article 50.

### `existing_controls`

List controls already implemented to receive an accurate gap analysis.
Valid control identifiers are listed in
`mappings/eu-ai-act-risk-categories.json` under `required_controls`.

**High-risk controls** (Articles 8–15):

| Identifier | Maps to AumOS tool |
|---|---|
| `risk_management_system` | compliance-mapper |
| `data_governance` | context-firewall |
| `technical_documentation` | agents-md-spec + aumos-docs |
| `record_keeping` | agent-audit-trail |
| `transparency_information` | agents-md-spec |
| `human_oversight` | trust-ladder |
| `accuracy_robustness_cybersecurity` | anomaly-sentinel + trust-test |

**Limited-risk controls** (Article 50):

| Identifier | Maps to AumOS tool |
|---|---|
| `disclosure_of_ai_interaction` | agents-md-spec |
| `content_labeling` | agents-md-spec |

## Understanding the Result

The `RiskClassification` / `RiskClassification` interface provides:

- **`level`** — The assigned risk level.
- **`confidence`** — How certain the classifier is (0.0–1.0). Values below
  0.75 indicate borderline cases requiring human legal review.
- **`matchingCriteria`** — Which criteria drove the classification.
- **`applicableArticles`** — EU AI Act articles that apply.
- **`requiredControls`** — All mandatory controls for this risk level.
- **`gaps`** — Controls required but not in `existingControls`.
- **`recommendations`** — One AumOS tool suggestion per gap.

## Article-to-AumOS Mapping

The full article-to-tool mapping is in
`mappings/eu-ai-act-article-mapping.json`. Key mappings:

| Article | Requirement | AumOS Tool |
|---|---|---|
| Article 9 | Risk management system | compliance-mapper |
| Article 10 | Data governance | context-firewall |
| Article 11 | Technical documentation | agents-md-spec |
| Article 12 | Record-keeping | agent-audit-trail |
| Article 13 | Transparency to deployers | agents-md-spec |
| Article 14 | Human oversight | trust-ladder |
| Article 15 | Accuracy and robustness | anomaly-sentinel + trust-test |
| Article 50 | Transparency to users | agents-md-spec |

## Running the Example

```bash
# From the repo root
python examples/risk-classification-example.py
```

This classifies three sample systems — a loan engine (high-risk), a customer
chatbot (limited risk), and an internal recommendation tool (minimal risk) —
and prints the gap analysis with AumOS remediation guidance for each.

## Limitations

- The classifier uses keyword matching against static JSON criteria. It is a
  decision-support tool, not a legal determination. Consult qualified legal
  counsel before relying on the output for regulatory submissions.
- The `confidence` values are heuristic approximations, not probabilistic
  model outputs. A confidence of 0.85 means the matched criteria strongly
  suggest that risk level; it does not mean a 15% probability of being wrong.
- Sector and deployment-context inference covers the most common patterns.
  Novel deployment contexts may require adding explicit `use_cases` values.

## Related Files

| File | Purpose |
|---|---|
| `mappings/eu-ai-act-risk-categories.json` | Risk level criteria and required controls |
| `mappings/eu-ai-act-article-mapping.json` | Article-to-AumOS-tool mapping |
| `python/src/compliance_mapper/risk_classifier.py` | Python implementation |
| `typescript/src/risk-classifier.ts` | TypeScript implementation |
| `examples/risk-classification-example.py` | Runnable three-system example |
