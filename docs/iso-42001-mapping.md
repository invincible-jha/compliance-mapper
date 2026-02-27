# ISO/IEC 42001:2023 Mapping

This document explains how `compliance-mapper` maps ISO/IEC 42001:2023
(AI Management System) clauses and Annex A controls to AumOS governance
protocols, and how to generate coverage reports and gap analyses.

---

## Overview

ISO/IEC 42001 is the first international standard for AI Management Systems
(AIMS). It provides a structured framework for organizations to manage AI
risks, establish governance, and demonstrate responsible AI practices.

The mapping covers:

- **Clauses 4–10**: Core management system requirements (context, leadership,
  planning, support, operation, performance evaluation, improvement).
- **Annex A (A.2–A.10)**: AI-specific controls covering policies, internal
  organization, resources, impact assessment, lifecycle management, data
  governance, transparency, use, and monitoring.

Each clause maps to one or more AumOS protocol controls (ATP, AOAP, ALP)
and specifies the governance configuration paths and audit log events
needed to demonstrate compliance.

---

## Quick Start

### Python

```python
from compliance_mapper.frameworks.iso42001 import (
    ISO42001Framework,
    get_coverage_report,
    get_evidence_requirements,
    generate_gap_analysis,
)

# 1. Generate a coverage report from your GBOM controls.
gbom_controls = ["ATP-001", "AOAP-001", "ALP-002", "ATP-007", "AOAP-004"]
report = get_coverage_report(gbom_controls)

print(f"Coverage: {report.coverage_percentage}%")
print(f"Covered: {report.covered_count}/{report.total_clauses}")

# 2. Look up evidence requirements for a specific clause.
requirements = get_evidence_requirements("5.1")
for req in requirements:
    print(f"  Evidence type: {req.evidence_type}")
    print(f"  Config paths: {req.governance_config_paths}")

# 3. Generate a gap analysis.
gaps = generate_gap_analysis(gbom_controls)
print(f"Total gaps: {gaps.total_gaps}")
for gap in gaps.gaps:
    print(f"  {gap.clause_id}: {gap.title} ({gap.severity})")

# 4. Use as a ComplianceFramework in the mapper.
from compliance_mapper.mapper import ComplianceMapper

mapper = ComplianceMapper()
compliance_report = mapper.map(
    governance_config,
    audit_log,
    [ISO42001Framework()],
)
```

### TypeScript

```typescript
import {
  ISO42001Framework,
  getCoverageReport,
  getEvidenceRequirements,
  generateGapAnalysis,
} from "@aumos/compliance-mapper/frameworks/iso42001";

// 1. Generate a coverage report.
const report = await getCoverageReport(["ATP-001", "AOAP-001", "ALP-002"]);
console.log(`Coverage: ${report.coveragePercentage}%`);

// 2. Look up evidence requirements.
const requirements = await getEvidenceRequirements("5.1");

// 3. Generate a gap analysis.
const gaps = await generateGapAnalysis(["ATP-001", "AOAP-001"]);

// 4. Use as a ComplianceFramework in the mapper.
import { ComplianceMapper } from "@aumos/compliance-mapper";

const mapper = new ComplianceMapper();
const complianceReport = await mapper.map(config, auditLog, [
  new ISO42001Framework(),
]);
```

---

## Clause-to-AumOS Mapping Summary

| Clause | Title | AumOS Protocols | Evidence Type |
|--------|-------|-----------------|---------------|
| 4.1 | Understanding the organization | ATP | governance_config |
| 4.2 | Interested parties | ATP, AOAP | governance_config |
| 4.3 | Scope of the AIMS | ATP | governance_config |
| 5.1 | Leadership and commitment | ATP, AOAP | governance_config |
| 5.2 | AI policy | ATP, ALP | policy_document |
| 5.3 | Roles and responsibilities | ATP, AOAP | governance_config |
| 6.1 | Risk and opportunity actions | ATP, AOAP | risk_assessment |
| 6.2 | AI objectives | ATP | governance_config |
| 7.1–7.5 | Support (resources through docs) | ATP, ALP, AOAP | mixed |
| 8.1–8.4 | Operation (planning through impact) | ATP, AOAP, ALP | mixed |
| 9.1–9.3 | Performance evaluation | ALP, AOAP, ATP | mixed |
| 10.1–10.2 | Improvement | ALP, AOAP, ATP | mixed |
| A.2–A.10 | Annex A controls | ATP, AOAP, ALP | mixed |

---

## Evidence Types

The mapping uses these evidence types to classify required documentation:

| Type | Description |
|------|-------------|
| `governance_config` | Configuration settings from the governance system |
| `policy_document` | Formal policy documents |
| `risk_assessment` | Risk identification, analysis, and treatment records |
| `impact_assessment` | AI system impact assessments on individuals and society |
| `training_record` | Personnel training and competence records |
| `monitoring_record` | Ongoing monitoring and measurement results |
| `audit_report` | Internal audit reports and findings |
| `review_record` | Management review minutes and decisions |
| `corrective_action` | Nonconformity and corrective action records |

---

## Mapping File

The full mapping is stored in `mappings/iso-42001-controls.json`. Each entry
contains:

- `id` — Clause identifier (e.g. `"5.1"`, `"A.5.2"`)
- `title` — Clause title
- `category` — Clause category grouping
- `aumos_protocols` — AumOS protocols that address this clause
- `aumos_controls` — Specific AumOS control identifiers
- `governanceConfigPaths` — Governance config paths needed for evidence
- `auditLogEvents` — Audit log event types needed for evidence

---

## Related Files

| File | Purpose |
|------|---------|
| `mappings/iso-42001-controls.json` | Full clause-to-control mapping |
| `python/src/compliance_mapper/frameworks/iso42001.py` | Python framework handler |
| `typescript/src/frameworks/iso42001.ts` | TypeScript framework handler |
| `docs/adding-frameworks.md` | How to add new framework plugins |
