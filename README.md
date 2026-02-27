# @aumos/compliance-mapper

[![Governance Score](https://img.shields.io/badge/governance-self--assessed-blue)](https://github.com/aumos-ai/compliance-mapper)

Auto-generate SOC 2 Type II, GDPR, and EU AI Act compliance evidence from governance configs and audit logs.

Part of the [Aumos OSS](https://github.com/muveraai/aumos-oss) governance toolkit — Phase 4, Project 4.1.

## Overview

`compliance-mapper` reads your governance configuration files and structured audit logs, then produces point-in-time compliance evidence packages and gap-analysis reports for:

- **SOC 2 Type II** — 50+ Trust Services Criteria controls
- **GDPR** — Articles 5–22, 25, 32, 35
- **EU AI Act** — Chapter 2 high-risk AI system requirements

The `ComplianceFramework` interface lets you add your own regulatory mappings without touching the core engine.

## Architecture

```
governance configs + audit logs
        │
        ▼
  EvidenceCollector
        │
        ▼
  ComplianceMapper.map()
        │
        ├─► SOC2Framework
        ├─► GDPRFramework
        └─► EUAIActFramework
                │
                ▼
        EvidenceGenerator
                │
                ▼
       ComplianceReport
       (Markdown + JSON)
```

## Quick Start (TypeScript)

```typescript
import { ComplianceMapper, SOC2Framework, GDPRFramework } from "@aumos/compliance-mapper";

const mapper = new ComplianceMapper();
const report = await mapper.map(
  governanceConfig,
  auditLog,
  [new SOC2Framework(), new GDPRFramework()]
);

console.log(report.summary);
```

## Quick Start (Python)

```python
from compliance_mapper import ComplianceMapper
from compliance_mapper.frameworks import SOC2Framework, GDPRFramework

mapper = ComplianceMapper()
report = mapper.map(governance_config, audit_log, [SOC2Framework(), GDPRFramework()])
print(report.summary)
```

## Packages

| Package | Language | Registry |
|---|---|---|
| `@aumos/compliance-mapper` | TypeScript | npm |
| `compliance-mapper` | Python | PyPI |

## Fire Line

See [FIRE_LINE.md](./FIRE_LINE.md) for explicit scope boundaries.

## License

Business Source License 1.1 — see [LICENSE](./LICENSE).
