# CLAUDE.md — compliance-mapper

## Project Context

Phase 4, Project 4.1 of Project Quasar / Aumos OSS.

Generates point-in-time compliance evidence packages from governance configs and structured audit logs. Targets SOC 2 Type II, GDPR, and EU AI Act.

## Key Conventions

- Every source file opens with the SPDX header and copyright — no exceptions.
- TypeScript: strict mode, no `any`, named exports, functional patterns preferred.
- Python: type hints on all function signatures, Python 3.10+, `from __future__ import annotations`.
- Framework plugins implement `ComplianceFramework` (TS) or `ComplianceFrameworkABC` (Python).
- Evidence items reference their source (config path or audit log entry) explicitly.
- All reports are point-in-time snapshots — no state mutation between calls.

## Forbidden Identifiers

Never use these identifiers anywhere in source:
`progressLevel`, `promoteLevel`, `computeTrustScore`, `behavioralScore`,
`adaptiveBudget`, `optimizeBudget`, `predictSpending`, `detectAnomaly`,
`generateCounterfactual`, `PersonalWorldModel`, `MissionAlignment`,
`SocialTrust`, `CognitiveLoop`, `AttentionFilter`, `GOVERNANCE_PIPELINE`

## Fire Line

See `FIRE_LINE.md` — do not add jurisdiction-specific or vertical-specific frameworks.

## Directory Map

```
mappings/          — Static JSON control/article mappings for all three frameworks
typescript/src/    — @aumos/compliance-mapper TypeScript package
python/src/        — compliance-mapper Python package
examples/          — Runnable example scripts (Python)
docs/              — Framework and API documentation
scripts/           — Utility shell scripts
```

## Core Data Flow

```
GovernanceConfig + AuditLog
  → EvidenceCollector.collect()
  → ComplianceMapper.map(evidence, frameworks[])
  → ComplianceReport { frameworkResults[], gaps[], summary }
  → MarkdownRenderer | JsonRenderer
```

## Adding a Framework

1. Implement `ComplianceFramework` interface (TS) or `ComplianceFrameworkABC` (Python).
2. Add a mapping JSON file under `mappings/`.
3. Register controls with their `governanceConfigPath` references.
4. See `docs/adding-frameworks.md`.

## License

BSL-1.1. All contributions must include the SPDX header.
