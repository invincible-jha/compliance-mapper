# Fire Line — Scope Boundaries

This document defines explicit, non-negotiable scope boundaries for `compliance-mapper`.

## In Scope

- **SOC 2 Type II** — Trust Services Criteria (Security, Availability, Confidentiality, Processing Integrity, Privacy)
- **GDPR** — Articles 5–22, 25, 32, 35 (controller and processor obligations)
- **EU AI Act** — Chapter 2 high-risk AI system requirements (Articles 8–15)
- **Generic ComplianceFramework interface** — enabling users to plug in their own regulatory mappings
- **Point-in-time report generation** — snapshot evidence packages from governance configs and audit logs
- **Gap analysis** — identifying missing governance configurations relative to framework requirements

## Out of Scope — Do Not Implement

### Jurisdiction-Specific Regulations
- India: DPDPA, IT Act, CERT-In directives
- US: CCPA/CPRA, state-level privacy laws
- China: PIPL, DSL
- Any single-country privacy law other than GDPR

### Vertical-Specific Regulations
- Healthcare: HIPAA, HITECH
- Financial services: FINRA, SOX, PCI-DSS, GLBA
- Government: FedRAMP, FISMA, CMMC
- Telecommunications: CPNI regulations

### Continuous Operations
- Real-time monitoring or alerting
- Continuous control testing
- Automated remediation
- CI/CD compliance gating (use `governance-linter` for that)

### Assessment Services
- Third-party audit coordination
- Penetration testing integration
- Vendor risk scoring

## Rationale

`compliance-mapper` is a **generic evidence generation engine**. It maps governance artifacts to control requirements and produces documentation — nothing more. Vertical and jurisdiction scope belongs in community-maintained framework plugins, not the core package.
