# Compliance Frameworks

This document describes the three built-in frameworks included in `compliance-mapper`
and explains how they map governance configuration paths and audit log events to
specific controls or regulatory articles.

---

## How frameworks work

Each framework implements the `ComplianceFramework` interface (TypeScript) or
`ComplianceFramework` ABC (Python). When the mapper calls `assess()`, the framework:

1. Iterates over its control or article list.
2. Calls `EvidenceCollector.collect_for_control()` for each item, resolving
   dot-separated governance config paths and searching the audit log for required
   event types.
3. Passes the raw collection to `EvidenceGenerator.generate_assessment()`, which
   determines `ControlStatus` and builds `EvidenceItem` objects.

All three frameworks load their full control/article list from a JSON file under
`mappings/` at the repository root. If the file is unavailable (e.g. when installed
as a library without the repository), each framework falls back to an inline subset
of the most commonly assessed controls.

---

## SOC 2 Type II

**Framework ID:** `soc2`
**Issuer:** AICPA
**Version:** 2017 (Trust Services Criteria)

### Scope

The SOC 2 framework covers all five Trust Services Categories:

| Category | Prefix | Description |
|----------|--------|-------------|
| Security (Common Criteria) | `CC` | Logical and physical access, change management, incident response |
| Availability | `A` | Capacity, redundancy, recovery |
| Confidentiality | `C` | Data classification, labelling, disposal |
| Processing Integrity | `PI` | Input/output validation, reconciliation |
| Privacy | `P` | Notice, consent, access, disclosure, quality |

### Control mapping structure

Each control in `mappings/soc2-controls.json` specifies:

```json
{
  "id": "CC6.1",
  "title": "Logical Access Security Software Infrastructure",
  "description": "...",
  "governanceConfigPaths": [
    "governance.access.authenticationPolicy",
    "governance.access.mfaPolicy",
    "governance.access.networkSegmentationPolicy"
  ],
  "auditLogEvents": [
    "mfa_enforced",
    "access_attempt",
    "network_policy_applied"
  ],
  "evidenceTypes": ["access_policy", "mfa_configuration", "network_diagram"]
}
```

The mapper resolves each `governanceConfigPaths` entry against the input config
and checks for each `auditLogEvents` entry in the audit log window.

### Governance config shape

Controls reference paths rooted at `governance.*`. Common namespaces:

| Namespace | Purpose |
|-----------|---------|
| `governance.access` | Authentication, MFA, RBAC, provisioning |
| `governance.ethics` | Code of conduct, conflict-of-interest policies |
| `governance.incident` | Response policy, team, communication |
| `governance.changeManagement` | Change policy, approval, testing |
| `governance.business` | BCP, RTO/RPO, DR test schedule |
| `governance.data` | Classification, retention, encryption |
| `governance.privacy` | Notice, consent, data subject rights |
| `governance.risk` | Risk register, assessment, mitigation |
| `governance.monitoring` | SIEM, alerting, log aggregation |

---

## GDPR

**Framework ID:** `gdpr`
**Issuer:** European Parliament and Council
**Version:** 2016/679

### Scope

The GDPR framework covers controller and processor obligations under
Regulation (EU) 2016/679. Articles assessed:

| Article | Title |
|---------|-------|
| Art5 | Principles relating to processing of personal data |
| Art6 | Lawfulness of processing |
| Art7 | Conditions for consent |
| Art15 | Right of access by the data subject |
| Art17 | Right to erasure ('right to be forgotten') |
| Art22 | Automated individual decision-making, including profiling |
| Art25 | Data protection by design and by default |
| Art30 | Records of processing activities |
| Art32 | Security of processing |
| Art33 | Notification of a personal data breach to the supervisory authority |
| Art35 | Data protection impact assessment |

### Governance config shape

Key namespaces for GDPR controls:

| Namespace | Purpose |
|-----------|---------|
| `governance.privacy` | Lawful basis, consent, DSAR process, DPIA, DPO |
| `governance.data` | Retention, encryption, pseudonymisation, disposal |
| `governance.ai` | Automated decision register, human oversight, profiling |
| `governance.security` | Access control, penetration testing, vulnerability management |

---

## EU AI Act

**Framework ID:** `eu-ai-act`
**Issuer:** European Parliament and Council
**Version:** 2024/1689

### Scope

The EU AI Act framework covers **Chapter 2** requirements (Articles 8–15) for
**high-risk AI systems** as classified under Annex III of
Regulation (EU) 2024/1689. GPAI model obligations (Chapter 5) are out of scope.

| Article | Title |
|---------|-------|
| Art8 | Compliance with the requirements |
| Art9 | Risk management system |
| Art10 | Data and data governance |
| Art11 | Technical documentation |
| Art12 | Record-keeping |
| Art13 | Transparency and provision of information to deployers |
| Art14 | Human oversight |
| Art15 | Accuracy, robustness and cybersecurity |

### Governance config shape

All AI Act controls reference paths under `governance.ai.*`:

| Namespace | Purpose |
|-----------|---------|
| `governance.ai.riskManagementSystem` | Risk management system documentation |
| `governance.ai.dataGovernancePolicy` | Training/validation data governance |
| `governance.ai.technicalDocumentationRegister` | Technical docs registry |
| `governance.ai.auditLoggingPolicy` | Logging policy for AI decisions |
| `governance.ai.humanOversightProcess` | Human oversight procedures |
| `governance.ai.accuracyMetrics` | Accuracy measurement and thresholds |
| `governance.security.aiSystemSecurityPolicy` | AI-specific security controls |

---

## Control status definitions

| Status | Meaning |
|--------|---------|
| `satisfied` | All required config paths are populated and all required audit events were found |
| `partial` | Some requirements met, but not all |
| `gap` | No requirements met — config paths missing and no audit events found |
| `not_applicable` | Control was excluded via `MapperOptions.exclude_control_ids` or has no requirements defined |

## Gap severity definitions

| Severity | Criteria |
|----------|---------|
| `critical` | >= 80% of required items missing |
| `high` | >= 50% missing |
| `medium` | >= 25% missing |
| `low` | < 25% missing |
