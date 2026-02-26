# Evidence Collection

This document explains how the compliance-mapper collects and structures
evidence from governance configurations and audit logs.

---

## Overview

Evidence collection is a two-stage pipeline:

```
GovernanceConfig + AuditLog
  → EvidenceCollector.collect_for_control()
      → ControlEvidenceCollection
  → EvidenceGenerator.generate_assessment()
      → ControlAssessment { evidence[], status, gap_description }
  → EvidenceGenerator.generate_gap_item()
      → GapItem | None
```

Both stages are stateless and deterministic for the same inputs. No I/O
occurs after the initial config/log are passed in.

---

## Stage 1: EvidenceCollector

`EvidenceCollector` resolves two kinds of raw evidence for each control:

### Governance config path resolution

Config paths are dot-separated keys that navigate a nested governance config
object. For example, `"governance.access.mfaPolicy"` resolves to the value at:

```python
config["governance"]["access"]["mfaPolicy"]
```

Resolution rules:

- Any segment absent from the dict → `found = False`.
- Terminal value is `None` or `""` → `found = False` (treated as unconfigured).
- Any other value (string, number, boolean, dict, list) → `found = True`.

The result is a `ConfigPathResolution`:

```python
@dataclass(frozen=True)
class ConfigPathResolution:
    path: str         # e.g. "governance.access.mfaPolicy"
    found: bool       # True if path exists and has a meaningful value
    value: Any        # The resolved value, or None
```

### Audit log event resolution

Each required audit log event type is searched across all entries in the
`AuditLog`. Entries are assumed to be in time-ascending order; the last
matching entry's timestamp is used as `last_seen_at`.

The result is an `AuditEventResolution`:

```python
@dataclass(frozen=True)
class AuditEventResolution:
    event_type: str           # e.g. "mfa_enforced"
    found: bool               # True if >= 1 matching entry found
    last_seen_at: str | None  # ISO 8601 timestamp of most recent match
    occurrence_count: int     # Total number of matching entries
```

### ControlEvidenceCollection

`collect_for_control()` bundles both sets of resolutions:

```python
collection = collector.collect_for_control(
    control_id="CC6.1",
    required_config_paths=["governance.access.mfaPolicy"],
    required_audit_events=["mfa_enforced"],
)
```

```python
@dataclass(frozen=True)
class ControlEvidenceCollection:
    control_id: str
    config_resolutions: tuple[ConfigPathResolution, ...]
    audit_event_resolutions: tuple[AuditEventResolution, ...]
    collected_at: str  # ISO 8601 timestamp
```

---

## Stage 2: EvidenceGenerator

`EvidenceGenerator` converts a `ControlEvidenceCollection` into a
`ControlAssessment`.

### Status derivation

Status is derived from the counts of satisfied and missing items:

| Condition | Status |
|-----------|--------|
| No requirements defined | `not_applicable` |
| All config paths present AND all audit events found (or audit gaps not counted) | `satisfied` |
| No config paths present AND no audit events found | `gap` |
| Some requirements met | `partial` |

The `include_audit_event_gaps` option (default `True`) controls whether missing
audit events contribute to gap status. When `False`, only config paths affect
the status calculation.

### EvidenceItem construction

One `EvidenceItem` is created for each **found** config path and each **found**
audit event. Missing items do not produce evidence items — they contribute to
gap tracking only.

```python
@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str         # UUID
    title: str               # e.g. "Config: governance.access.mfaPolicy"
    description: str         # Human-readable explanation
    source_kind: str         # "governance_config" | "audit_log" | "generated_document"
    source_path: str         # Config path or event type
    value: Any               # Resolved value or occurrence count
    collected_at: str        # ISO 8601 timestamp
    is_present: bool         # Always True for items in the evidence array
```

### Gap items

`generate_gap_item()` converts a `ControlAssessment` with status `"gap"` or
`"partial"` into a `GapItem`. The severity is computed from the ratio of missing
items to total required items:

| Missing ratio | Severity |
|---------------|---------|
| >= 80% | `critical` |
| >= 50% | `high` |
| >= 25% | `medium` |
| < 25%  | `low` |

---

## Audit log structure

The `AuditLog` type requires a `start_period` and `end_period` (both ISO 8601)
and an ordered sequence of `AuditLogEntry` objects:

```python
@dataclass(frozen=True)
class AuditLogEntry:
    timestamp: str                              # ISO 8601
    event_type: str                             # Machine-readable identifier
    actor: str                                  # User ID, service name, etc.
    metadata: dict[str, Any]                    # Free-form per-event metadata
    outcome: Literal["success", "failure", "partial"]
    resource_id: str | None = None              # Optional resource reference
```

`event_type` values must match the strings listed in the framework mapping JSON
files under `auditLogEvents` for a control to register audit evidence.

---

## Governance config shape

The governance config is a plain nested dict with no required top-level
structure, but all built-in frameworks expect keys rooted at `governance.*`.
See [frameworks.md](frameworks.md) for namespace details per framework.

Example:

```python
governance_config = {
    "governance": {
        "access": {
            "mfaPolicy": "required",
            "rbacPolicy": "least-privilege",
        },
        "privacy": {
            "dpoContact": "dpo@example.com",
            "consentManagement": "consent-platform-v2",
        },
    }
}
```

---

## Evidence source kinds

| Kind | When used |
|------|-----------|
| `governance_config` | Config path was resolved successfully |
| `audit_log` | Audit log event was found in the log window |
| `generated_document` | Reserved for future use by custom framework implementations |

---

## Using EvidenceCollector directly

You can use `EvidenceCollector` independently for custom assessments:

```python
from compliance_mapper.evidence.collector import EvidenceCollector

collector = EvidenceCollector(config=my_config, audit_log=my_log)

# Resolve specific paths
resolutions = collector.resolve_config_paths([
    "governance.access.mfaPolicy",
    "governance.access.rbacPolicy",
])
for resolution in resolutions:
    print(resolution.path, "->", "FOUND" if resolution.found else "MISSING", resolution.value)

# Check specific audit events
events = collector.resolve_audit_events(["mfa_enforced", "role_assigned"])
for event in events:
    print(event.event_type, ":", event.occurrence_count, "occurrences")
```
