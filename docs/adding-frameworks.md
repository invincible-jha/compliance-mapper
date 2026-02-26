# Adding a Framework

This document explains how to implement a new compliance framework plugin for
`compliance-mapper`. The same pattern applies to both the Python and TypeScript packages.

---

## Overview

A framework is a class that:

1. Declares its identity via a `metadata` property (`FrameworkMetadata`).
2. Lists all control/article IDs it can assess via `list_control_ids()`.
3. Assesses all controls against a `GovernanceConfig` and `AuditLog` via `assess()`.

The mapper is fully decoupled from framework logic — it calls `assess()` and
works with the returned `ControlAssessment` objects regardless of how the
framework produced them.

---

## Python implementation

### 1. Define the control mapping

Create a JSON file under `mappings/` (optional but recommended for larger
frameworks). Follow the existing file structure:

```json
{
  "$schema": "https://aumos.ai/schemas/compliance-mapping/v1",
  "framework": "ISO/IEC 27001:2022",
  "version": "2022",
  "source": "ISO/IEC",
  "lastUpdated": "2026-02-26",
  "categories": [
    {
      "id": "A5",
      "name": "Organizational Controls",
      "controls": [
        {
          "id": "A.5.1",
          "title": "Policies for information security",
          "description": "Information security policy and topic-specific policies shall be defined.",
          "governanceConfigPaths": [
            "governance.security.informationSecurityPolicy",
            "governance.policies.policyInventory"
          ],
          "auditLogEvents": ["policy_approved", "policy_reviewed"],
          "evidenceTypes": ["policy_document", "policy_register"]
        }
      ]
    }
  ]
}
```

### 2. Create the framework file

Create `python/src/compliance_mapper/frameworks/iso27001.py`:

```python
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""ISO/IEC 27001:2022 compliance framework implementation."""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from compliance_mapper.evidence.collector import EvidenceCollector
from compliance_mapper.evidence.generator import AssessmentGenerationParams, EvidenceGenerator
from compliance_mapper.evidence.types import ControlEvidenceCollection
from compliance_mapper.frameworks.interface import ComplianceFramework, FrameworkMetadata
from compliance_mapper.types import (
    AuditLog,
    ControlAssessment,
    GovernanceConfig,
    MapperOptions,
)


@dataclass(frozen=True)
class _ISO27001Control:
    id: str
    title: str
    description: str
    governance_config_paths: tuple[str, ...]
    audit_log_events: tuple[str, ...]


# Inline fallback — include the most critical controls here.
_INLINE_CONTROLS: tuple[_ISO27001Control, ...] = (
    _ISO27001Control(
        id="A.5.1",
        title="Policies for information security",
        description="Information security policy and topic-specific policies shall be defined.",
        governance_config_paths=(
            "governance.security.informationSecurityPolicy",
            "governance.policies.policyInventory",
        ),
        audit_log_events=("policy_approved", "policy_reviewed"),
    ),
    # Add more controls here...
)

_MAPPING_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent.parent
    / "mappings"
    / "iso27001-controls.json"
)


def _parse_control(raw: dict[str, Any]) -> _ISO27001Control:
    return _ISO27001Control(
        id=raw["id"],
        title=raw["title"],
        description=raw["description"],
        governance_config_paths=tuple(raw.get("governanceConfigPaths", [])),
        audit_log_events=tuple(raw.get("auditLogEvents", [])),
    )


def _load_controls() -> tuple[_ISO27001Control, ...]:
    try:
        data = json.loads(_MAPPING_PATH.read_text(encoding="utf-8"))
        controls = [
            _parse_control(c)
            for category in data.get("categories", [])
            for c in category.get("controls", [])
        ]
        return tuple(controls) if controls else _INLINE_CONTROLS
    except (OSError, KeyError, json.JSONDecodeError):
        return _INLINE_CONTROLS


class ISO27001Framework(ComplianceFramework):
    """ISO/IEC 27001:2022 compliance framework."""

    def __init__(self) -> None:
        self._controls: tuple[_ISO27001Control, ...] | None = None

    @property
    def metadata(self) -> FrameworkMetadata:
        return FrameworkMetadata(
            id="iso27001",
            name="ISO/IEC 27001:2022",
            version="2022",
            source="ISO/IEC",
            scope_description="Information security management system controls.",
        )

    def _ensure_loaded(self) -> tuple[_ISO27001Control, ...]:
        if self._controls is None:
            self._controls = _load_controls()
        return self._controls

    def list_control_ids(self) -> tuple[str, ...]:
        return tuple(c.id for c in self._ensure_loaded())

    def assess(
        self,
        governance_config: GovernanceConfig,
        audit_log: AuditLog,
        options: MapperOptions,
    ) -> tuple[ControlAssessment, ...]:
        controls = self._ensure_loaded()
        excluded_ids = set(options.exclude_control_ids)
        report_timestamp = (
            options.report_timestamp or datetime.now(tz=timezone.utc).isoformat()
        )

        collector = EvidenceCollector(config=governance_config, audit_log=audit_log)
        generator = EvidenceGenerator()

        assessments: list[ControlAssessment] = []
        for control in controls:
            is_excluded = control.id in excluded_ids

            if is_excluded:
                collection = ControlEvidenceCollection(
                    control_id=control.id,
                    config_resolutions=(),
                    audit_event_resolutions=(),
                    collected_at=report_timestamp,
                )
            else:
                collection = collector.collect_for_control(
                    control_id=control.id,
                    required_config_paths=control.governance_config_paths,
                    required_audit_events=control.audit_log_events,
                )

            assessments.append(
                generator.generate_assessment(
                    AssessmentGenerationParams(
                        control_id=control.id,
                        title=control.title,
                        description=control.description,
                        framework_id=self.metadata.id,
                        collection=collection,
                        include_audit_event_gaps=options.include_audit_event_gaps,
                        is_excluded=is_excluded,
                    )
                )
            )

        return tuple(assessments)
```

### 3. Register the framework (optional)

If you want the framework available from the package root, add it to
`python/src/compliance_mapper/frameworks/__init__.py`:

```python
from compliance_mapper.frameworks.iso27001 import ISO27001Framework

__all__ = [
    ...,
    "ISO27001Framework",
]
```

### 4. Use the framework

```python
from compliance_mapper import ComplianceMapper
from compliance_mapper.frameworks.iso27001 import ISO27001Framework

mapper = ComplianceMapper()
report = mapper.map(
    governance_config,
    audit_log,
    [ISO27001Framework()],
)
```

---

## TypeScript implementation

The TypeScript pattern mirrors the Python pattern. Implement the
`ComplianceFramework` interface from `./frameworks/interface.ts`:

```typescript
import type { ComplianceFramework, FrameworkMetadata } from "./interface.js";
import type { ControlAssessment, GovernanceConfig, AuditLog, MapperOptions } from "../types.js";
import { EvidenceCollector } from "../evidence/collector.js";
import { EvidenceGenerator } from "../evidence/generator.js";

export class ISO27001Framework implements ComplianceFramework {
  private controls: readonly ISO27001Control[] = [];
  private loaded = false;

  readonly metadata: FrameworkMetadata = {
    id: "iso27001",
    name: "ISO/IEC 27001:2022",
    version: "2022",
    source: "ISO/IEC",
    scopeDescription: "Information security management system controls.",
  };

  listControlIds(): readonly string[] {
    return this.controls.map((c) => c.id);
  }

  async assess(
    governanceConfig: GovernanceConfig,
    auditLog: AuditLog,
    options: MapperOptions,
  ): Promise<readonly ControlAssessment[]> {
    // ... implementation follows soc2.ts pattern
  }
}
```

---

## Design guidelines

**Keep frameworks generic.** Each framework should cover a single, widely
recognised regulatory standard or certification scheme. Jurisdiction-specific
or vertical-specific variants should be separate framework classes, not
conditional logic inside an existing one.

**Use descriptive `governance_config_paths`.** Path names should be readable
and consistent with the `governance.*` namespace convention used throughout the
built-in frameworks. Avoid abbreviations.

**Provide a meaningful inline fallback.** The inline control set should cover
the most critical subset of controls so the framework is useful even when the
JSON mapping file is absent.

**Write tests.** Add a test file under `python/tests/` (or `typescript/src/`)
that covers:
- Satisfied, gap, partial, and not-applicable status outcomes.
- JSON file load path and inline fallback.
- Exclusion via `MapperOptions.exclude_control_ids`.

---

## Fire line

The following are permanently out of scope for new framework implementations:

- India-specific regulatory frameworks (DPDPA, RBI, SEBI).
- UPI or India payment system governance.
- Vertical-specific frameworks (healthcare-only, fintech-only).
- Any framework that requires continuous monitoring state between mapper calls.

See `FIRE_LINE.md` for the full list of prohibited project types.
