# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Evidence collection and generation sub-package.

Re-exports the public surface of the evidence pipeline:

- ``EvidenceCollector`` — resolves governance config paths and audit log events.
- ``EvidenceGenerator`` — converts raw collections into ``ControlAssessment``
  and ``GapItem`` objects.
- Internal resolution types for users who need to inspect intermediate results.
"""

from __future__ import annotations

from compliance_mapper.evidence.collector import EvidenceCollector
from compliance_mapper.evidence.generator import (
    AssessmentGenerationParams,
    EvidenceGenerator,
)
from compliance_mapper.evidence.types import (
    AuditEventResolution,
    ConfigPathResolution,
    ControlEvidenceCollection,
)

__all__ = [
    "EvidenceCollector",
    "EvidenceGenerator",
    "AssessmentGenerationParams",
    "AuditEventResolution",
    "ConfigPathResolution",
    "ControlEvidenceCollection",
]
