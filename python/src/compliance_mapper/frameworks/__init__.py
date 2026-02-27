# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Compliance framework implementations sub-package.

Re-exports the public surface:

- ``ComplianceFramework`` — abstract base class for implementing new frameworks.
- ``FrameworkMetadata`` — dataclass describing a framework's identity.
- ``SOC2Framework`` — AICPA Trust Services Criteria (2017).
- ``GDPRFramework`` — Regulation (EU) 2016/679.
- ``EUAIActFramework`` — Regulation (EU) 2024/1689, Chapter 2.
- ``ISO42001Framework`` — ISO/IEC 42001:2023, AI Management System.
- ``NISTAIRMFFramework`` — NIST AI Risk Management Framework 1.0.
"""

from __future__ import annotations

from compliance_mapper.frameworks.eu_ai_act import EUAIActFramework
from compliance_mapper.frameworks.gdpr import GDPRFramework
from compliance_mapper.frameworks.interface import ComplianceFramework, FrameworkMetadata
from compliance_mapper.frameworks.iso42001 import ISO42001Framework
from compliance_mapper.frameworks.nist_ai_rmf import NISTAIRMFFramework
from compliance_mapper.frameworks.soc2 import SOC2Framework

__all__ = [
    "ComplianceFramework",
    "FrameworkMetadata",
    "SOC2Framework",
    "GDPRFramework",
    "EUAIActFramework",
    "ISO42001Framework",
    "NISTAIRMFFramework",
]
