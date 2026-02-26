# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
Internal types for the evidence collection and generation pipeline.

These dataclasses represent the intermediate state produced by
``EvidenceCollector`` before ``EvidenceGenerator`` converts them into the
public ``ControlAssessment`` and ``EvidenceItem`` types.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ConfigPathResolution:
    """Result of resolving a single dot-separated config path against a governance config."""

    path: str
    """The dot-separated path that was resolved (e.g. ``'governance.access.mfaPolicy'``)."""

    found: bool
    """Whether the path existed and had a non-null, non-empty value."""

    value: Any
    """The resolved value, or ``None`` if not found."""


@dataclass(frozen=True)
class AuditEventResolution:
    """Result of searching the audit log for a specific event type."""

    event_type: str
    """The event type that was searched for."""

    found: bool
    """Whether at least one matching entry was found."""

    last_seen_at: str | None
    """The most recent matching entry's timestamp, or ``None`` if not found."""

    occurrence_count: int
    """Total number of matching entries found."""


@dataclass(frozen=True)
class ControlEvidenceCollection:
    """Aggregated collection result for a single control or article."""

    control_id: str
    """Framework-specific control or article identifier."""

    config_resolutions: tuple[ConfigPathResolution, ...]
    """Resolutions for each required governance config path."""

    audit_event_resolutions: tuple[AuditEventResolution, ...]
    """Resolutions for each required audit log event."""

    collected_at: str
    """ISO 8601 timestamp when collection ran."""
