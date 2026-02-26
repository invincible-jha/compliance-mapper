# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
"""
EvidenceCollector — resolves governance config paths and audit log event
lookups for a given set of control requirements.

This module is intentionally stateless with respect to the framework being
assessed. Each ``collect_for_control`` call is an independent, pure operation
given the same ``GovernanceConfig`` and ``AuditLog`` inputs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from compliance_mapper.evidence.types import (
    AuditEventResolution,
    ConfigPathResolution,
    ControlEvidenceCollection,
)
from compliance_mapper.types import AuditLog, GovernanceConfig


def _resolve_config_path(config: GovernanceConfig, path: str) -> Any:
    """
    Resolve a dot-separated path against a nested configuration dict.

    Returns ``None`` if any segment in the path is absent, or if the terminal
    value is ``None`` or an empty string (treated as not configured).

    Examples::

        >>> cfg = {"governance": {"access": {"mfaPolicy": "required"}}}
        >>> _resolve_config_path(cfg, "governance.access.mfaPolicy")
        'required'
        >>> _resolve_config_path(cfg, "governance.access.missing")  # None
    """
    segments = path.split(".")
    current: Any = config

    for segment in segments:
        if not isinstance(current, dict):
            return None
        if segment not in current:
            return None
        current = current[segment]

    # Empty strings are treated as unconfigured — a meaningful value is required.
    if current is None or current == "":
        return None
    return current


class EvidenceCollector:
    """
    Gather raw evidence from a governance config and audit log for a set of
    control requirements.

    The collector is stateless with respect to individual framework assessments;
    you may reuse a single instance across many ``collect_for_control`` calls.

    Parameters
    ----------
    config:
        The governance configuration dict to resolve paths against.
    audit_log:
        The structured audit log to search for event types.

    Example::

        from compliance_mapper.evidence.collector import EvidenceCollector
        from compliance_mapper.types import AuditLog, AuditLogEntry

        collector = EvidenceCollector(config=my_config, audit_log=my_log)
        collection = collector.collect_for_control(
            control_id="CC6.1",
            required_config_paths=["governance.access.mfaPolicy"],
            required_audit_events=["mfa_enforced"],
        )
    """

    def __init__(self, config: GovernanceConfig, audit_log: AuditLog) -> None:
        self._config = config
        self._audit_log = audit_log

    def resolve_config_paths(
        self, paths: tuple[str, ...] | list[str]
    ) -> tuple[ConfigPathResolution, ...]:
        """
        Resolve all required config paths for a single control.

        Parameters
        ----------
        paths:
            Dot-separated governance config paths to check.

        Returns
        -------
        tuple[ConfigPathResolution, ...]
            One resolution per path, in input order.
        """
        resolutions: list[ConfigPathResolution] = []
        for path in paths:
            value = _resolve_config_path(self._config, path)
            resolutions.append(
                ConfigPathResolution(
                    path=path,
                    found=value is not None,
                    value=value,
                )
            )
        return tuple(resolutions)

    def resolve_audit_events(
        self, event_types: tuple[str, ...] | list[str]
    ) -> tuple[AuditEventResolution, ...]:
        """
        Search the audit log for occurrences of each required event type.

        Entries are expected to be in time-ascending order; the last matching
        entry is used as ``last_seen_at``.

        Parameters
        ----------
        event_types:
            Audit log event type strings to search for.

        Returns
        -------
        tuple[AuditEventResolution, ...]
            One resolution per event type, in input order.
        """
        resolutions: list[AuditEventResolution] = []
        for event_type in event_types:
            matches = [e for e in self._audit_log.entries if e.event_type == event_type]
            if not matches:
                resolutions.append(
                    AuditEventResolution(
                        event_type=event_type,
                        found=False,
                        last_seen_at=None,
                        occurrence_count=0,
                    )
                )
            else:
                # Last entry in time-ascending order has the most recent timestamp.
                last_seen_at = matches[-1].timestamp
                resolutions.append(
                    AuditEventResolution(
                        event_type=event_type,
                        found=True,
                        last_seen_at=last_seen_at,
                        occurrence_count=len(matches),
                    )
                )
        return tuple(resolutions)

    def collect_for_control(
        self,
        control_id: str,
        required_config_paths: tuple[str, ...] | list[str],
        required_audit_events: tuple[str, ...] | list[str],
    ) -> ControlEvidenceCollection:
        """
        Collect all evidence for a single control or article.

        Parameters
        ----------
        control_id:
            Framework-specific identifier (e.g. ``'CC6.1'``, ``'Art32'``).
        required_config_paths:
            Governance config paths that should be populated.
        required_audit_events:
            Audit log event types that should appear in the log window.

        Returns
        -------
        ControlEvidenceCollection
            Raw collection result ready to be passed to ``EvidenceGenerator``.
        """
        collected_at = datetime.now(tz=timezone.utc).isoformat()
        config_resolutions = self.resolve_config_paths(required_config_paths)
        audit_event_resolutions = self.resolve_audit_events(required_audit_events)

        return ControlEvidenceCollection(
            control_id=control_id,
            config_resolutions=config_resolutions,
            audit_event_resolutions=audit_event_resolutions,
            collected_at=collected_at,
        )
