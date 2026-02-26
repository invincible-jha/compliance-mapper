# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-02-26

### Added
- `ComplianceMapper` core engine with `map()` entry point
- `ComplianceFramework` interface for pluggable regulatory frameworks
- `SOC2Framework` with 50+ Trust Services Criteria control mappings
- `GDPRFramework` mapping Articles 5–22, 25, 32, 35
- `EUAIActFramework` mapping Chapter 2 high-risk AI system requirements
- `EvidenceCollector` — gathers evidence from governance configs and audit logs
- `EvidenceGenerator` — produces compliance document artifacts
- Markdown and JSON report renderers
- Gap analysis identifying missing governance configuration paths
- Structured mapping JSON files for all three frameworks
- Python package `compliance-mapper` with full type hints
- TypeScript package `@aumos/compliance-mapper` in strict mode
- Example scripts for SOC 2, GDPR, and full multi-framework reports
- `fire-line-audit.sh` script for scope-boundary verification
