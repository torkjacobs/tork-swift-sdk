# Changelog

## 0.2.0 - 2026-09-03

### Added
- feat: tool-result scanning (`scanToolResult`, `Tork.scanToolResult`) for PII and prompt-injection heuristics on MCP/external tool results, ported from tork-js-sdk's tool-result-scan.ts (DECIDED-TACT2-V2-C). Tier 1 parity: 10-type PII vocabulary, `tork-injection-heuristics-v1` heuristic ruleset, `toolResultScan` receipt block.

### Fixed
- fix: `PIIType` declared only 7 of the JS SDK's 10-type Tier 1 PII vocabulary -- `passport`, `driversLicense` and `bankAccount` were entirely undeclared and so passed through `PiiDetector.detect` unflagged and unmasked (SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS). All 10 types are now declared with live patterns, guarded by a parity test.
