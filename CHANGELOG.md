# Changelog

## 0.4.0 - 2026-10-03

### Added
- **Agent telemetry request fields** on the governance call: optional
  `agent_id`, `agent_role`, `session_id` and `session_turn` (integer), carried
  by `SessionContext` (`agentId`, `agentRole`, `sessionId`, `sessionTurn`) via
  `govern(_:sessionContext:)` or `GovernOptions`. Passed through to the receipt
  when set, omitted when not. `SessionContext` is now `Codable` (snake_case wire
  names, unset fields omitted rather than `null`) and exposes `requestFields`.
- Per-type PII tests: every declared `PIIType` has a positive and a negative
  example (`testEveryDeclaredTypeHasPositiveAndNegativeExample`).

### PII types (SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS)
All 10 declared types have a working pattern; none removed: `ssn`,
`credit_card`, `email`, `phone`, `ip_address`, `date_of_birth`, `address`,
`passport`, `drivers_license`, `bank_account`. The parity test already fails on
a declared type without a pattern.

## 0.3.0 - 2026-09-25

### Added
- **PII registry bundle 1.2.0 (24 countries, incl. AU TFN/ABN/Medicare).**
- **The country layer: 24 country profiles, 54 patterns (3 alwaysOn), 20 check
  digits.** Patterns, keywords, redaction labels and checksum gates are
  generated from Tork's own country registry and consumed verbatim from the
  SDK bundle (`Registry-Version: 1.2.0`, content `cfd4f61ebaf45e74`).
  Countries: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR, CA, ZA, GH, IT, KE,
  MU, MX, MY, PK, SG, TH, ID. Three patterns -- `au_tfn`, `au_abn`,
  `au_medicare` -- are `alwaysOn`: they run on every document under rule 1a,
  before country activation, so they still detect an Australian TFN, ABN or
  Medicare number with no other Australian signal present. `PiiCountry` was
  updated to actually dispatch `alwaysOn` patterns unconditionally (bundle
  1.1.0's port never read the flag); see `testAUTFNIsDetectedWithItsKeywordEvenWithNoOtherAustralianSignal`
  and its siblings. `au_tfn`'s and `au_abn`'s checksums are required, but only
  `au_tfn` falls back to the generic near-miss redaction on failure --
  `au_abn`'s `nearMissFallback` is false, so a checksum-failing ABN is left
  unredacted rather than mistyped. `au_medicare`'s checksum is advisory
  (community-sourced, unconfirmed) and never rejects a match.
- New public API in `Sources/TorkGovernance/Pii`: `torkPiiPatterns` (the
  bundle's 54 patterns), `torkPiiSignals` and `torkPiiCountryPatterns` (the 51
  activation signals and the country map), `PiiChecksums` (20 algorithms) and
  `PiiCountry` (the matcher). All pure and local: no network, no clock.
- `PIIResult` gains `countryMatches`, `countryLabels` and `regions`, all
  defaulting to empty so the existing memberwise construction still compiles.
  `PiiDetector.detect(_:regions:)` forces a set of country profiles on; the
  single-argument `detect(_:)` is unchanged.
- **Nine check digits ported by hand.** The bundle names twenty algorithms and
  specifies the eleven that reduce to a weight vector and a modulus; the other
  nine (`br_cpf`, `br_cnpj`, `cn_resident_id`, `de_steuer_id`, `fr_nir`,
  `it_codice_fiscale`, `jp_my_number`, `kr_rrn`, `sg_nric`) are ported from the
  cloud's `lib/pii/checksums.ts`, each tested against the issuing authority's
  own worked example where one is published.

### Fixed
- **SDK-SWIFT-PARTIAL-REDACTION.** Until 0.2.0 each pattern was redacted with
  its own `stringByReplacingMatches` over text a previous pattern had already
  rewritten, while `matches` carried ranges into the *original* text. Two
  patterns matching overlapping spans could leave half an identifier standing
  beside a redaction token -- digits exposed in output the caller had been told
  was redacted. Every match is now collected against the original text,
  overlaps are resolved before anything is rewritten, and the surviving spans
  are spliced right to left in one pass.
  `testNothingIsEverPartiallyRedacted` asserts the invariant across all 268
  vectors.

### Notes
- The XCTest suite runs in this environment (Xcode 27, Swift 6.4); 0.2.0's
  release note recorded the tests as verified through a `swiftc` stand-in with
  the XCTest run pending. 42 tests pass, 13 of them new.
- `CountryMatch.startIndex` and `.endIndex` are **UTF-16 offsets**, because
  `NSRegularExpression` works in UTF-16 code units. That is self-consistent
  within this SDK, and the redacted *string* is what the cross-SDK parity
  fixtures compare.
- **The bundle now states the whole contract, and this SDK implements it.**
  Bundle 1.0.0's README documented three rules; measured against the cloud's
  golden snapshot they disagreed with it on 14 of 86 country-corpus cases, so
  this SDK carried two more of its own. Bundle **1.1.0 documents seven**, marks
  each SDK or cloud-only, and ships the data all seven need in every language
  file -- the activation signals, the country map, the asymmetric 60/40 window,
  the symmetric 60 context window, the whole-word vocabulary, the near-miss
  policy, the table constants and the reference labels. So the locally generated
  activation layer is **deleted**, no window is hard-coded any more, and rules 6
  (near miss), 7 (column header) and 7b (nearest label) are implemented here for
  the first time. Every rule now reads its data off the placed bundle.
- Advisory checksums never reject a match: `ca_sin`, `emirates_id`,
  `de_tax_id`, `kr_rrn`, `sa_national_id`. Korea stopped issuing check digits on
  20 Oct 2020.
- Not ported, and still cloud-only: the slot, context,
  gravity and name layers, industry profiles, and org configuration.
- **Indonesia is the country 1.1.0 added, and it is the one that proves the
  whole-word rule.** `id_nik`'s only short spellings -- NIK, KTP, NPWP -- are
  `wholeWordKeywords`, not ordinary keywords, because `nik` sits inside
  *teknik*, *elektronik*, *klinik* and *pabrik*. Matching them by substring
  would open the gate on an Indonesian sales ledger; matching them on a word
  boundary catches "NIK 3171010101900001" and leaves *teknik* alone. An SDK that
  merged the two lists would be shipping a false-positive bug, so the boundary
  test is implemented rather than the shortcut, and four unit cases assert both
  halves.
- **FLAGGED, upstream: bundle 1.1.0 cannot detect Australia's TFN, ABN or
  Medicare number.** `checksums.json` declares `au_tfn` and `au_abn` as
  `requiredBy` and `au_medicare` as `advisoryFor` patterns of those names, and
  `patterns` ships none of them -- the AU profile carries only `au_acn` and
  `au_phone_intl`. The AU activation signals are still keyed on "tfn", "tax
  file" and "medicare", so the bundle switches Australia on for identifiers it
  then has no pattern to catch. The cloud detects all three. This is a recall
  gap no SDK can close from the bundle, and the six parity cases it costs are
  recorded in the fixture as `BUNDLE GAP` rather than silently accepted.

## 0.2.0 - 2026-09-03

### Added
- feat: tool-result scanning (`scanToolResult`, `Tork.scanToolResult`) for PII and prompt-injection heuristics on MCP/external tool results, ported from tork-js-sdk's tool-result-scan.ts (DECIDED-TACT2-V2-C). Tier 1 parity: 10-type PII vocabulary, `tork-injection-heuristics-v1` heuristic ruleset, `toolResultScan` receipt block.

### Fixed
- fix: `PIIType` declared only 7 of the JS SDK's 10-type Tier 1 PII vocabulary -- `passport`, `driversLicense` and `bankAccount` were entirely undeclared and so passed through `PiiDetector.detect` unflagged and unmasked (SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS). All 10 types are now declared with live patterns, guarded by a parity test.
