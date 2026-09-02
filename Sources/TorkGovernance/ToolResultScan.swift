import Foundation

// Tool-result scanning (DECIDED-TACT2-V2-C), ported from
// tork-js-sdk/src/tool-result-scan.ts.
//
// A tool result returned by an MCP server -- or by any external system the
// caller does not control -- is untrusted input that is about to be appended
// to a model's context. `scanToolResult` scans it BEFORE that happens,
// on-device, for two things:
//
//   1. PII, using the SAME on-device detector as `Tork.govern` (`PiiDetector`).
//      Nothing new was written for this: same patterns, same redaction
//      labels, same zero-network guarantee.
//   2. Prompt injection, using the conservative heuristic pattern set in
//      InjectionHeuristics.swift. Every injection finding is labelled
//      `heuristic:<type>` so no caller can mistake a regex hit for a
//      verified determination.
//
// ZERO NETWORK. Every function here is pure and synchronous: no URLSession,
// no I/O, no clock read beyond the processing-time measurement
// `Tork.scanToolResult` takes for its receipt. The payload never leaves the
// machine.
//
// WHAT THIS IS NOT: this is a client-side control that the CALLER runs and
// the caller attests to. It is not gateway-side enforcement -- a compromised
// or simply careless caller can skip it entirely, and Tork cannot tell.
// Enforcement at the gateway, where skipping is not an option, is a separate
// and later control.
//
// PARITY TIER: this port matches Tier 1 of the JS SDK -- the 10-type basic
// PII vocabulary (ssn, credit_card, email, phone, address, ip_address,
// date_of_birth, passport, drivers_license, bank_account) with JS-identical
// labels and redaction markers. It does NOT carry the Python SDK's
// regional/industry pattern tier (AU/US/GB/EU/AE/... profiles).

// ============================================================================
// Types
// ============================================================================

/// `pii` -- a detector match. `injection` -- a heuristic pattern match.
public enum ToolResultFindingKind: String, Sendable, Hashable {
    case pii
    case injection
}

/// One (kind, type, location) match tally.
public struct ToolResultFinding: Sendable, Hashable {
    /// `pii` for a detector match, `injection` for a heuristic pattern match.
    public let kind: ToolResultFindingKind
    /// For `.pii`, a `PIIType` raw value (`ssn`, `email`, ...). For
    /// `.injection`, always `heuristic:<name>` -- the prefix is part of the
    /// value, not decoration, so a downstream reader of a receipt cannot
    /// mistake a pattern hit for a verified determination.
    public let type: String
    /// Number of matches of this (kind, type) at this location.
    public let count: Int
    /// JSON path of the string the matches were found in, e.g. `$.content[0].text`.
    public let location: String
}

/// Input to `scanToolResult`.
public struct ToolResultScanInput {
    /// Name of the tool that produced this result. Recorded on the receipt.
    public let toolName: String
    /// URI of the MCP server (or other origin). Recorded on the receipt when present.
    public let serverUri: String?
    /// The tool result itself: any value reachable via `String`, `NSNumber`/
    /// `Bool`, `NSNull`, `[String: Any]` and `[Any]` -- the shape
    /// `JSONSerialization.jsonObject(with:)` produces. Never leaves the machine.
    public let payload: Any

    public init(toolName: String, serverUri: String? = nil, payload: Any) {
        self.toolName = toolName
        self.serverUri = serverUri
        self.payload = payload
    }
}

/// Optional parameters to `scanToolResult`.
public struct ToolResultScanOptions {
    /// Block the result when the injection heuristics fire. Default false:
    /// detect and report, let the caller decide. When true and an injection
    /// pattern matches, `blocked` is true, `reason` is set, and `sanitized`
    /// is `nil` -- there is deliberately no masked payload to accidentally
    /// append.
    public var blockOnInjection: Bool
    /// Extra redaction patterns, same semantics as the JS SDK's
    /// `TorkConfig.customPatterns`. NOTE (inherited from `PiiDetector`):
    /// custom patterns redact but are not counted, so they can change
    /// `sanitized` without producing a finding.
    public var customPatterns: [String: NSRegularExpression]?
    /// Maximum nesting depth to walk. Deeper values are passed through
    /// unscanned and unmodified. `nil` means "use the default" (32).
    /// Unlike a bare `Int` default parameter, `Optional<Int>` lets `0` mean
    /// "scan only the root value" -- distinct from "unset" -- matching the
    /// JS SDK's `options.maxDepth ?? DEFAULT_MAX_DEPTH` (`??` only replaces
    /// `null`/`undefined`, never a literal `0`).
    public var maxDepth: Int?

    public init(blockOnInjection: Bool = false, customPatterns: [String: NSRegularExpression]? = nil, maxDepth: Int? = nil) {
        self.blockOnInjection = blockOnInjection
        self.customPatterns = customPatterns
        self.maxDepth = maxDepth
    }
}

/// Result of `scanToolResult`.
public struct ToolResultScanResult {
    /// The payload with PII masked in place, structurally identical
    /// otherwise. `nil` when `blocked` is true. Sub-trees containing no PII
    /// keep their original identity where the underlying container is a
    /// reference type (e.g. `NSDictionary`/`NSArray`, as produced by
    /// `JSONSerialization`) -- for native Swift `[String: Any]`/`[Any]`
    /// value-type containers there is no reference identity to preserve, but
    /// an untouched subtree is still returned as the exact same value
    /// (Swift's copy-on-write means no copy is made either way).
    public let sanitized: Any?
    public let findings: [ToolResultFinding]
    public let blocked: Bool
    /// Present only when `blocked` is true.
    public let reason: String?
}

// ============================================================================
// Traversal
// ============================================================================

private let defaultToolResultScanMaxDepth = 32

private let toolResultLocationIdentifier = try! NSRegularExpression(pattern: "^[A-Za-z_$][A-Za-z0-9_$]*$")

private func isIdentifier(_ key: String) -> Bool {
    let range = NSRange(location: 0, length: (key as NSString).length)
    return toolResultLocationIdentifier.firstMatch(in: key, range: range) != nil
}

/// JSON.stringify-equivalent quoting for a non-identifier key, so the
/// location grammar (`$.a[0].b` / `$["weird key"]`) matches the JS source
/// byte for byte for the same key.
private func jsonQuoted(_ key: String) -> String {
    if let data = try? JSONSerialization.data(withJSONObject: [key], options: [.fragmentsAllowed]),
       let arrayForm = String(data: data, encoding: .utf8) {
        return String(arrayForm.dropFirst().dropLast())
    }
    let escaped = key.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    return "\"\(escaped)\""
}

private func toolResultChildPath(_ parent: String, _ key: String) -> String {
    isIdentifier(key) ? "\(parent).\(key)" : "\(parent)[\(jsonQuoted(key))]"
}

/// Identity of a container, for the cycle guard -- `nil` for native Swift
/// `[String: Any]`/`[Any]` value types (where a self-reference is
/// structurally impossible), non-`nil` for reference-type containers
/// (`NSMutableDictionary`/`NSMutableArray` and friends) that a caller could
/// have wired into a genuine cycle.
private func containerIdentity(of value: Any) -> ObjectIdentifier? {
    guard type(of: value) is AnyClass else { return nil }
    return ObjectIdentifier(value as AnyObject)
}

/// Scan one string: PII (via the shared detector) then injection heuristics.
/// Returns the masked string plus any findings, both keyed to `location`.
private func scanToolResultString(
    _ text: String,
    location: String,
    customPatterns: [String: NSRegularExpression]?,
    findings: inout [ToolResultFinding]
) -> String {
    let pii = PiiDetector.detect(text)

    if pii.count > 0 {
        // Counts per type, emitted in a stable (sorted) order so two runs
        // over the same payload produce identical findings.
        var perType: [PIIType: Int] = [:]
        for match in pii.matches {
            perType[match.type, default: 0] += 1
        }
        for type in perType.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            findings.append(ToolResultFinding(kind: .pii, type: type.rawValue, count: perType[type] ?? 0, location: location))
        }
    }

    var perInjection: [String: Int] = [:]
    let nsText = text as NSString
    let fullRange = NSRange(location: 0, length: nsText.length)
    for pattern in injectionPatterns {
        let count = pattern.regex.numberOfMatches(in: text, range: fullRange)
        if count > 0 {
            perInjection[pattern.type, default: 0] += count
        }
    }
    for type in perInjection.keys.sorted() {
        findings.append(ToolResultFinding(
            kind: .injection,
            type: injectionHeuristicPrefix + type,
            count: perInjection[type] ?? 0,
            location: location
        ))
    }

    var redacted = pii.redactedText

    // Extra caller-supplied patterns, applied AFTER default detection and
    // redaction, for redaction only -- they never produce a finding. Applied
    // in sorted-name order for determinism: Swift's `Dictionary` (unlike a
    // JS object) has no defined iteration order, so this is a documented
    // traversal-order difference from the JS source (which iterates
    // `Object.entries` insertion order), the same divergence the Go port
    // documents for the identical reason. It only matters when two custom
    // patterns overlap the same span, an edge case.
    if let customPatterns = customPatterns {
        for name in customPatterns.keys.sorted() {
            guard let regex = customPatterns[name] else { continue }
            let nsRedacted = redacted as NSString
            redacted = regex.stringByReplacingMatches(
                in: redacted,
                range: NSRange(location: 0, length: nsRedacted.length),
                withTemplate: "[\(name.uppercased())_REDACTED]"
            )
        }
    }

    return redacted
}

/// Walk the payload, scanning every string. Returns a structure with PII
/// masked in place, and whether anything changed.
///
/// Only strings are scanned. Numbers, booleans, `NSNull`, and anything else
/// that is not a `String`, `[String: Any]` or `[Any]` pass through untouched
/// -- a bank account stored as a JSON number is NOT detected, matching the
/// JS behaviour. Cycles are left as-is and not re-entered.
private func walkToolResult(
    _ value: Any,
    location: String,
    depth: Int,
    maxDepth: Int,
    customPatterns: [String: NSRegularExpression]?,
    findings: inout [ToolResultFinding],
    seen: inout Set<ObjectIdentifier>
) -> (value: Any, changed: Bool) {
    if let text = value as? String {
        let masked = scanToolResultString(text, location: location, customPatterns: customPatterns, findings: &findings)
        return (masked, masked != text)
    }

    if depth >= maxDepth {
        return (value, false)
    }

    if let array = value as? [Any] {
        if let id = containerIdentity(of: value) {
            if seen.contains(id) { return (value, false) }
            seen.insert(id)
        }
        var changed = false
        var out: [Any] = []
        out.reserveCapacity(array.count)
        for (index, item) in array.enumerated() {
            let (next, itemChanged) = walkToolResult(
                item, location: "\(location)[\(index)]", depth: depth + 1, maxDepth: maxDepth,
                customPatterns: customPatterns, findings: &findings, seen: &seen
            )
            if itemChanged { changed = true }
            out.append(next)
        }
        return changed ? (out, true) : (value, false)
    }

    if let dict = value as? [String: Any] {
        if let id = containerIdentity(of: value) {
            if seen.contains(id) { return (value, false) }
            seen.insert(id)
        }
        var changed = false
        var out: [String: Any] = [:]
        for key in dict.keys.sorted() {
            guard let item = dict[key] else { continue }
            let (next, itemChanged) = walkToolResult(
                item, location: toolResultChildPath(location, key), depth: depth + 1, maxDepth: maxDepth,
                customPatterns: customPatterns, findings: &findings, seen: &seen
            )
            if itemChanged { changed = true }
            out[key] = next
        }
        return changed ? (out, true) : (value, false)
    }

    return (value, false)
}

// ============================================================================
// Public API
// ============================================================================

/// Scan a tool result for PII and prompt injection before it is appended to
/// model context. Pure, synchronous, on-device: makes no network call and
/// mutates nothing reachable from `input.payload`.
///
/// For the receipt-linked form (`attested_by: "client"`, `capture_mode: "edge"`),
/// use `Tork.scanToolResult`, which wraps this and records the scan.
public func scanToolResult(_ input: ToolResultScanInput, options: ToolResultScanOptions = ToolResultScanOptions()) -> ToolResultScanResult {
    let maxDepth = options.maxDepth ?? defaultToolResultScanMaxDepth

    var findings: [ToolResultFinding] = []
    var seen = Set<ObjectIdentifier>()
    let (sanitized, _) = walkToolResult(
        input.payload, location: "$", depth: 0, maxDepth: maxDepth,
        customPatterns: options.customPatterns, findings: &findings, seen: &seen
    )

    let injectionCount = findings.reduce(0) { $0 + ($1.kind == .injection ? $1.count : 0) }
    let blocked = options.blockOnInjection && injectionCount > 0

    if blocked {
        let types = Array(Set(findings.filter { $0.kind == .injection }.map { $0.type })).sorted()
        let reason = "Blocked: \(injectionCount) prompt-injection heuristic match(es) [\(types.joined(separator: ", "))] " +
            "in the result of tool \"\(input.toolName)\". These are heuristic pattern matches (\(injectionRuleset)), " +
            "not a verified determination. sanitized is nil so no masked copy can be appended to context by accident."
        return ToolResultScanResult(sanitized: nil, findings: findings, blocked: true, reason: reason)
    }

    return ToolResultScanResult(sanitized: sanitized, findings: findings, blocked: false, reason: nil)
}

// ============================================================================
// Receipt block
// ============================================================================

/// Counts by type for one kind (pii or injection). Injection type keys keep
/// their `heuristic:` prefix.
public struct ToolResultScanFindingCounts: Codable, Sendable, Equatable {
    public var injection: [String: Int]
    public var pii: [String: Int]
}

/// Total match count per kind.
public struct ToolResultScanTotals: Codable, Sendable, Equatable {
    public var injection: Int
    public var pii: Int
}

/// The `tool_result_scan` block recorded on the receipt.
///
/// snake_case wire form via `CodingKeys`; optional keys (`reason`,
/// `serverUri`) are OMITTED entirely rather than encoded null, which is
/// `Codable`'s default behaviour for `nil` `Optional` properties -- the same
/// discipline as the JS SDK's TORK-DNA-v2 canonical form, and for the same
/// reason: every SDK that mirrors this must produce a byte-identical block
/// for the same scan. Encode with `JSONEncoder.outputFormatting = [.sortedKeys]`
/// to get the alphabetical key order the JS/Go SDKs guarantee by construction.
///
/// It carries COUNTS ONLY. No payload, no matched substring, no location
/// path, no tool argument ever appears here.
public struct ToolResultScanReceiptBlock: Codable, Sendable, Equatable {
    /// Always `"client"`. This scan ran in the caller's process; Tork did not execute it.
    public var attestedBy: String
    public var blocked: Bool
    /// Always `"edge"` -- the capture_mode this SDK's client-side work is recorded under.
    public var captureMode: String
    public var findings: ToolResultScanFindingCounts
    /// Identifier of the injection ruleset that produced the injection counts.
    public var injectionRuleset: String
    /// Present only when blocked.
    public var reason: String?
    public var sdkLanguage: String
    public var sdkVersion: String
    /// Present only when the caller supplied one.
    public var serverUri: String?
    public var toolName: String
    public var totals: ToolResultScanTotals

    enum CodingKeys: String, CodingKey {
        case attestedBy = "attested_by"
        case blocked
        case captureMode = "capture_mode"
        case findings
        case injectionRuleset = "injection_ruleset"
        case reason
        case sdkLanguage = "sdk_language"
        case sdkVersion = "sdk_version"
        case serverUri = "server_uri"
        case toolName = "tool_name"
        case totals
    }
}

private func toolResultCountsByType(_ findings: [ToolResultFinding], kind: ToolResultFindingKind) -> [String: Int] {
    var totals: [String: Int] = [:]
    for finding in findings where finding.kind == kind {
        totals[finding.type, default: 0] += finding.count
    }
    return totals
}

private func sumCounts(_ counts: [String: Int]) -> Int {
    counts.values.reduce(0, +)
}

/// Parameters to `buildToolResultScanBlock`.
public struct BuildToolResultScanBlockParams {
    public let toolName: String
    public let serverUri: String?
    public let result: ToolResultScanResult
    public let sdkVersion: String

    public init(toolName: String, serverUri: String? = nil, result: ToolResultScanResult, sdkVersion: String) {
        self.toolName = toolName
        self.serverUri = serverUri
        self.result = result
        self.sdkVersion = sdkVersion
    }
}

/// Build the receipt block for a completed scan.
public func buildToolResultScanBlock(_ params: BuildToolResultScanBlockParams) -> ToolResultScanReceiptBlock {
    let pii = toolResultCountsByType(params.result.findings, kind: .pii)
    let injection = toolResultCountsByType(params.result.findings, kind: .injection)

    return ToolResultScanReceiptBlock(
        attestedBy: "client",
        blocked: params.result.blocked,
        captureMode: "edge",
        findings: ToolResultScanFindingCounts(injection: injection, pii: pii),
        injectionRuleset: injectionRuleset,
        reason: params.result.reason,
        sdkLanguage: "swift",
        sdkVersion: params.sdkVersion,
        serverUri: params.serverUri,
        toolName: params.toolName,
        totals: ToolResultScanTotals(injection: sumCounts(injection), pii: sumCounts(pii))
    )
}

/// Distinct PII types in a scan result, for the attestation canonical form.
public func scanPIITypes(_ findings: [ToolResultFinding]) -> [String] {
    Array(Set(findings.filter { $0.kind == .pii }.map { $0.type })).sorted()
}

/// Total PII match count in a scan result.
public func scanPIICount(_ findings: [ToolResultFinding]) -> Int {
    findings.filter { $0.kind == .pii }.reduce(0) { $0 + $1.count }
}

/// Total injection match count in a scan result.
public func scanInjectionCount(_ findings: [ToolResultFinding]) -> Int {
    findings.filter { $0.kind == .injection }.reduce(0) { $0 + $1.count }
}

/// Hashes a JSON-shaped value the same way `Tork.govern` hashes its
/// input/output strings: `ReceiptUtils.hashText` over a canonical text form.
/// `.sortedKeys` makes this deterministic for the same logical value
/// regardless of the source dictionary's iteration order.
///
/// NOTE (Swift-specific, not part of the byte-identical tool_result_scan
/// block contract): `Tork.scanToolResult`'s `receipt.inputHash`/`outputHash`
/// are not part of this port's reference material (only tool-result-scan.ts,
/// pii.ts and their tests were in scope). Hashing a JSON encoding of the
/// payload/sanitized value is this SDK's own choice for those two
/// Receipt-level fields, consistent with how `Tork.govern` already hashes
/// text -- it does not affect the `tool_result_scan` block itself, which
/// carries counts only. The Go port makes the same choice for the same reason.
func hashJSONForReceipt(_ value: Any?) -> String {
    guard let value = value else { return ReceiptUtils.hashText("") }
    if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed]),
       let text = String(data: data, encoding: .utf8) {
        return ReceiptUtils.hashText(text)
    }
    return ReceiptUtils.hashText("")
}
