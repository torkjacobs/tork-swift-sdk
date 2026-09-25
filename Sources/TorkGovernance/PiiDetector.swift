import Foundation

/// Represents a type of personally identifiable information.
///
/// Tier 1 vocabulary (10 types), matching tork-js-sdk/src/pii.ts's
/// `PIIType` exactly. Closes SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS:
/// this enum previously declared only 7 of the 10 -- passport,
/// driversLicense and bankAccount were entirely absent, so those PII
/// values passed through `PiiDetector.detect` unflagged and unmasked. See
/// the identical gap closed in tork-go-sdk/pii.go
/// (SDK-GO-PII-DETECTOR-DROPS-THREE-DECLARED-TYPES).
public enum PIIType: String, CaseIterable, Sendable {
    case ssn = "ssn"
    case creditCard = "credit_card"
    case email = "email"
    case phone = "phone"
    case ipAddress = "ip_address"
    case dateOfBirth = "date_of_birth"
    case address = "address"
    case passport = "passport"
    case driversLicense = "drivers_license"
    case bankAccount = "bank_account"
}

/// A detected PII match in text.
public struct PIIMatch: Sendable {
    public let type: PIIType
    public let value: String
    public let range: Range<String.Index>
}

/// Result of PII detection on text.
public struct PIIResult: Sendable {
    public let hasPII: Bool
    public let types: [PIIType]
    public let count: Int
    public let matches: [PIIMatch]
    public let redactedText: String
    /// Country-registry detections, kept separate from `matches` so `PIIType`
    /// stays the closed ten-value enum it has always been.
    public var countryMatches: [PiiCountry.CountryMatch] = []
    /// Redaction labels of those matches, e.g. `NATIONAL_ID`.
    public var countryLabels: [String] = []
    /// Country profiles the text activated, in registry order.
    public var regions: [String] = []
}

/// A pattern definition for PII detection.
struct PIIPattern {
    let type: PIIType
    let regex: NSRegularExpression
    let redaction: String
}

/// Detects PII in text using regex patterns.
public struct PiiDetector {

    static let defaultPatterns: [PIIPattern] = {
        var patterns: [PIIPattern] = []

        let defs: [(PIIType, String, String)] = [
            (.ssn, #"\b\d{3}-\d{2}-\d{4}\b"#, "[SSN_REDACTED]"),
            (.creditCard, #"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"#, "[CARD_REDACTED]"),
            (.email, #"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"#, "[EMAIL_REDACTED]"),
            (.phone, #"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"#, "[PHONE_REDACTED]"),
            (.ipAddress, #"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#, "[IP_REDACTED]"),
            (.dateOfBirth, #"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b"#, "[DOB_REDACTED]"),
            (.address, #"(?i)\b\d{1,5}\s+\w+(?:\s+\w+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b"#, "[ADDRESS_REDACTED]"),
            // The three patterns below close SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS:
            // ported verbatim from tork-js-sdk/src/pii.ts, appended in the
            // same order JS declares them so the chained detect-then-replace
            // semantics below (each pattern redacts over the previous
            // pattern's already-redacted text) match byte for byte.
            (.passport, #"\b[A-Z]{1,2}\d{6,9}\b"#, "[PASSPORT_REDACTED]"),
            (.driversLicense, #"\b[A-Z]\d{7,14}\b"#, "[DL_REDACTED]"),
            (.bankAccount, #"\b\d{8,17}\b"#, "[ACCOUNT_REDACTED]"),
        ]

        for (type, pattern, redaction) in defs {
            if let regex = try? NSRegularExpression(pattern: pattern) {
                patterns.append(PIIPattern(type: type, regex: regex, redaction: redaction))
            }
        }

        return patterns
    }()

    /// Detect PII in the given text.
    ///
    /// Country profiles are activated from the content itself. Use
    /// `detect(_:regions:)` to force a set of profiles on.
    public static func detect(_ text: String) -> PIIResult {
        detect(text, regions: nil)
    }

    /// Detect PII, optionally forcing a set of country profiles on instead of
    /// inferring them from the content. Region codes are case-insensitive.
    ///
    /// REDACTION IS ONE PASS. Until 0.2.0 each pattern was redacted with its own
    /// `stringByReplacingMatches` over text a previous pattern had already
    /// rewritten, while `matches` carried ranges into the ORIGINAL text. Two
    /// patterns matching overlapping spans could leave half an identifier
    /// standing beside a redaction token -- digits exposed in output the caller
    /// had been told was redacted. Every match is now collected against the
    /// original text, overlaps are resolved before anything is rewritten, and
    /// the surviving spans are spliced right to left in a single pass.
    public static func detect(_ text: String, regions regionOverride: [String]?) -> PIIResult {
        let ns = text as NSString
        let fullRange = NSRange(location: 0, length: ns.length)

        var matches: [PIIMatch] = []
        var typeSet = Set<PIIType>()

        // L0: collect every match against the ORIGINAL text.
        struct L0Hit {
            let match: PIIMatch
            let start: Int
            let end: Int
            let redaction: String
        }
        var l0: [L0Hit] = []
        for pattern in defaultPatterns {
            for result in pattern.regex.matches(in: text, range: fullRange) {
                guard result.range.length > 0,
                      let range = Range(result.range, in: text) else { continue }
                l0.append(L0Hit(
                    match: PIIMatch(type: pattern.type, value: "[REDACTED]", range: range),
                    start: result.range.location,
                    end: result.range.location + result.range.length,
                    redaction: pattern.redaction
                ))
            }
        }

        // Country layer.
        let activeRegions: [String]
        if let override = regionOverride, !override.isEmpty {
            activeRegions = override.map { $0.uppercased() }
        } else {
            activeRegions = PiiCountry.inferRegions(text)
        }
        let countryMatches = PiiCountry.detect(
            text, patterns: PiiCountry.patternsForRegions(activeRegions))

        // Resolve overlaps before anything is rewritten. A country identifier
        // supersedes any L0 span it fully contains -- the cloud does the same,
        // which is how a Saudi national ID stops coming back as
        // [PHONE_REDACTED].
        var claimed: [(Int, Int)] = []
        var spans: [PiiCountry.RedactionSpan] = []
        for c in countryMatches {
            claimed.append((c.startIndex, c.endIndex))
            spans.append(PiiCountry.RedactionSpan(
                startIndex: c.startIndex, endIndex: c.endIndex, redaction: c.redaction))
        }

        for hit in l0 {
            let overlapping = claimed.filter { hit.start < $0.1 && hit.end > $0.0 }
            if !overlapping.isEmpty {
                let swallowsAll = overlapping.allSatisfy { r in
                    let (cs, ce) = PiiCountry.trimmedCore(ns, r.0, r.1)
                    return hit.start <= cs && hit.end >= ce
                }
                if !swallowsAll { continue }
                // An L0 span that fully contains a country span still loses:
                // the country label is the more specific claim.
                let hitsCountry = overlapping.contains { o in
                    countryMatches.contains { $0.startIndex == o.0 && $0.endIndex == o.1 }
                }
                if hitsCountry { continue }
                for o in overlapping {
                    claimed.removeAll { $0 == o }
                    spans.removeAll { $0.startIndex == o.0 && $0.endIndex == o.1 }
                }
            }
            claimed.append((hit.start, hit.end))
            spans.append(PiiCountry.RedactionSpan(
                startIndex: hit.start, endIndex: hit.end, redaction: hit.redaction))
            matches.append(hit.match)
            typeSet.insert(hit.match.type)
        }

        var countryLabels: [String] = []
        for c in countryMatches where !countryLabels.contains(c.label) {
            countryLabels.append(c.label)
        }

        return PIIResult(
            hasPII: !matches.isEmpty || !countryMatches.isEmpty,
            types: Array(typeSet),
            count: matches.count + countryMatches.count,
            matches: matches,
            redactedText: PiiCountry.applyRedactions(text, spans),
            countryMatches: countryMatches,
            countryLabels: countryLabels,
            regions: activeRegions
        )
    }

    /// Quick check if text contains any PII.
    public static func containsPII(_ text: String) -> Bool {
        detect(text).hasPII
    }

    /// Redact all PII in text and return the cleaned string.
    public static func redact(_ text: String) -> String {
        detect(text).redactedText
    }
}
