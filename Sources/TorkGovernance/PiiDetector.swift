import Foundation

/// Represents a type of personally identifiable information.
public enum PIIType: String, CaseIterable, Sendable {
    case ssn = "ssn"
    case creditCard = "credit_card"
    case email = "email"
    case phone = "phone"
    case ipAddress = "ip_address"
    case dateOfBirth = "date_of_birth"
    case address = "address"
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
        ]

        for (type, pattern, redaction) in defs {
            if let regex = try? NSRegularExpression(pattern: pattern) {
                patterns.append(PIIPattern(type: type, regex: regex, redaction: redaction))
            }
        }

        return patterns
    }()

    /// Detect PII in the given text.
    public static func detect(_ text: String) -> PIIResult {
        let nsText = text as NSString
        let fullRange = NSRange(location: 0, length: nsText.length)

        var allMatches: [PIIMatch] = []
        var typeSet = Set<PIIType>()
        var redacted = text

        for pattern in defaultPatterns {
            let results = pattern.regex.matches(in: text, range: fullRange)
            for result in results {
                guard let range = Range(result.range, in: text) else { continue }
                allMatches.append(PIIMatch(type: pattern.type, value: "[REDACTED]", range: range))
                typeSet.insert(pattern.type)
            }
            redacted = pattern.regex.stringByReplacingMatches(
                in: redacted,
                range: NSRange(location: 0, length: (redacted as NSString).length),
                withTemplate: pattern.redaction
            )
        }

        return PIIResult(
            hasPII: !allMatches.isEmpty,
            types: Array(typeSet),
            count: allMatches.count,
            matches: allMatches,
            redactedText: redacted
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
