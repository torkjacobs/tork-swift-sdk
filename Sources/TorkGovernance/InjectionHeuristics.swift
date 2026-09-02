import Foundation

// Prompt-injection heuristics for tool-result scanning (DECIDED-TACT2-V2-C).
//
// Ported verbatim from tork-js-sdk/src/tool-result-scan.ts (INJECTION_PATTERNS).
// The regex SOURCE STRINGS are byte-identical to the JS patterns modulo
// syntax that differs only in how a regex literal is written, never in what
// it matches:
//
//   - JS /pattern/gi becomes an NSRegularExpression with the source string
//     unchanged and `.caseInsensitive` passed as an option -- NSRegularExpression
//     (built on ICU regex, like Swift's native Regex) has no inline flag
//     suffix, so case-insensitivity is an explicit option instead.
//   - JS /pattern/gim becomes `.caseInsensitive` + `.anchorsMatchLines` (ICU's
//     equivalent of JS's `m` flag: `^`/`$` match at line boundaries).
//   - JS's "global" (find every match) is just how `matches(in:range:)` /
//     `numberOfMatches(in:range:)` already behave -- no flag needed.
//   - JS's escaped forward slashes (`https:\/\/`) are unescaped here, since
//     Swift's `#"..."#` raw string literals have no delimiter conflict with
//     `/` the way JS regex literals do.
//
// ICU (which NSRegularExpression and Swift's Regex both use) supports
// lookaround, unlike Go's RE2 -- but none of these patterns use lookahead or
// lookbehind, so none needed a lookaround substitution or ICU-specific
// escaping change. Every pattern below compiles and matches identically to
// its JS source.

/// Prefix on every injection finding's `type`. Not cosmetic: these patterns
/// are regexes over untrusted text, they carry false positives and false
/// negatives, and the label travels with the finding into the receipt.
public let injectionHeuristicPrefix = "heuristic:"

/// Identifies this exact pattern set in receipts. Bump when the patterns
/// change, so a receipt says which ruleset produced its counts. Every SDK
/// mirroring this implementation must emit the SAME value for the same
/// ruleset -- it is a shared identifier, not a per-language one.
public let injectionRuleset = "tork-injection-heuristics-v1"

struct InjectionPattern {
    let type: String
    let regex: NSRegularExpression
}

private func makeInjectionPattern(_ type: String, _ pattern: String, multiline: Bool = false) -> InjectionPattern {
    var options: NSRegularExpression.Options = [.caseInsensitive]
    if multiline {
        options.insert(.anchorsMatchLines)
    }
    guard let regex = try? NSRegularExpression(pattern: pattern, options: options) else {
        fatalError("invalid injection heuristic pattern: \(pattern)")
    }
    return InjectionPattern(type: type, regex: regex)
}

/// Conservative on purpose. Each pattern targets a phrase that has no
/// plausible reason to appear in a legitimate tool result -- a database row, a
/// search hit, a file listing. Broader "suspicious language" matching would
/// fire on ordinary documentation and support tickets, and an alert nobody
/// believes is worse than no alert.
let injectionPatterns: [InjectionPattern] = [
    // -- instruction override --------------------------------------------
    makeInjectionPattern(
        "instruction_override",
        #"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|preceding|all|any)\b[^.\n]{0,30}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b"#
    ),
    makeInjectionPattern(
        "instruction_override",
        #"\b(?:the\s+)?(?:instructions?|prompts?|rules?)\s+(?:above|below|before\s+this)\s+(?:are|is)\s+(?:now\s+)?(?:void|invalid|obsolete|outdated|no\s+longer\s+(?:valid|active|in\s+effect))\b"#
    ),
    makeInjectionPattern(
        "instruction_override",
        #"\bdisregard\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\b"#
    ),

    // -- role reassignment ------------------------------------------------
    makeInjectionPattern(
        "role_reassignment",
        #"\byou\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b"#
    ),
    makeInjectionPattern(
        "role_reassignment",
        #"\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+this\s+(?:conversation|session))\b[^.\n]{0,30}\byou\s+(?:are|will|must|should)\b"#
    ),
    makeInjectionPattern(
        "role_reassignment",
        #"\bnew\s+(?:system\s+)?(?:instructions?|prompt|persona|role)\s*:"#
    ),
    makeInjectionPattern(
        "role_reassignment",
        #"\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak|unrestricted)\s+mode\b"#
    ),
    makeInjectionPattern(
        "role_reassignment",
        #"\b(?:act|behave|respond|pretend\s+to\s+be)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken)\b"#
    ),
    // A role header smuggled into content -- "system:" / "<|im_start|>system"
    // at the start of a line is a conversation-structure forgery, not prose.
    makeInjectionPattern(
        "role_reassignment",
        #"^[ \t>*-]*(?:<\|im_start\|>\s*)?(?:system|assistant|developer)\s*(?::|\]|>)"#,
        multiline: true
    ),

    // -- exfiltration -----------------------------------------------------
    // A markdown image/link whose URL carries the content out as a query
    // parameter -- the classic zero-click exfiltration shape.
    makeInjectionPattern(
        "exfiltration_url",
        #"!?\[[^\]\n]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:data|payload|prompt|content|text|secret|token|key|conversation|history)=[^)\s]*\)"#
    ),
    makeInjectionPattern(
        "exfiltration_url",
        #"\bhttps?://\S*[?&](?:data|payload|secret|token|api[_-]?key|apikey|password|credential|conversation|history)="#
    ),
    makeInjectionPattern(
        "exfiltration_url",
        #"\b(?:send|post|upload|forward|transmit|exfiltrate|leak|report)\b[^.\n]{0,60}\bto\s+https?://\S+"#
    ),
]

/// Distinct injection types the ruleset can emit, for documentation/tests.
public let injectionTypes: [String] = Array(Set(injectionPatterns.map { $0.type })).sorted()
