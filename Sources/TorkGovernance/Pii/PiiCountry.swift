// The country layer: 24 country profiles, 51 patterns, 20 check digits.
//
// This implements the seven rules that generated/sdk-registry/README.md marks
// SDK, from the bundle alone. Bundle 1.1.0 carries the data all seven need --
// the activation signals, the country map, the three windows, the whole-word
// vocabulary, the near-miss policy, the table constants and the reference
// labels -- so nothing here is hand-written registry data and no window is
// hard-coded.
//
//   1. ACTIVATE   a country's patterns run only when one of its signals fires.
//   1a. ALWAYS ON a pattern whose `alwaysOn` is true (bundle 1.2.0: au_tfn,
//                 au_abn, au_medicare) runs on every document regardless of
//                 rule 1, before the activated country patterns, so an
//                 activated pattern can still supersede it under rule 5.
//   2. MATCH      the regex, case-sensitively, globally.
//   3. KEYWORD    whole-word (symmetric contextWindow) or column verdict or the
//                 ASYMMETRIC substring window (60 before, 40 after); then 7b
//                 may close the gate again.
//   4. CHECKSUM   when required. Advisory checksums never reject.
//   5. SUPERSEDE  a match containing every range it overlaps takes them.
//   6. NEAR MISS  a checksum-failing identifier is redacted generically.
//   7. COLUMN     in a delimited table a bare value cell is judged by its header.
//   7b. NEAREST LABEL  a closer commercial label closes the gate.
//
// Still cloud-only, by design: the universal (L0) patterns, the slot, context,
// gravity and name layers, industry profiles and org configuration.
//
// Offsets are UTF-16 offsets, because NSRegularExpression works in UTF-16 code
// units. That is self-consistent within this SDK, and the redacted STRING is
// what the cross-SDK parity fixtures compare.

import Foundation

public enum PiiCountry {
    /// Characters before a match that count as nearby for the substring gate.
    public static let keywordWindowBefore = torkPiiKeywordWindowBefore
    /// Characters after. Deliberately NOT the same number as before.
    public static let keywordWindowAfter = torkPiiKeywordWindowAfter
    /// The symmetric window: whole-word keywords and the near-miss gate.
    public static let contextWindow = torkPiiContextWindow

    /// The bundle this SDK shipped.
    public static let registryVersion = torkPiiRegistryVersion
    /// The bundle content hash, which answers "did the data change".
    public static let contentHash = torkPiiContentHash

    /// One country identifier found in the content.
    public struct CountryMatch: Sendable, Equatable {
        /// Registry pattern name, or `national_id_near_miss` for a rule 6 span.
        public let name: String
        /// ISO 3166-1 alpha-2, or `EU` for the bloc. Empty for a near miss.
        public let country: String
        /// The shared redaction label. The receipt block hashes labels.
        public let label: String
        public let type: String
        public let redaction: String
        public let startIndex: Int
        public let endIndex: Int
    }

    /// A span of the original text and the token that replaces it.
    public struct RedactionSpan: Sendable, Equatable {
        public let startIndex: Int
        public let endIndex: Int
        public let redaction: String

        public init(startIndex: Int, endIndex: Int, redaction: String) {
            self.startIndex = startIndex
            self.endIndex = endIndex
            self.redaction = redaction
        }
    }

    // ── compiled once ───────────────────────────────────────────────────────

    private static let compiled: [String: NSRegularExpression] = {
        var m: [String: NSRegularExpression] = [:]
        for p in torkPiiPatterns {
            m[p.name] = try! NSRegularExpression(pattern: p.regex)
        }
        return m
    }()

    private static let compiledSignals: [NSRegularExpression] = torkPiiSignals.map {
        try! NSRegularExpression(
            pattern: $0.regex,
            options: $0.flags.contains("i") ? [.caseInsensitive] : [])
    }

    private static let byName: [String: TorkPiiPattern] = {
        var m: [String: TorkPiiPattern] = [:]
        for p in torkPiiPatterns { m[p.name] = p }
        return m
    }()

    private static let countryPatterns: [String: [String]] = {
        var m: [String: [String]] = [:]
        for c in torkPiiCountries { m[c.code] = c.patterns }
        return m
    }()

    private static let signalOrder: [String] = {
        var order: [String] = []
        for s in torkPiiSignals where !order.contains(s.country) { order.append(s.country) }
        return order
    }()

    private static let genericSet = Set(torkPiiGenericIdKeywords)
    private static let nationalIdKeywords = torkPiiGenericIdKeywords + torkPiiLocalIdKeywords

    /// Rule 1a: patterns that run on every document, regardless of rule 1.
    private static let alwaysOnPatterns: [TorkPiiPattern] = torkPiiPatterns.filter { $0.alwaysOn }

    private static func isAlnum(_ u: unichar) -> Bool {
        (u >= 97 && u <= 122) || (u >= 48 && u <= 57) || (u >= 65 && u <= 90)
    }

    /// A pattern's whole vocabulary: the substring keywords and the whole-word ones.
    private static func allKeywordsOf(_ p: TorkPiiPattern) -> [String] {
        p.wholeWordKeywords.isEmpty ? p.keywords : p.keywords + p.wholeWordKeywords
    }

    /// The half of a vocabulary that names ONE country's identifier.
    private static func specificKeywords(_ keywords: [String]) -> [String] {
        keywords.filter { !genericSet.contains($0) }
    }

    private static func window(_ ns: NSString, _ lo: Int, _ hi: Int) -> String {
        let l = max(0, lo), h = min(ns.length, hi)
        guard h > l else { return "" }
        return ns.substring(with: NSRange(location: l, length: h - l)).lowercased()
    }

    /// Rule 3, substring half: ASYMMETRIC -- 60 before the match, 40 after it.
    private static func hasNearbyContext(_ ns: NSString, _ start: Int, _ end: Int, _ keywords: [String]) -> Bool {
        let before = window(ns, start - keywordWindowBefore, start)
        let after = window(ns, end, end + keywordWindowAfter)
        return keywords.contains { before.contains($0) || after.contains($0) }
    }

    /// Symmetric contextWindow either side, substring. Used by rule 6.
    private static func hasContextAround(_ ns: NSString, _ start: Int, _ end: Int, _ keywords: [String]) -> Bool {
        let w = window(ns, start - contextWindow, end + contextWindow)
        return keywords.contains { w.contains($0) }
    }

    /// Rule 3, whole-word half: symmetric contextWindow, a boundary each side,
    /// a boundary being "not a letter or digit".
    ///
    /// This is the gate Indonesia needs: `nik` sits inside *teknik*,
    /// *elektronik*, *klinik* and *pabrik*, so a substring test would open the
    /// gate on a sales ledger.
    public static func hasWholeWordContextAround(
        _ text: String, _ start: Int, _ end: Int, _ words: [String]
    ) -> Bool {
        guard !words.isEmpty else { return false }
        let ns = text as NSString
        let w = window(ns, start - contextWindow, end + contextWindow) as NSString
        for word in words {
            let needle = word as NSString
            var from = 0
            while from <= w.length - needle.length {
                let r = w.range(of: word, options: [.literal],
                                range: NSRange(location: from, length: w.length - from))
                if r.location == NSNotFound { break }
                let beforeOk = r.location == 0 || !isAlnum(w.character(at: r.location - 1))
                let j = r.location + r.length
                let afterOk = j >= w.length || !isAlnum(w.character(at: j))
                if beforeOk && afterOk { return true }
                from = r.location + 1
            }
        }
        return false
    }

    private static func documentHasWholeWord(_ text: String, _ words: [String]) -> Bool {
        guard !words.isEmpty else { return false }
        return hasWholeWordContextAround(text, 0, (text as NSString).length, words)
    }

    // ── rule 1: activation ──────────────────────────────────────────────────

    /// The countries this text activates, in the bundle's signal order.
    public static func inferRegions(_ text: String) -> [String] {
        let ns = text as NSString
        let full = NSRange(location: 0, length: ns.length)
        let lower = text.lowercased()
        var regions: [String] = []

        for code in signalOrder {
            for (i, s) in torkPiiSignals.enumerated() where s.country == code {
                guard compiledSignals[i].firstMatch(in: text, range: full) != nil else { continue }
                let bySubstring = !s.keywords.isEmpty && s.keywords.contains { lower.contains($0) }
                let byWholeWord = documentHasWholeWord(text, s.wholeWordKeywords)
                // Both lists empty means the shape alone is distinctive enough.
                if (!s.keywords.isEmpty || !s.wholeWordKeywords.isEmpty), !bySubstring, !byWholeWord {
                    continue
                }
                let target = s.activates.isEmpty ? code : s.activates
                if !regions.contains(target) { regions.append(target) }
                break // one signal per country is enough
            }
        }
        return regions
    }

    /// The patterns those regions switch on, de-duplicated, in registry order.
    public static func patternsForRegions(_ regions: [String]) -> [TorkPiiPattern] {
        var out: [TorkPiiPattern] = []
        var seen = Set<String>()
        for code in regions {
            for name in countryPatterns[code.uppercased()] ?? [] {
                guard !seen.contains(name), let p = byName[name] else { continue }
                seen.insert(name)
                out.append(p)
            }
        }
        return out
    }

    // ── rule 7: the column is the context ───────────────────────────────────

    struct TableScope {
        let start: Int
        let end: Int
        let header: String
        let rowStart: Int
        let rowEnd: Int
    }

    private static func looksLikeHeader(_ cells: [String], _ delimiter: String) -> Bool {
        let minimum = delimiter == "," ? torkPiiTableMinCommaColumns : 2
        guard cells.count >= minimum else { return false }
        for cell in cells {
            let t = cell.trimmingCharacters(in: .whitespaces)
            if t.isEmpty || (t as NSString).length > torkPiiTableMaxHeaderLength { return false }
            if t.rangeOfCharacter(from: .letters) == nil { return false }
            if t.allSatisfy({ $0.isNumber || " .-/+".contains($0) }) { return false }
            if t.contains(".") || t.contains("?") || t.contains("!") { return false }
            if t.split(whereSeparator: { $0.isWhitespace }).count > torkPiiTableMaxHeaderWords { return false }
        }
        return true
    }

    /// The cells of `text`, when it is a delimited table with a header row.
    static func tableScopes(_ text: String) -> [TableScope] {
        let lines = text.components(separatedBy: "\n")
        guard lines.count >= torkPiiTableMinRows else { return [] }

        var offsets: [Int] = []
        var at = 0
        for line in lines {
            offsets.append(at)
            at += (line as NSString).length + 1
        }

        for delimiter in torkPiiTableDelimiters {
            let headerCells = lines[0].components(separatedBy: delimiter)
            guard looksLikeHeader(headerCells, delimiter) else { continue }
            let width = headerCells.count

            var dataRows: [Int] = []
            for i in 1..<lines.count {
                if lines[i].trimmingCharacters(in: .whitespaces).isEmpty { continue }
                if lines[i].components(separatedBy: delimiter).count != width { return [] }
                dataRows.append(i)
            }
            guard dataRows.count >= torkPiiTableMinRows - 1 else { continue }

            var scopes: [TableScope] = []
            for row in dataRows {
                let cells = lines[row].components(separatedBy: delimiter)
                let rowStart = offsets[row]
                let rowEnd = rowStart + (lines[row] as NSString).length
                var cellStart = rowStart
                for col in 0..<width {
                    let len = (cells[col] as NSString).length
                    scopes.append(TableScope(
                        start: cellStart, end: cellStart + len,
                        header: headerCells[col].trimmingCharacters(in: .whitespaces).lowercased(),
                        rowStart: rowStart, rowEnd: rowEnd))
                    cellStart += len + (delimiter as NSString).length
                }
            }
            return scopes
        }
        return []
    }

    /// A whole-word match, not a substring.
    private static func headerNames(_ header: String, _ keywords: [String]) -> Bool {
        let h = header as NSString
        for kw in keywords {
            let r = h.range(of: kw, options: [.literal])
            if r.location == NSNotFound { continue }
            let beforeOk = r.location == 0 || !isAlnum(h.character(at: r.location - 1))
            let j = r.location + r.length
            let afterOk = j >= h.length || !isAlnum(h.character(at: j))
            if beforeOk && afterOk { return true }
        }
        return false
    }

    /// nil when the window should be consulted as usual.
    private static func columnVerdict(
        _ ns: NSString, _ scopes: [TableScope], _ start: Int, _ end: Int,
        _ all: [String], _ specific: [String]
    ) -> Bool? {
        guard !scopes.isEmpty,
              let cell = scopes.first(where: { start >= $0.start && end <= $0.end })
        else { return nil }
        // A cell whose own row names the identifier is prose in a delimited block.
        let rowText = window(ns, cell.rowStart, cell.rowEnd)
        if all.contains(where: { rowText.contains($0) }) { return nil }
        return !specific.isEmpty && headerNames(cell.header, specific)
    }

    // ── rule 7b: nearest label wins ─────────────────────────────────────────

    private static func closestBefore(_ before: String, _ keywords: [String]) -> Int? {
        let b = before as NSString
        var best: Int?
        for kw in keywords {
            let r = b.range(of: kw, options: [.literal, .backwards])
            if r.location == NSNotFound { continue }
            let d = b.length - (r.location + r.length)
            if best == nil || d < best! { best = d }
        }
        return best
    }

    private static func closestAfter(_ after: String, _ keywords: [String]) -> Int? {
        let a = after as NSString
        var best: Int?
        for kw in keywords {
            let r = a.range(of: kw, options: [.literal])
            if r.location == NSNotFound { continue }
            if best == nil || r.location < best! { best = r.location }
        }
        return best
    }

    /// Whether the number is labelled as a commercial reference more closely
    /// than as an identifier. It can only ever close a gate, never open one.
    public static func labelledAsReference(
        _ text: String, _ start: Int, _ end: Int, _ identifierKeywords: [String]
    ) -> Bool {
        let ns = text as NSString
        let before = window(ns, start - torkPiiLabelWindow, start)
        guard let reference = closestBefore(before, torkPiiReferenceLabels),
              reference <= torkPiiLabelReach else { return false }
        if identifierKeywords.isEmpty { return true }
        if let idBefore = closestBefore(before, identifierKeywords), idBefore <= reference { return false }
        let after = window(ns, end, end + torkPiiLabelWindow)
        if let idAfter = closestAfter(after, identifierKeywords), idAfter <= reference { return false }
        return true
    }

    // ── the pass ────────────────────────────────────────────────────────────

    /// The span with leading and trailing non-alphanumeric characters removed.
    public static func trimmedCore(_ ns: NSString, _ start: Int, _ end: Int) -> (Int, Int) {
        var s = start, e = end
        while s < e, !isAlnum(ns.character(at: s)) { s += 1 }
        while e > s, !isAlnum(ns.character(at: e - 1)) { e -= 1 }
        return s == e ? (start, end) : (s, e)
    }

    /// Matches, plus the caller's own L0 ranges that rule 5 superseded.
    public struct Result {
        public let matches: [CountryMatch]
        public let supersededRanges: [(Int, Int)]
    }

    /// Country matches for `text`, de-overlapped and ordered by position.
    public static func detect(_ text: String, patterns: [TorkPiiPattern]? = nil) -> [CountryMatch] {
        detectWithRanges(text, patterns: patterns).matches
    }

    /// The full pass. Pass your own L0 spans so rule 5 can supersede them.
    public static func detectWithRanges(
        _ text: String, patterns: [TorkPiiPattern]? = nil, existingRanges: [(Int, Int)] = []
    ) -> Result {
        let active: [TorkPiiPattern]
        if let patterns {
            active = patterns
        } else {
            var seen = Set<String>()
            var out: [TorkPiiPattern] = []
            for p in alwaysOnPatterns where seen.insert(p.name).inserted { out.append(p) }
            for p in patternsForRegions(inferRegions(text)) where seen.insert(p.name).inserted { out.append(p) }
            active = out
        }
        guard !active.isEmpty else { return Result(matches: [], supersededRanges: []) }

        let ns = text as NSString
        let full = NSRange(location: 0, length: ns.length)
        let tables = tableScopes(text)

        var activeExisting = existingRanges
        var superseded: [(Int, Int)] = []
        var claimed: [(Int, Int)] = []
        var found: [CountryMatch] = []
        var nearMisses: [(Int, Int)] = []

        for pattern in active {
            guard let re = compiled[pattern.name] else { continue }
            for m in re.matches(in: text, range: full) {
                let start = m.range.location
                let end = start + m.range.length
                if m.range.length == 0 { continue }

                // Rules 3, 7 and 7b.
                if pattern.requiresKeyword && !pattern.keywords.isEmpty {
                    let all = allKeywordsOf(pattern)
                    var ok = hasWholeWordContextAround(text, start, end, pattern.wholeWordKeywords)
                    if !ok {
                        if let column = columnVerdict(ns, tables, start, end, all, specificKeywords(all)) {
                            ok = column
                        } else {
                            ok = hasNearbyContext(ns, start, end, pattern.keywords)
                        }
                    }
                    if !ok { continue }
                    if labelledAsReference(text, start, end, pattern.keywords) { continue }
                }

                // Rule 4, and rule 6's candidate.
                if pattern.checksumRequired, let name = pattern.checksum,
                   let fn = PiiChecksums.functions[name],
                   !fn(ns.substring(with: m.range)) {
                    if pattern.nearMissFallback {
                        let extra = pattern.nearMissKeywords.isEmpty ? pattern.keywords : pattern.nearMissKeywords
                        let vocabulary = extra.isEmpty ? nationalIdKeywords : nationalIdKeywords + extra
                        if hasContextAround(ns, start, end, vocabulary) { nearMisses.append((start, end)) }
                    }
                    continue
                }

                // Rule 5.
                let overlapping = (activeExisting + claimed).filter { start < $0.1 && end > $0.0 }
                if !overlapping.isEmpty {
                    let supersedesAll = overlapping.allSatisfy { r in
                        let (cs, ce) = trimmedCore(ns, r.0, r.1)
                        return start <= cs && end >= ce
                    }
                    if !supersedesAll { continue }
                    for o in overlapping {
                        if let i = activeExisting.firstIndex(where: { $0 == o }) {
                            superseded.append(activeExisting.remove(at: i))
                        }
                        claimed.removeAll { $0 == o }
                        found.removeAll { $0.startIndex == o.0 && $0.endIndex == o.1 }
                    }
                }

                claimed.append((start, end))
                found.append(CountryMatch(
                    name: pattern.name, country: pattern.country, label: pattern.label,
                    type: pattern.type, redaction: pattern.redaction,
                    startIndex: start, endIndex: end))
            }
        }

        // Rule 6, last: a near miss can only ever fill a hole.
        var taken = activeExisting + claimed
        for c in nearMisses {
            if taken.contains(where: { c.0 < $0.1 && c.1 > $0.0 }) { continue }
            taken.append(c)
            found.append(CountryMatch(
                name: torkPiiNearMissType, country: "", label: "NATIONAL_ID",
                type: torkPiiNearMissType, redaction: torkPiiNearMissRedaction,
                startIndex: c.0, endIndex: c.1))
        }

        found.sort { $0.startIndex < $1.startIndex }
        return Result(matches: found, supersededRanges: superseded)
    }

    /// Turn country matches into redaction spans.
    public static func redactionSpansOf(_ matches: [CountryMatch]) -> [RedactionSpan] {
        matches.map { RedactionSpan(startIndex: $0.startIndex, endIndex: $0.endIndex, redaction: $0.redaction) }
    }

    /// Replace every span with its redaction, right to left.
    ///
    /// Right to left is what keeps the earlier indices valid, and splicing whole
    /// spans in one pass is what guarantees no partial redaction: a digit can
    /// never be left standing beside a redaction token, because nothing is ever
    /// matched against text a previous replacement has already rewritten.
    public static func applyRedactions(_ text: String, _ spans: [RedactionSpan]) -> String {
        guard !spans.isEmpty else { return text }
        let ordered = spans.sorted { $0.startIndex < $1.startIndex }
        var out = text as NSString
        for s in ordered.reversed() {
            out = out.replacingCharacters(
                in: NSRange(location: s.startIndex, length: s.endIndex - s.startIndex),
                with: s.redaction) as NSString
        }
        return out as String
    }
}
