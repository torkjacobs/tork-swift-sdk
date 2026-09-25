// Country-layer parity tests.
//
// The fixtures are generated from the cloud's own evidence, not written here:
//
//   pii_unit_cases.json  one valid sample per registry pattern, a
//                        checksum-broken variant for each pattern whose
//                        checksum is a gate, and the Indonesian boundary cases.
//   pii_vectors.json     all 2,092 inputs of the cloud's golden snapshot: every
//                        country-corpus sentence for all 249 ISO jurisdictions,
//                        and the whole 1,523-line business false-positive corpus.
//
// expectedOutput is the COUNTRY LAYER alone. Where the cloud's own output
// differs, the case carries cloudOutput and a divergence naming the cause.

import Foundation
import XCTest

@testable import TorkGovernance

private struct UnitCase: Decodable {
    let pattern: String
    let label: String
    let redaction: String
    let input: String
    let sample: String
    let expectDetected: Bool
}

private struct Vector: Decodable {
    let id: String
    let kind: String
    let input: String
    let expectedOutput: String
    let expectedRegions: [String]
    let expectedLabels: [String]
    let expectedNames: [String]
    let cloudOutput: String?
    let divergence: String?
}

private struct VectorFile: Decodable {
    let bundleVersion: String
    let contentHash: String
    let cases: [Vector]
}

final class PiiCountryTests: XCTestCase {
    private static let nik = "3171010101900001"

    private func fixture<T: Decodable>(_ name: String, as: T.Type) throws -> T {
        let url = Bundle.module.url(forResource: "Fixtures/\(name)", withExtension: "json")
            ?? Bundle.module.url(forResource: name, withExtension: "json")!
        return try JSONDecoder().decode(T.self, from: Data(contentsOf: url))
    }

    private func vectors() throws -> VectorFile { try fixture("pii_vectors", as: VectorFile.self) }

    private func redact(_ s: String) -> String {
        let matches = PiiCountry.detect(s)
        return PiiCountry.applyRedactions(s, PiiCountry.redactionSpansOf(matches))
    }

    // ── the bundle ──────────────────────────────────────────────────────────

    func testIsTheVersionAndContentTheFixturesWereGeneratedFrom() throws {
        let v = try vectors()
        XCTAssertEqual(torkPiiRegistryVersion, v.bundleVersion)
        XCTAssertEqual(torkPiiContentHash, v.contentHash)
    }

    func testCarries54PatternsAcross24ProfilesWith51SignalsAnd3AlwaysOn() {
        XCTAssertEqual(torkPiiPatterns.count, 54)
        XCTAssertEqual(torkPiiCountries.count, 24)
        XCTAssertEqual(torkPiiSignals.count, 51)
        XCTAssertEqual(torkPiiPatterns.filter { $0.alwaysOn }.count, 3)
    }

    func testCoversIndonesiaAddedIn110() throws {
        let id = try XCTUnwrap(torkPiiCountries.first { $0.code == "ID" }, "Indonesia is missing")
        XCTAssertTrue(id.patterns.contains("id_nik"))
        let nik = try XCTUnwrap(torkPiiPatterns.first { $0.name == "id_nik" })
        XCTAssertEqual(nik.label, "NIK")
        XCTAssertTrue(nik.wholeWordKeywords.contains("nik"))
    }

    func testReadsItsWindowsFromTheBundleAndTheyAreNotAllTheSame() {
        XCTAssertEqual(PiiCountry.keywordWindowBefore, 60)
        XCTAssertEqual(PiiCountry.keywordWindowAfter, 40)
        XCTAssertEqual(PiiCountry.contextWindow, 60)
        XCTAssertNotEqual(PiiCountry.keywordWindowBefore, PiiCountry.keywordWindowAfter)
    }

    func testNamesAChecksumFunctionForEveryPatternThatDeclaresOne() {
        for p in torkPiiPatterns {
            guard let c = p.checksum else { continue }
            XCTAssertNotNil(PiiChecksums.functions[c], "\(p.name) -> \(c)")
        }
    }

    func testUsesOnlyThePortableRegexSubset() {
        let forbidden = [("(?=", "lookahead"), ("(?!", "negative lookahead"),
                         ("(?<=", "lookbehind"), ("(?<!", "negative lookbehind"),
                         ("\\p{", "unicode property escape"), ("(?>", "atomic group")]
        let sources = torkPiiPatterns.map(\.regex) + torkPiiSignals.map(\.regex)
        for src in sources {
            for (bad, why) in forbidden {
                XCTAssertFalse(src.contains(bad), "\(src) uses \(why)")
            }
        }
    }

    // ── per-pattern unit cases ──────────────────────────────────────────────

    func testPerPatternUnitCases() throws {
        let units = try fixture("pii_unit_cases", as: [UnitCase].self)
        XCTAssertFalse(units.isEmpty)
        var byName: [String: TorkPiiPattern] = [:]
        for p in torkPiiPatterns { byName[p.name] = p }

        for c in units {
            let p = try XCTUnwrap(byName[c.pattern], "\(c.pattern) is not in the bundle")
            let found = PiiCountry.detect(c.input, patterns: [p])
            let hit = found.first { $0.name == c.pattern }
            if c.expectDetected {
                let h = try XCTUnwrap(hit, "expected \(c.pattern) to match \(c.input)")
                let ns = c.input as NSString
                XCTAssertEqual(ns.substring(with: NSRange(location: h.startIndex, length: h.endIndex - h.startIndex)), c.sample)
                XCTAssertEqual(h.redaction, c.redaction)
            } else {
                XCTAssertNil(hit, "expected \(c.pattern) NOT to match \(c.input)")
            }
        }
    }

    // ── golden-snapshot parity ──────────────────────────────────────────────

    func testReproducesTheCloudOnEveryCorpusVector() throws {
        let corpus = try vectors().cases.filter { $0.kind != "business-fp" }
        XCTAssertGreaterThan(corpus.count, 500)
        var failures: [String] = []
        for c in corpus {
            let matches = PiiCountry.detect(c.input)
            let out = PiiCountry.applyRedactions(c.input, PiiCountry.redactionSpansOf(matches))
            if PiiCountry.inferRegions(c.input) != c.expectedRegions { failures.append("\(c.id) activation") }
            if out != c.expectedOutput { failures.append("\(c.id) redaction: \(out)") }
            var labels: [String] = [], names: [String] = []
            for m in matches {
                if !labels.contains(m.label) { labels.append(m.label) }
                if !names.contains(m.name) { names.append(m.name) }
            }
            if labels != c.expectedLabels { failures.append("\(c.id) labels") }
            if names != c.expectedNames { failures.append("\(c.id) names") }
        }
        XCTAssertEqual(failures, [])
    }

    func testAddsNoFalsePositiveToTheBusinessCorpus() throws {
        let business = try vectors().cases.filter { $0.kind == "business-fp" }
        XCTAssertGreaterThan(business.count, 1500)
        let bad = business.filter { !PiiCountry.detect($0.input).isEmpty }.map(\.id)
        XCTAssertEqual(bad, [])
        let drift = business.filter { PiiCountry.inferRegions($0.input) != $0.expectedRegions }.map(\.id)
        XCTAssertEqual(drift, [])
    }

    func testDivergesFromTheCloudForExactlyTwoStatedReasons() throws {
        let diverged = try vectors().cases.filter { $0.divergence != nil }
        for c in diverged {
            let d = c.divergence!
            XCTAssertTrue(d.hasPrefix("L0:") || d.hasPrefix("BUNDLE GAP:"), "\(c.id): unexplained divergence")
        }
        // checksums.json names au_tfn, au_abn and au_medicare; `patterns` ships none.
        let gaps = Set(diverged.filter { $0.divergence!.hasPrefix("BUNDLE GAP:") }
            .map { $0.id.split(separator: "/")[1] }.map(String.init))
        XCTAssertEqual(gaps, ["au_tfn", "au_medicare"])
    }

    func testNothingIsEverPartiallyRedacted() throws {
        let bad = try NSRegularExpression(pattern: #"\d\[[A-Z_]+_REDACTED\]|\[[A-Z_]+_REDACTED\]\d"#)
        for c in try vectors().cases {
            let matches = PiiCountry.detect(c.input)
            let out = PiiCountry.applyRedactions(c.input, PiiCountry.redactionSpansOf(matches))
            XCTAssertNil(bad.firstMatch(in: out, range: NSRange(location: 0, length: (out as NSString).length)), c.id)
            let ns = c.input as NSString
            for m in matches {
                let raw = ns.substring(with: NSRange(location: m.startIndex, length: m.endIndex - m.startIndex))
                XCTAssertFalse(out.contains(raw), "\(c.id): \(raw) survived")
            }
        }
    }

    // ── Indonesia, the rule 1.1.0 added ─────────────────────────────────────

    func testDetectsTheShortSpellingWhichIsAWholeWordKeywordOnly() {
        let s = "NIK \(Self.nik) untuk pendaftaran rekening di Jakarta, Indonesia."
        XCTAssertEqual(PiiCountry.inferRegions(s), ["ID"])
        XCTAssertEqual(redact(s), "NIK [NIK_REDACTED] untuk pendaftaran rekening di Jakarta, Indonesia.")
    }

    func testDetectsTheLongSpellingWhichIsAnOrdinarySubstringKeyword() {
        XCTAssertTrue(redact("Nomor Induk Kependudukan \(Self.nik) untuk pendaftaran.").contains("[NIK_REDACTED]"))
    }

    func testNikInsideAnOrdinaryIndonesianWordDoesNotOpenTheGate() {
        for word in ["teknik", "elektronik", "klinik", "pabrik", "piknik"] {
            XCTAssertTrue(PiiCountry.detect("Faktur \(word) \(Self.nik) untuk pelanggan.").isEmpty,
                          "\(word) opened the gate")
        }
    }

    func testABareNikIsNotRedacted() {
        XCTAssertTrue(PiiCountry.detect(Self.nik).isEmpty)
    }

    // ── the rules 1.1.0 added to the SDK half of the contract ───────────────

    func testRule6ChecksumFailingIdentifierIsRedactedGenerically() {
        let out = redact("South African ID number 8001015009088 for the FICA check.")
        XCTAssertFalse(out.contains("8001015009088"))
        XCTAssertTrue(out.contains("[NATIONAL_ID_REDACTED]"))
    }

    func testRule7ColumnHeaderIsTheContextForABareValueCell() {
        let csv = ["Name,CNIC,City", "Ali,42201-1234567-1,Karachi",
                   "Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan"].joined(separator: "\n")
        XCTAssertFalse(PiiCountry.tableScopes(csv).isEmpty)
        XCTAssertFalse(redact(csv).contains("42201-1234567-1"))
    }

    func testRule7GenericHeaderDoesNotActAsContext() {
        let csv = ["Name,Order ID Number,City", "Ali,42201-1234567-1,Karachi",
                   "Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan"].joined(separator: "\n")
        XCTAssertTrue(PiiCountry.detect(csv).isEmpty)
    }

    func testRule7bCloserCommercialLabelClosesTheGate() {
        let s = "Please do not send your CNIC. Use the job number 4220112345671."
        let at = (s as NSString).range(of: "4220112345671").location
        XCTAssertTrue(PiiCountry.labelledAsReference(s, at, at + 13, ["cnic"]))
        XCTAssertTrue(redact(s).contains("4220112345671"))
    }

    func testRule7bCanOnlyCloseAGateNeverOpenOne() {
        XCTAssertTrue(PiiCountry.detect("Order 12345678901234 with no identifier word anywhere.").isEmpty)
    }

    func testRule5CountryMatchSupersedesAWiderL0Range() {
        let s = "CPF 529.982.247-25 para a nota fiscal no Brasil."
        let at = (s as NSString).range(of: "529.982.247-25").location
        let res = PiiCountry.detectWithRanges(s, existingRanges: [(at - 1, at + 14)])
        XCTAssertTrue(res.matches.contains { $0.name == "br_cpf" })
        XCTAssertEqual(res.supersededRanges.count, 1)
    }

    // ── bundle 1.2.0: the alwaysOn Australian patterns (rule 1a) ────────────

    func testAUTFNIsDetectedWithItsKeywordEvenWithNoOtherAustralianSignal() {
        let out = redact("Please quote tax file number 876543210 on the form.")
        XCTAssertFalse(out.contains("876543210"))
        XCTAssertTrue(out.contains("[TFN_REDACTED]"))
    }

    func testAUABNIsDetectedWithItsKeywordEvenWithNoOtherAustralianSignal() {
        let out = redact("Supplier ABN 51824753556 appears on the invoice.")
        XCTAssertFalse(out.contains("51824753556"))
        XCTAssertTrue(out.contains("[ABN_REDACTED]"))
    }

    func testAUTFNChecksumFailureFallsBackToTheGenericNearMissNotAHardReject() {
        let out = redact("Please quote tax file number 876543211 on the form.")
        XCTAssertFalse(out.contains("876543211"), "the near miss must still redact the digits")
        XCTAssertTrue(out.contains("[NATIONAL_ID_REDACTED]"))
        XCTAssertFalse(out.contains("[TFN_REDACTED]"), "a failed checksum must not be typed as au_tfn")
    }

    func testAUABNChecksumFailureIsSilentlyDroppedNotANearMiss() {
        // au_abn's nearMissFallback is false in the bundle: unlike au_tfn, a
        // checksum-failing ABN gets no fallback and is left unredacted rather
        // than mistyped as a near miss or as a valid ABN.
        let out = redact("Supplier ABN 51824753557 appears on the invoice.")
        XCTAssertTrue(out.contains("51824753557"), "a checksum-failing ABN must not be redacted at all")
        XCTAssertFalse(out.contains("[ABN_REDACTED]"))
        XCTAssertFalse(out.contains("[NATIONAL_ID_REDACTED]"))
    }

    func testAUMedicareIsDetectedWithItsKeyword() {
        let out = redact("Patient Medicare number 2123456701 for the visit.")
        XCTAssertFalse(out.contains("2123456701"))
        XCTAssertTrue(out.contains("[MEDICARE_REDACTED]"))
    }

    func testAUMedicareChecksumIsAdvisoryAndNeverRejects() {
        // au_medicare's checksum is community-sourced and unconfirmed: the
        // bundle marks checksumRequired false, so a checksum-failing number
        // must still be detected and redacted exactly like a valid one.
        let out = redact("Patient Medicare number 2123456711 for the visit.")
        XCTAssertFalse(out.contains("2123456711"))
        XCTAssertTrue(out.contains("[MEDICARE_REDACTED]"))
    }

    func testWholeWordMatchingRespectsBoundaries() {
        XCTAssertTrue(PiiCountry.hasWholeWordContextAround("nik 123", 4, 7, ["nik"]))
        XCTAssertFalse(PiiCountry.hasWholeWordContextAround("teknik 123", 7, 10, ["nik"]))
    }
}
