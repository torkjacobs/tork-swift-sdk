import XCTest
@testable import TorkGovernance

/// Registers SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS (P1):
/// every `PIIType` this SDK declares must have a live detection pattern.
///
/// This SDK's gap took a different shape than the Go SDK's (which declared
/// all 10 `PIIType` cases but only shipped 7 patterns): here the enum itself
/// only declared 7 of the JS SDK's 10-type Tier 1 vocabulary, so
/// `passport`, `driversLicense` and `bankAccount` did not exist as cases at
/// all -- not merely "declared without a pattern," but entirely undeclared,
/// which is the more severe version of the same underlying defect: the
/// SDK's PII vocabulary silently fell short of the JS source of truth.
final class PiiDetectorParityTests: XCTestCase {

    func testEveryDeclaredPIITypeHasALivePattern() {
        let patternedTypes = Set(PiiDetector.defaultPatterns.map { $0.type })
        for type in PIIType.allCases {
            XCTAssertTrue(
                patternedTypes.contains(type),
                "PIIType.\(type) is declared but has no detection pattern in PiiDetector.defaultPatterns"
            )
        }
        XCTAssertEqual(patternedTypes.count, PIIType.allCases.count)
    }

    func testTier1VocabularyMatchesJSSDK() {
        let expected: Set<PIIType> = [
            .ssn, .creditCard, .email, .phone, .address,
            .ipAddress, .dateOfBirth, .passport, .driversLicense, .bankAccount,
        ]
        XCTAssertEqual(Set(PIIType.allCases), expected)
    }

    func testJSFixtureParityForAllTenPIITypes() {
        let fixtures: [(String, PIIType)] = [
            ("My SSN is 123-45-6789", .ssn),
            ("Contact me at john@example.com", .email),
            ("Card: 4111-1111-1111-1111", .creditCard),
            ("Call me at 555-123-4567", .phone),
            ("Server IP: 192.168.1.1", .ipAddress),
            ("DOB: 01/15/1990", .dateOfBirth),
            ("I live at 123 Main Street", .address),
            ("Passport AB1234567", .passport),
            ("License D12345678", .driversLicense),
            ("Account 123456789012", .bankAccount),
        ]
        for (text, expected) in fixtures {
            let result = PiiDetector.detect(text)
            XCTAssertTrue(result.types.contains(expected), "\(text) did not detect \(expected)")
        }
    }

    /// Every declared type needs a positive and a negative example. The
    /// negative must not trigger THAT type (other types may fire on other text).
    func testEveryDeclaredTypeHasPositiveAndNegativeExample() {
        let examples: [PIIType: (positive: String, negative: String)] = [
            .ssn: ("My SSN is 123-45-6789", "Order 123-45-67 shipped"),
            .creditCard: ("Card: 4111-1111-1111-1111", "Card: 4111-1111"),
            .email: ("Contact me at john@example.com", "Contact me at john at example"),
            .phone: ("Call me at 555-123-4567", "Call me at 555-12"),
            .ipAddress: ("Server IP: 192.168.1.1", "Version 1.2.3"),
            .dateOfBirth: ("DOB: 01/15/1990", "Meeting on 13/45/1990"),
            .address: ("I live at 123 Main Street", "I live in Main Street"),
            .passport: ("Passport AB1234567", "Passport AB12"),
            .driversLicense: ("License D12345678", "License D12"),
            .bankAccount: ("Account 123456789012", "Account 1234"),
        ]
        XCTAssertEqual(Set(examples.keys), Set(PIIType.allCases), "a declared type has no example")
        for (type, ex) in examples {
            XCTAssertTrue(PiiDetector.detect(ex.positive).types.contains(type), "positive: \(type)")
            XCTAssertFalse(PiiDetector.detect(ex.negative).types.contains(type), "negative: \(type)")
        }
    }
}
