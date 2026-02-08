import XCTest
@testable import TorkGovernance

final class TorkTests: XCTestCase {

    func testCleanTextPassesThrough() {
        let tork = Tork()
        let result = tork.govern("Hello, world!")

        XCTAssertEqual(result.action, .allow)
        XCTAssertEqual(result.output, "Hello, world!")
        XCTAssertFalse(result.pii.hasPII)
    }

    func testSSNIsRedacted() {
        let tork = Tork()
        let result = tork.govern("My SSN is 123-45-6789")

        XCTAssertEqual(result.action, .redact)
        XCTAssertTrue(result.output.contains("[SSN_REDACTED]"))
        XCTAssertFalse(result.output.contains("123-45-6789"))
        XCTAssertTrue(result.pii.hasPII)
        XCTAssertTrue(result.pii.types.contains(.ssn))
    }

    func testEmailIsRedacted() {
        let tork = Tork()
        let result = tork.govern("Contact john@example.com for details")

        XCTAssertEqual(result.action, .redact)
        XCTAssertTrue(result.output.contains("[EMAIL_REDACTED]"))
        XCTAssertFalse(result.output.contains("john@example.com"))
        XCTAssertTrue(result.pii.types.contains(.email))
    }

    func testMultiplePIIRedaction() {
        let tork = Tork()
        let result = tork.govern("SSN: 123-45-6789, email: test@example.com")

        XCTAssertEqual(result.action, .redact)
        XCTAssertTrue(result.output.contains("[SSN_REDACTED]"))
        XCTAssertTrue(result.output.contains("[EMAIL_REDACTED]"))
        XCTAssertGreaterThanOrEqual(result.pii.count, 2)
    }

    func testReceiptIsGenerated() {
        let tork = Tork()
        let result = tork.govern("My SSN is 123-45-6789")

        XCTAssertTrue(result.receipt.receiptId.hasPrefix("rcpt_"))
        XCTAssertTrue(result.receipt.inputHash.hasPrefix("sha256:"))
        XCTAssertTrue(result.receipt.outputHash.hasPrefix("sha256:"))
        XCTAssertNotEqual(result.receipt.inputHash, result.receipt.outputHash)
        XCTAssertEqual(result.receipt.action, .redact)
    }
}
