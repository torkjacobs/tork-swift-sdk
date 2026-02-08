import XCTest
@testable import TorkGovernance

/// Mock HTTP request for testing.
struct MockHTTPRequest: TorkHTTPRequest {
    var method: String
    var urlPath: String
    var bodyString: String?
}

/// Mock HTTP response for testing.
struct MockHTTPResponse: TorkHTTPResponse {
    var bodyString: String?

    mutating func setBody(_ string: String) {
        bodyString = string
    }
}

final class VaporMiddlewareTests: XCTestCase {

    func testGovernRequestWithPII() {
        let tork = Tork()
        let middleware = TorkVaporMiddleware(tork: tork)

        let request = MockHTTPRequest(
            method: "POST",
            urlPath: "/chat",
            bodyString: #"{"content": "My SSN is 123-45-6789"}"#
        )

        let result = middleware.governRequest(request)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.action, .redact)
        XCTAssertTrue(result?.output.contains("[SSN_REDACTED]") ?? false)
    }

    func testSkipGetRequests() {
        let tork = Tork()
        let middleware = TorkVaporMiddleware(tork: tork)

        let request = MockHTTPRequest(
            method: "GET",
            urlPath: "/chat",
            bodyString: #"{"content": "My SSN is 123-45-6789"}"#
        )

        let result = middleware.governRequest(request)

        XCTAssertNil(result)
    }

    func testSkipConfiguredPaths() {
        let tork = Tork()
        let config = VaporMiddlewareConfig(skipPaths: ["/health"])
        let middleware = TorkVaporMiddleware(tork: tork, config: config)

        let request = MockHTTPRequest(
            method: "POST",
            urlPath: "/health",
            bodyString: #"{"content": "My SSN is 123-45-6789"}"#
        )

        let result = middleware.governRequest(request)

        XCTAssertNil(result)
    }
}
