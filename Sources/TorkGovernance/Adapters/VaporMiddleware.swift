import Foundation

// MARK: - Vapor Middleware Protocol Conformance
//
// This adapter provides Vapor integration for Tork governance.
// Since Vapor is not a direct dependency, types are defined as protocols
// that Vapor's types conform to. Users bridge them in their Vapor app.
//
// Usage:
//
//     import TorkGovernance
//     import Vapor
//
//     let tork = Tork()
//     app.middleware.use(TorkVaporMiddleware(tork: tork))

/// Minimal protocol representing an HTTP request for Vapor integration.
public protocol TorkHTTPRequest {
    var method: String { get }
    var urlPath: String { get }
    var bodyString: String? { get }
}

/// Minimal protocol representing an HTTP response for Vapor integration.
public protocol TorkHTTPResponse {
    var bodyString: String? { get }
    mutating func setBody(_ string: String)
}

/// Configuration for Vapor middleware.
public struct VaporMiddlewareConfig: Sendable {
    public var skipPaths: [String]
    public var governResponse: Bool

    public init(
        skipPaths: [String] = [],
        governResponse: Bool = true
    ) {
        self.skipPaths = skipPaths
        self.governResponse = governResponse
    }
}

/// Tork governance middleware for Vapor.
///
/// Inspects incoming request bodies for PII and applies governance.
/// Stores the ``GovernanceResult`` on the request for downstream handlers.
///
/// ```swift
/// let tork = Tork()
/// let middleware = TorkVaporMiddleware(tork: tork)
/// // Use with Vapor's middleware pipeline
/// ```
public final class TorkVaporMiddleware: @unchecked Sendable {

    public let tork: Tork
    public let config: VaporMiddlewareConfig
    private(set) public var lastResult: GovernanceResult?

    public init(tork: Tork, config: VaporMiddlewareConfig = VaporMiddlewareConfig()) {
        self.tork = tork
        self.config = config
    }

    /// Govern an incoming request body string.
    ///
    /// Returns a ``GovernanceResult`` if the body contains text to govern,
    /// or `nil` if the request should be skipped.
    public func governRequest(_ request: TorkHTTPRequest) -> GovernanceResult? {
        // Skip non-mutating methods
        let method = request.method.uppercased()
        guard method == "POST" || method == "PUT" || method == "PATCH" else {
            return nil
        }

        // Skip configured paths
        let path = request.urlPath
        for skip in config.skipPaths {
            if path.hasPrefix(skip) { return nil }
        }

        // Extract body
        guard let body = request.bodyString, !body.isEmpty else {
            return nil
        }

        // Extract content from JSON body
        guard let content = extractContent(from: body) else {
            return nil
        }

        let result = tork.govern(content)
        lastResult = result
        return result
    }

    /// Govern an outgoing response body string.
    public func governResponse(_ body: String) -> GovernanceResult {
        let result = tork.govern(body)
        lastResult = result
        return result
    }

    /// Extract text content from a JSON body string.
    private func extractContent(from body: String) -> String? {
        guard let data = body.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return body
        }

        let keys = ["content", "message", "text", "prompt", "query", "input"]
        for key in keys {
            if let value = json[key] as? String, !value.isEmpty {
                return value
            }
        }

        return nil
    }
}
