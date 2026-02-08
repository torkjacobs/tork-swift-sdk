import Foundation

/// Configuration for the Tork governance client.
public struct TorkConfig: Sendable {
    public var policyVersion: String
    public var defaultAction: GovernanceAction

    public init(
        policyVersion: String = "1.0.0",
        defaultAction: GovernanceAction = .redact
    ) {
        self.policyVersion = policyVersion
        self.defaultAction = defaultAction
    }
}

/// Main Tork governance client.
///
/// Detects PII in text, applies governance policies, and generates
/// cryptographic receipts for audit trails.
///
/// ```swift
/// let tork = Tork()
/// let result = tork.govern("My SSN is 123-45-6789")
/// print(result.output)  // "My SSN is [SSN_REDACTED]"
/// print(result.receipt.receiptId)  // "rcpt_..."
/// ```
public final class Tork: @unchecked Sendable {

    private var config: TorkConfig
    private var totalCalls: Int = 0
    private var totalPIIDetected: Int = 0

    /// Create a new Tork client with default configuration.
    public init(config: TorkConfig = TorkConfig()) {
        self.config = config
    }

    /// Apply governance rules to the input text.
    ///
    /// Detects PII, applies the configured action (allow/deny/redact),
    /// and returns a ``GovernanceResult`` with a cryptographic receipt.
    public func govern(_ text: String) -> GovernanceResult {
        let start = DispatchTime.now()

        let pii = PiiDetector.detect(text)

        let action: GovernanceAction
        let output: String

        if pii.hasPII {
            action = config.defaultAction
            output = action == .redact ? pii.redactedText : text
        } else {
            action = .allow
            output = text
        }

        let end = DispatchTime.now()
        let processingNs = end.uptimeNanoseconds - start.uptimeNanoseconds

        let receipt = ReceiptUtils.generate(
            input: text,
            output: output,
            action: action,
            piiTypes: pii.types,
            piiCount: pii.count,
            policyVersion: config.policyVersion,
            processingTimeNs: processingNs
        )

        totalCalls += 1
        if pii.hasPII { totalPIIDetected += 1 }

        return GovernanceResult(
            action: action,
            output: output,
            pii: pii,
            receipt: receipt
        )
    }

    /// Get the total number of governance calls made.
    public var callCount: Int { totalCalls }

    /// Get the total number of calls that detected PII.
    public var piiDetectedCount: Int { totalPIIDetected }

    /// Reset all statistics.
    public func resetStats() {
        totalCalls = 0
        totalPIIDetected = 0
    }
}
