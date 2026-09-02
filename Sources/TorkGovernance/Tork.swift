import Foundation

/// What `Tork.scanToolResult` returns: the pure scan result, plus the
/// receipt recording it. The four scan fields (`sanitized`, `findings`,
/// `blocked`, `reason`) are exactly the shape of the standalone
/// `scanToolResult(_:options:)` function's return value.
public struct GovernedToolResultScanResult {
    public let sanitized: Any?
    public let findings: [ToolResultFinding]
    public let blocked: Bool
    /// Present only when `blocked` is true.
    public let reason: String?
    /// Carries the `toolResultScan` block.
    public let receipt: GovernanceReceipt
}

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

    /// Apply governance rules with regional and industry-specific detection.
    ///
    /// - Parameters:
    ///   - text: The text to govern
    ///   - options: Regional, industry, and session context options
    /// - Returns: A ``GovernanceResult`` with a cryptographic receipt.
    public func govern(_ text: String, options: GovernOptions) -> GovernanceResult {
        let result = govern(text, sessionContext: options.sessionContext)
        return GovernanceResult(
            action: result.action,
            output: result.output,
            pii: result.pii,
            receipt: result.receipt,
            region: options.region,
            industry: options.industry,
            sessionContext: options.sessionContext
        )
    }

    /// Apply governance rules to the input text.
    ///
    /// Detects PII, applies the configured action (allow/deny/redact),
    /// and returns a ``GovernanceResult`` with a cryptographic receipt.
    ///
    /// - Parameters:
    ///   - text: The text to govern
    ///   - sessionContext: Optional agent/session context for multi-agent tracking
    public func govern(_ text: String, sessionContext: SessionContext? = nil) -> GovernanceResult {
        let start = DispatchTime.now()

        let pii = PiiDetector.detect(text)

        let action: GovernanceAction
        let output: String

        if pii.hasPII {
            action = config.defaultAction
            output = pii.redactedText
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
            processingTimeNs: processingNs,
            sessionContext: sessionContext
        )

        totalCalls += 1
        if pii.hasPII { totalPIIDetected += 1 }

        return GovernanceResult(
            action: action,
            output: output,
            pii: pii,
            receipt: receipt,
            region: nil,
            industry: nil,
            sessionContext: sessionContext
        )
    }

    /// Scan a tool result (MCP server response, or any external system's
    /// output) for PII and prompt injection BEFORE it is appended to model
    /// context, and record the scan on a receipt.
    ///
    /// The scan itself is the pure `scanToolResult(_:options:)` function --
    /// on-device, synchronous, zero network calls, using the same PII
    /// detector as ``govern(_:sessionContext:)``. This method adds the
    /// receipt: `receipt.toolResultScan` carries counts by kind and type,
    /// the tool name, the server URI, whether the result was blocked, and
    /// the SDK version. It never carries the payload, a matched substring,
    /// or a location path.
    ///
    /// This is a CLIENT-SIDE, CLIENT-ATTESTED control: it runs in the
    /// caller's process, so the receipt records `attested_by: "client"` and
    /// `capture_mode: "edge"` -- Tork did not execute this scan and cannot
    /// verify it ran at all. Enforcement at the gateway, where a caller
    /// cannot skip the scan, is a separate and later control.
    ///
    /// - Parameters:
    ///   - input: The tool result to scan.
    ///   - options: Scan options (`blockOnInjection`, `customPatterns`, `maxDepth`).
    public func scanToolResult(
        _ input: ToolResultScanInput,
        options: ToolResultScanOptions = ToolResultScanOptions()
    ) -> GovernedToolResultScanResult {
        let start = DispatchTime.now()

        // Module-qualified to disambiguate from this instance method of the
        // same name: unqualified `scanToolResult(...)` inside a method body
        // resolves to `self.scanToolResult` first, which would recurse.
        let scan = TorkGovernance.scanToolResult(input, options: options)

        let piiCount = TorkGovernance.scanPIICount(scan.findings)
        let injectionCount = TorkGovernance.scanInjectionCount(scan.findings)
        let piiTypes = TorkGovernance.scanPIITypes(scan.findings).compactMap { PIIType(rawValue: $0) }

        // Fixed mapping, deliberately NOT config.defaultAction: unlike
        // govern(), this path always returns masked output when it returns
        // any, so the action must describe what actually happened to the
        // tool result. Every SDK mirroring this must use the same mapping.
        //   blocked            -> deny     (nothing is returned to append)
        //   injection detected -> escalate (returned, flagged for a human)
        //   PII masked         -> redact
        //   nothing found      -> allow
        let action: GovernanceAction
        if scan.blocked {
            action = .deny
        } else if injectionCount > 0 {
            action = .escalate
        } else if piiCount > 0 {
            action = .redact
        } else {
            action = .allow
        }

        let end = DispatchTime.now()
        let processingNs = end.uptimeNanoseconds - start.uptimeNanoseconds

        let block = buildToolResultScanBlock(BuildToolResultScanBlockParams(
            toolName: input.toolName,
            serverUri: input.serverUri,
            result: scan,
            sdkVersion: SDK_VERSION
        ))

        // Hashes, not content: hashJSONForReceipt is SHA256, so neither the
        // payload nor the sanitized copy is recoverable from the receipt. A
        // blocked scan has no output to hash and records the hash of the
        // empty string.
        let receipt = GovernanceReceipt(
            receiptId: ReceiptUtils.generateReceiptId(),
            timestamp: Date(),
            inputHash: hashJSONForReceipt(input.payload),
            outputHash: scan.blocked ? ReceiptUtils.hashText("") : hashJSONForReceipt(scan.sanitized),
            action: action,
            piiTypes: piiTypes,
            piiCount: piiCount,
            policyVersion: config.policyVersion,
            processingTimeNs: processingNs,
            toolResultScan: block
        )

        totalCalls += 1
        if piiCount > 0 { totalPIIDetected += 1 }

        return GovernedToolResultScanResult(
            sanitized: scan.sanitized,
            findings: scan.findings,
            blocked: scan.blocked,
            reason: scan.reason,
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
