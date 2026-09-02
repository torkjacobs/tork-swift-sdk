import Foundation
import CryptoKit

/// Governance action taken on input.
public enum GovernanceAction: String, Sendable {
    case allow = "allow"
    case deny = "deny"
    case redact = "redact"
    case escalate = "escalate"
}

/// Cryptographic receipt for a governance operation.
public struct GovernanceReceipt: Sendable {
    public let receiptId: String
    public let timestamp: Date
    public let inputHash: String
    public let outputHash: String
    public let action: GovernanceAction
    public let piiTypes: [PIIType]
    public let piiCount: Int
    public let policyVersion: String
    public let processingTimeNs: UInt64
    /// Agent/session context when provided.
    public let sessionContext: SessionContext?
    /// Present only on receipts produced by `Tork.scanToolResult`. Records
    /// the tool-result scan as a CLIENT-ATTESTED, edge-captured control:
    /// counts by kind and type, the tool it came from, and the SDK that ran
    /// it -- never the payload.
    public let toolResultScan: ToolResultScanReceiptBlock?

    public init(
        receiptId: String,
        timestamp: Date,
        inputHash: String,
        outputHash: String,
        action: GovernanceAction,
        piiTypes: [PIIType],
        piiCount: Int,
        policyVersion: String,
        processingTimeNs: UInt64,
        sessionContext: SessionContext? = nil,
        toolResultScan: ToolResultScanReceiptBlock? = nil
    ) {
        self.receiptId = receiptId
        self.timestamp = timestamp
        self.inputHash = inputHash
        self.outputHash = outputHash
        self.action = action
        self.piiTypes = piiTypes
        self.piiCount = piiCount
        self.policyVersion = policyVersion
        self.processingTimeNs = processingTimeNs
        self.sessionContext = sessionContext
        self.toolResultScan = toolResultScan
    }
}

/// Agent/session context for multi-agent governance tracking.
///
/// All fields are optional. When provided, they are included in the POST body
/// to /api/v1/govern and returned in the receipt under `session_context`.
public struct SessionContext: Sendable {
    /// Identifier for the agent making the call.
    public let agentId: String?
    /// Role of the agent: "planner", "worker", or "judge".
    public let agentRole: String?
    /// Groups all calls from the same agent session.
    public let sessionId: String?
    /// Position in the conversation (1, 2, 3...).
    public let sessionTurn: Int?

    public init(agentId: String? = nil, agentRole: String? = nil,
                sessionId: String? = nil, sessionTurn: Int? = nil) {
        self.agentId = agentId
        self.agentRole = agentRole
        self.sessionId = sessionId
        self.sessionTurn = sessionTurn
    }
}

/// Options for regional and industry-specific PII detection.
public struct GovernOptions: Sendable {
    public let region: [String]?
    public let industry: String?
    /// Optional agent/session context for multi-agent tracking.
    public let sessionContext: SessionContext?

    public init(region: [String]? = nil, industry: String? = nil,
                sessionContext: SessionContext? = nil) {
        self.region = region
        self.industry = industry
        self.sessionContext = sessionContext
    }
}

/// Result of a governance operation.
public struct GovernanceResult: Sendable {
    public let action: GovernanceAction
    public let output: String
    public let pii: PIIResult
    public let receipt: GovernanceReceipt
    public let region: [String]?
    public let industry: String?
    /// Agent/session context when provided.
    public let sessionContext: SessionContext?
}

/// Utility functions for receipt generation.
public enum ReceiptUtils {
    /// Generate a unique receipt ID.
    public static func generateReceiptId() -> String {
        "rcpt_\(UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "").prefix(32))"
    }

    /// Compute a SHA-256 hash of the given text.
    public static func hashText(_ text: String) -> String {
        let data = Data(text.utf8)
        let digest = SHA256.hash(data: data)
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return "sha256:\(hex)"
    }

    /// Generate a full governance receipt.
    public static func generate(
        input: String,
        output: String,
        action: GovernanceAction,
        piiTypes: [PIIType],
        piiCount: Int,
        policyVersion: String,
        processingTimeNs: UInt64,
        sessionContext: SessionContext? = nil
    ) -> GovernanceReceipt {
        GovernanceReceipt(
            receiptId: generateReceiptId(),
            timestamp: Date(),
            inputHash: hashText(input),
            outputHash: hashText(output),
            action: action,
            piiTypes: piiTypes,
            piiCount: piiCount,
            policyVersion: policyVersion,
            processingTimeNs: processingTimeNs,
            sessionContext: sessionContext
        )
    }
}
