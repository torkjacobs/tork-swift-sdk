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
}

/// Options for regional and industry-specific PII detection.
public struct GovernOptions: Sendable {
    public let region: [String]?
    public let industry: String?

    public init(region: [String]? = nil, industry: String? = nil) {
        self.region = region
        self.industry = industry
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
        processingTimeNs: UInt64
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
            processingTimeNs: processingTimeNs
        )
    }
}
