# Tork Governance Swift SDK

On-device AI governance with PII detection, redaction, and cryptographic receipts for Swift applications.

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/torkjacobs/tork-swift-sdk.git", from: "0.1.0"),
]
```

Then add `TorkGovernance` to your target dependencies:

```swift
.target(
    name: "YourApp",
    dependencies: ["TorkGovernance"]
),
```

## Quick Start

```swift
import TorkGovernance

let tork = Tork()

let result = tork.govern("My SSN is 123-45-6789")
print(result.action)               // .redact
print(result.output)               // "My SSN is [SSN_REDACTED]"
print(result.pii.types)            // [.ssn]
print(result.receipt.receiptId)    // "rcpt_..."
```

## Regional PII Detection (v1.1)

Activate country-specific and industry-specific PII patterns:

```swift
let tork = Tork()

// UAE regional detection — Emirates ID, +971 phone, PO Box
let result = tork.govern(
    "Emirates ID: 784-1234-1234567-1",
    options: GovernOptions(region: ["ae"])
)

// Multi-region + industry
let result = tork.govern(
    "Aadhaar: 1234 5678 9012, ICD-10: J45.20",
    options: GovernOptions(region: ["in"], industry: "healthcare")
)

// Available regions: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR
// Available industries: healthcare, finance, legal
```

## Vapor Integration

```swift
import Vapor
import TorkGovernance

let tork = Tork()
let middleware = TorkVaporMiddleware(tork: tork)

// In your Vapor route handler:
func chatHandler(_ req: Request) throws -> String {
    let body = try req.content.decode(ChatRequest.self)
    let result = tork.govern(body.message)
    return result.output
}
```

### Middleware Configuration

```swift
let config = VaporMiddlewareConfig(
    skipPaths: ["/health", "/metrics"],
    governResponse: true
)
let middleware = TorkVaporMiddleware(tork: tork, config: config)
```

## PII Detection

Detects and redacts the following PII types:

| Type | Example | Redaction |
|------|---------|-----------|
| SSN | 123-45-6789 | [SSN_REDACTED] |
| Credit Card | 4111-1111-1111-1111 | [CARD_REDACTED] |
| Email | john@example.com | [EMAIL_REDACTED] |
| Phone | 555-123-4567 | [PHONE_REDACTED] |
| IP Address | 192.168.1.1 | [IP_REDACTED] |
| Date of Birth | 01/15/1990 | [DOB_REDACTED] |
| Address | 123 Main Street | [ADDRESS_REDACTED] |

## Cryptographic Receipts

Every governance operation generates a receipt with SHA-256 hashes:

```swift
let result = tork.govern("Sensitive data")

print(result.receipt.receiptId)        // Unique ID
print(result.receipt.inputHash)        // SHA-256 of input
print(result.receipt.outputHash)       // SHA-256 of output
print(result.receipt.timestamp)        // ISO 8601 timestamp
print(result.receipt.policyVersion)    // Applied policy version
```

## License

MIT
