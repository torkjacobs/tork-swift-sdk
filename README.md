# Tork Governance Swift SDK

On-device AI governance with PII detection, redaction, and cryptographic receipts for Swift applications.

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/torkjacobs/tork-swift-sdk.git", from: "0.3.0"),
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

## Country PII detection

23 country profiles, 50 patterns and 20 check digits, generated from Tork's own
country registry (bundle `1.0.0`) and computed entirely on-device.

Countries: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR, CA, ZA, GH, IT, KE,
MU, MX, MY, PK, SG, TH.

A country's patterns switch on when the text activates that country — the same
content signals the cloud uses — so ordinary business text is not measured
against 50 national-identifier patterns it could never contain. On the
1,159-line business corpus this SDK is tested against, nothing is redacted.

```swift
import TorkGovernance

let r = PiiDetector.detect("South African ID number 8001015009087 for the FICA check.")
r.regions       // ["ZA"]
r.countryLabels // ["ZA_ID"]
r.redactedText  // "South African ID number [ZA_ID_REDACTED] for the FICA check."
```

Force profiles on when you already know the jurisdiction:

```swift
let forced = PiiDetector.detect("Documento 529.982.247-25 arquivado.", regions: ["br"])
// forced.redactedText == "Documento [CPF_REDACTED] arquivado."
```

Three gates keep the false-positive rate down, and all three must pass:

1. **Activation** — one of the country's content signals fires.
2. **Keyword** — for 18 of the 24 national, tax and health identifiers, one of
   the identifier's keywords must appear within 60 characters before the match
   or 40 after.
3. **Check digit** — for the 10 identifiers whose issuing authority publishes
   the algorithm, a number of the right shape that fails its check digit is not
   that country's identifier. Where the algorithm is community-sourced rather
   than authority-published (`ca_sin`, `emirates_id`, `de_tax_id`, `kr_rrn`,
   `sa_national_id`) the checksum is advisory and never rejects a match.

Every pattern is asserted to compile under `NSRegularExpression`, which with
Go's RE2 bounds the portable subset the registry is written in.

Offsets in `CountryMatch` are UTF-16, because that is what
`NSRegularExpression` works in.

Still cloud-only, and not in this SDK: the near-miss fallback, the slot,
context, gravity and name layers, industry profiles, and org configuration.

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
| Passport | AB1234567 | [PASSPORT_REDACTED] |
| Driver's License | D1234567 | [DL_REDACTED] |
| Bank Account | 12345678901234 | [ACCOUNT_REDACTED] |

## Agent telemetry fields

Optional `agent_id`, `agent_role`, `session_id` and `session_turn` (an integer) travel on a `SessionContext`. They are passed through to the receipt when set and omitted when not:

```swift
let ctx = SessionContext(agentId: "planner-1", agentRole: "planner",
                         sessionId: "sess-42", sessionTurn: 3)
let result = tork.govern(text, sessionContext: ctx)   // or GovernOptions(sessionContext: ctx)
result.receipt.sessionContext?.sessionTurn            // 3
ctx.requestFields                                     // ["agent_id": ..., "session_turn": 3, ...] (set fields only)
```

## Scanning tool results

A tool result returned by an MCP server — or any external system you do not control — is untrusted input that is about to be appended to a model's context. `Tork.scanToolResult` scans it first, on-device, for PII and prompt injection:

```swift
import TorkGovernance

let tork = Tork()
let scan = tork.scanToolResult(
    ToolResultScanInput(
        toolName: "lookup_customer",
        serverUri: "mcp://crm.internal/customers",
        payload: toolResult              // whatever the server returned
    ),
    options: ToolResultScanOptions(blockOnInjection: true)
)

if scan.blocked {
    print(scan.reason!)                  // do not append anything
} else {
    appendToContext(scan.sanitized)      // PII masked in place
}

scan.findings
// [ToolResultFinding(kind: .pii, type: "email", count: 1, location: "$.content[0].text"),
//  ToolResultFinding(kind: .injection, type: "heuristic:instruction_override", count: 1, location: "$.content[0].text")]
```

There is also a standalone `scanToolResult(_:options:)` function with the same signature that returns a `ToolResultScanResult` (`sanitized`/`findings`/`blocked`/`reason`) and produces no receipt.

- **PII uses the same on-device detector as `govern`** — same patterns, same redaction labels. Matches are masked in place; the payload structure is otherwise unchanged, and a clean payload comes back untouched.
- **Injection detection is heuristic.** A conservative pattern set (`tork-injection-heuristics-v1`) covering instruction-override phrases, role reassignment, and exfiltration URLs. Every injection finding is typed `heuristic:<name>` because that is exactly what it is: a regex match over untrusted text, with false positives and false negatives, not a verified determination. Without `blockOnInjection`, matches are reported and the result is still returned; with it, `sanitized` is `nil` so no masked copy can be appended by accident.
- **Zero network calls.** The scan is pure and synchronous — no `URLSession` on the scan path.
- **Recorded on the receipt as counts only.** `receipt.toolResultScan` carries `attestedBy: "client"`, `captureMode: "edge"`, the tool name and server URI, counts by kind and type, the blocked flag, and the SDK version. It never carries the payload, a matched value, or a location path.

**This is a client-side, client-attested control.** The scan runs in your process, and the receipt says so: Tork did not execute it and cannot verify it ran at all. **Gateway-side enforcement, where a caller cannot skip the scan, is a separate and later control.** Do not read a `toolResultScan` block as proof that every tool result reaching a model was scanned; read it as a record of the scans a caller chose to run and report.

**Parity tier:** this matches Tier 1 of the JS SDK — the 10-type basic PII vocabulary (`ssn`, `credit_card`, `email`, `phone`, `address`, `ip_address`, `date_of_birth`, `passport`, `drivers_license`, `bank_account`) with JS-identical labels and redaction markers. It does not carry the Python SDK's regional/industry pattern tier.

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
