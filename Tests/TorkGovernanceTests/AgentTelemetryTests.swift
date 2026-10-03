import XCTest
@testable import TorkGovernance

/// Optional agent telemetry fields on the governance call: `agent_id`,
/// `agent_role`, `session_id`, `session_turn` (Int). Passed through when set,
/// omitted when not.
final class AgentTelemetryTests: XCTestCase {

    func testFieldsPassThroughGovern() {
        let ctx = SessionContext(agentId: "a1", agentRole: "worker", sessionId: "s1", sessionTurn: 3)
        let r = Tork().govern("My SSN is 123-45-6789", sessionContext: ctx)
        XCTAssertEqual(r.sessionContext, ctx)
        XCTAssertEqual(r.receipt.sessionContext?.agentId, "a1")
        XCTAssertEqual(r.receipt.sessionContext?.agentRole, "worker")
        XCTAssertEqual(r.receipt.sessionContext?.sessionId, "s1")
        XCTAssertEqual(r.receipt.sessionContext?.sessionTurn, 3)
    }

    func testFieldsPassThroughGovernOptions() {
        let ctx = SessionContext(agentId: "a2", sessionTurn: 1)
        let r = Tork().govern("hello", options: GovernOptions(sessionContext: ctx))
        XCTAssertEqual(r.sessionContext, ctx)
    }

    func testOmittedWhenNotSet() {
        let r = Tork().govern("hello")
        XCTAssertNil(r.sessionContext)
        XCTAssertNil(r.receipt.sessionContext)
        XCTAssertTrue(SessionContext().requestFields.isEmpty)
    }

    func testRequestFieldsUseWireNamesAndOmitUnset() {
        let f = SessionContext(agentId: "a1", sessionTurn: 2).requestFields
        XCTAssertEqual(Set(f.keys), ["agent_id", "session_turn"])
        XCTAssertEqual(f["agent_id"] as? String, "a1")
        XCTAssertEqual(f["session_turn"] as? Int, 2)
    }

    func testJSONEncodingIsSnakeCaseIntegerTurnAndOmitsNil() throws {
        let full = try JSONSerialization.jsonObject(with: JSONEncoder().encode(
            SessionContext(agentId: "a", agentRole: "judge", sessionId: "s", sessionTurn: 7))) as! [String: Any]
        XCTAssertEqual(Set(full.keys), ["agent_id", "agent_role", "session_id", "session_turn"])
        XCTAssertEqual(full["session_turn"] as? Int, 7)

        let empty = try JSONSerialization.jsonObject(with: JSONEncoder().encode(SessionContext())) as! [String: Any]
        XCTAssertTrue(empty.isEmpty)
    }
}
