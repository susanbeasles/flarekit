import XCTest
@testable import FlareKitCore
import Foundation

final class WorkerBindingTests: XCTestCase {
    func json(_ text: String) throws -> JSON { try JSONDecoder().decode(JSON.self,from:Data(text.utf8)) }
    func config() throws -> JSON {
        try json("""
        {"name":"trustless-injector","main":"private-injector.mjs","compatibility_date":"2026-08-08","workers_dev":false,
        "durable_objects":{"bindings":[{"name":"STATE","class_name":"BrokerCoordinator","script_name":"trustless-gateway"}]},
        "services":[{"binding":"VAULT","service":"trustless-vault","entrypoint":"VaultResolution"}]}
        """)
    }
    func profile(allowed: Bool) throws -> Profile {
        var fields=try json("""
        {"accountID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","group":{"project":"fixture","environment":"test","purpose":"bindings","contentType":"binary"},"allowedOperations":["worker.plan"]}
        """).object!
        if allowed {
            fields["allowedWorkerServiceNames"] = .array([.string("trustless-vault")])
            fields["allowedWorkerDurableObjectScriptNames"] = .array([.string("trustless-gateway")])
        }
        return try JSON.object(fields).decode(Profile.self)
    }
    func readback() throws -> [JSON] {
        try json("""
        [{"name":"STATE","type":"durable_object_namespace","class_name":"BrokerCoordinator","script_name":"trustless-gateway","namespace_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {"name":"VAULT","type":"service","service":"trustless-vault","entrypoint":"VaultResolution"}]
        """).array!
    }
    func testExplicitProfileGrantsRequired() throws {
        let config=try config()
        XCTAssertNoThrow(try validateWorkerConfig(config,account:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
        XCTAssertThrowsError(try validateWorkerPrivateBindingAuthority(config,profile:profile(allowed:false)))
        XCTAssertNoThrow(try validateWorkerPrivateBindingAuthority(config,profile:profile(allowed:true)))
        var changed=config.object!
        changed["services"] = try json(#"[{"binding":"VAULT","service":"other-vault","entrypoint":"VaultResolution"}]"#)
        XCTAssertThrowsError(try validateWorkerPrivateBindingAuthority(.object(changed),profile:profile(allowed:true)))
        changed=config.object!
        changed["durable_objects"] = try json(#"{"bindings":[{"name":"STATE","class_name":"BrokerCoordinator","script_name":"other-gateway"}]}"#)
        XCTAssertThrowsError(try validateWorkerPrivateBindingAuthority(.object(changed),profile:profile(allowed:true)))
    }
    func testReadbackRejectsWrongEntrypointClassOrExternalScript() throws {
        let config=try config(), bindings=try readback()
        XCTAssertNoThrow(try verifyWorkerPrivateBindings(config,bindings:bindings))
        for (index,key,value) in [(1,"entrypoint","VaultAdministration"),(0,"class_name","OtherCoordinator"),(0,"script_name","other-gateway")] {
            var changed=bindings, fields=changed[index].object!
            fields[key] = .string(value); changed[index] = .object(fields)
            XCTAssertThrowsError(try verifyWorkerPrivateBindings(config,bindings:changed))
        }
        XCTAssertThrowsError(try verifyWorkerPrivateBindings(config,bindings:[]))
    }
    func testServiceConfigurationRejectsUnexpectedFields() throws {
        var fields=try config().object!
        fields["services"] = try json(#"[{"binding":"VAULT","service":"trustless-vault","environment":"production"}]"#)
        XCTAssertThrowsError(try validateWorkerConfig(.object(fields),account:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
        fields["services"] = .object([:])
        XCTAssertThrowsError(try validateWorkerConfig(.object(fields),account:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    }
}
