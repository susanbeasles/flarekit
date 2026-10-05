import XCTest
@testable import FlareKitCore
import Foundation
#if canImport(Security)
import Security
#endif

final class KeychainTests: XCTestCase {
    func testTemporaryCredentialRoundTripAndDuplicatePreservesOriginal() throws {
        #if canImport(Security)
        guard ProcessInfo.processInfo.environment["FK_TEST_KEYCHAIN"] == "1" else {
            throw XCTSkip("Opt in with ./scripts/check --keychain")
        }
        let reference = "fk-test-" + UUID().uuidString
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "FlareKit.credentials.v1", kSecAttrAccount as String: reference]
        defer {
            let status = SecItemDelete(query as CFDictionary)
            XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound, "Temporary Keychain item cleanup failed")
        }
        let credentials = Credentials(environment: [:])
        let ref = CredentialReference(provider: "keychain", reference: reference, expiresAt: nil)
        XCTAssertThrowsError(try credentials.get(ref))
        let value = "synthetic-credential-" + UUID().uuidString
        try credentials.enroll(reference: reference, secret: Data(value.utf8))
        XCTAssertEqual(try credentials.get(ref), value)
        XCTAssertThrowsError(try credentials.enroll(reference: reference, secret: Data("replacement".utf8))) {
            XCTAssertEqual(($0 as? FKError)?.code, "collision")
        }
        XCTAssertEqual(try credentials.get(ref), value)
        #else
        throw XCTSkip("macOS Keychain validation requires macOS")
        #endif
    }
}
