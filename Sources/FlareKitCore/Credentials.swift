import Foundation
#if canImport(Security)
import Security
#endif

public struct Credentials {
    public var environment: [String: String]
    public init(environment: [String: String] = ProcessInfo.processInfo.environment) { self.environment = environment }
    public func get(_ ref: CredentialReference?) throws -> String {
        guard let ref else { throw FKError("authorization", "Required credential reference is missing", stage: "credentials") }
        try ref.validate()
        if let expiry = ref.expiresAt, expiry <= Date() { throw FKError("authorization", "Credential expired; enroll and verify a replacement", stage: "credentials") }
        switch ref.provider {
        case "environment":
            guard let value = environment[ref.reference], !value.isEmpty else { throw FKError("authorization", "Referenced environment credential is missing", stage: "credentials") }
            return value
        case "keychain":
            #if canImport(Security)
            let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "FlareKit.credentials.v1", kSecAttrAccount as String: ref.reference, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            guard status == errSecSuccess, let bytes = result as? Data, let value = String(data: bytes, encoding: .utf8) else { throw FKError("authorization", "Keychain credential unavailable; unlock or enroll it", stage: "credentials") }
            return value
            #else
            throw FKError("unsupported", "Keychain provider requires macOS", stage: "credentials")
            #endif
        default: throw FKError("unsupported", "Hardware provider is not installed; software fallback is forbidden", stage: "credentials")
        }
    }
    public func enroll(reference: String, secret: Data) throws {
        try CredentialReference(provider: "keychain", reference: reference, expiresAt: nil).validate()
        try require(!secret.isEmpty && secret.count <= 65536, "Invalid secret size")
        #if canImport(Security)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "FlareKit.credentials.v1", kSecAttrAccount as String: reference]
        // Replacement is explicit; enrollment cannot silently overwrite an identity.
        var add = query; add[kSecValueData as String] = secret
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw FKError(status == errSecDuplicateItem ? "collision" : "authorization", "Credential enrollment failed; existing credentials are preserved", stage: "credentials") }
        #else
        throw FKError("unsupported", "Enrollment requires macOS Keychain", stage: "credentials")
        #endif
    }
}
