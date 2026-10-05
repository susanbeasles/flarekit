import Foundation

public enum JSON: Codable, Equatable {
    case object([String: JSON]), array([JSON]), string(String), number(Double), bool(Bool), null
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([String: JSON].self) { self = .object(v) }
        else if let v = try? c.decode([JSON].self) { self = .array(v) }
        else { self = .number(try c.decode(Double.self)) }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .object(let x): try c.encode(x)
        case .array(let x): try c.encode(x)
        case .string(let x): try c.encode(x)
        case .number(let x): try c.encode(x)
        case .bool(let x): try c.encode(x)
        case .null: try c.encodeNil()
        }
    }
    public subscript(_ key: String) -> JSON { if case .object(let x) = self { return x[key] ?? .null }; return .null }
    public var string: String? { if case .string(let x) = self { return x }; return nil }
    public var array: [JSON]? { if case .array(let x) = self { return x }; return nil }
    public var object: [String: JSON]? { if case .object(let x) = self { return x }; return nil }
    public var bool: Bool? { if case .bool(let x) = self { return x }; return nil }
    public func decode<T: Decodable>(_ type: T.Type) throws -> T { let d=JSONDecoder();d.dateDecodingStrategy = .iso8601;return try d.decode(type, from: encoded()) }
    public func encoded() throws -> Data { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return try e.encode(self) }
    public static func value<T: Encodable>(_ x: T) throws -> JSON { let e=JSONEncoder();e.dateEncodingStrategy = .iso8601;return try JSONDecoder().decode(JSON.self, from: e.encode(x)) }
}

public enum Operation: String, Codable, CaseIterable {
    case bucketInspect = "storage.bucket.inspect", bucketCreate = "storage.bucket.create"
    case retentionInspect = "storage.retention.inspect", retentionApply = "storage.retention.apply"
    case objectUpload = "storage.object.upload", objectDownload = "storage.object.download"
    case objectList = "storage.object.list", objectInspect = "storage.object.inspect", objectVerify = "storage.object.verify"
    case multipartUpload = "storage.multipart.upload", multipartAbort = "storage.multipart.abort"
    case workerPlan = "worker.plan", workerApply = "worker.apply", workerInspect = "worker.inspect"
    case workerPromote = "worker.promote", workerSecretStage = "worker.secret.stage"
    case gitCapture = "archive.git.capture", gitVerify = "archive.git.verify", gitRestore = "archive.git.restore"
    case vaultInitialize = "archive.vault.initialize", snapshotCreate = "archive.snapshot.create"
    case snapshotRestore = "archive.snapshot.restore", snapshotPublish = "archive.snapshot.publish"
    case snapshotFetch = "archive.snapshot.fetch", snapshotVerify = "archive.snapshot.verify"
    case credentialEnroll = "credential.enroll", configurationValidate = "configuration.validate"
}
public struct Request: Codable {
    public let schemaVersion: Int
    public let requestID: String
    public let operation: Operation
    public let profile: String?
    public let parameters: JSON
    public init(operation: Operation, profile: String? = nil, parameters: JSON, requestID: String = UUID().uuidString) {
        self.schemaVersion = 1; self.requestID = requestID; self.operation = operation; self.profile = profile; self.parameters = parameters
    }
}
public struct Result: Codable {
    public let schemaVersion = 1
    public let requestID: String
    public let operation: Operation
    public let status: String
    public let output: JSON
}
public struct FKError: Error, Codable {
    public let code: String
    public let stage: String
    public let message: String
    public let retryable: Bool
    public let httpStatus: Int?
    public let requestID: String?
    public init(_ code: String, _ message: String, stage: String = "validation", retryable: Bool = false, httpStatus: Int? = nil, requestID: String? = nil) {
        self.code = code; self.message = message; self.stage = stage; self.retryable = retryable; self.httpStatus = httpStatus; self.requestID = requestID
    }
    public var exitCode: Int32 {
        switch code { case "authorization": return 3; case "collision": return 4; case "integrity": return 5; case "drift": return 6; case "network": return 7; case "unsupported": return 8; default: return 2 }
    }
}
public func require(_ condition: Bool, _ message: String) throws { if !condition { throw FKError("validation", message) } }

public struct CredentialReference: Codable, Equatable {
    public let provider: String
    public let reference: String
    public let expiresAt: Date?
}
public struct Group: Codable, Equatable {
    public let project: String
    public let environment: String
    public let purpose: String
    public let contentType: String
}
public struct Profile: Codable {
    public let accountID: String
    public let jurisdiction: String?
    public let managementCredential: CredentialReference?
    public let workerCredential: CredentialReference?
    public let accessKeyID: CredentialReference?
    public let secretAccessKey: CredentialReference?
    public let bucket: String?
    public let group: Group
    public let allowedOperations: [Operation]
    public let allowedWorkerBucketNames: [String]?
    public let allowedWorkerSecretReferences: [String]?
}
public struct Configuration: Codable {
    public let schemaVersion: Int
    public let profiles: [String: Profile]
    public let vaults: [VaultConfiguration]
    public func validate() throws {
        try require(schemaVersion == 1, "Unsupported configuration schema")
        for (name, p) in profiles {
            try require(!name.isEmpty && p.accountID.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil, "Invalid profile or account ID")
            try require([nil, "eu", "us", "fedramp"].contains(p.jurisdiction), "Unsupported jurisdiction")
            if let b = p.bucket { try validateBucket(b) }
            try require(!p.group.project.isEmpty && !p.group.environment.isEmpty && !p.group.purpose.isEmpty, "Incomplete resource group")
            for value in [p.group.project,p.group.environment,p.group.purpose,p.group.contentType] { try require(value.range(of:"^[A-Za-z0-9][A-Za-z0-9_./-]{0,127}$",options:.regularExpression) != nil,"Resource group values must be safe nonsecret metadata") }
            for ref in [p.managementCredential, p.workerCredential, p.accessKeyID, p.secretAccessKey].compactMap({ $0 }) { try ref.validate() }
        }
        for v in vaults { try v.validate() }
    }
    public func selected(_ name: String?, operation: Operation) throws -> Profile {
        try require(name != nil, "Select an explicit profile")
        guard let p = profiles[name!] else { throw FKError("validation", "Unknown profile") }
        try require(p.allowedOperations.contains(operation), "Operation is not allowed by this profile")
        return p
    }
}
public func validateBucket(_ value: String) throws {
    try require(value.range(of: "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", options: .regularExpression) != nil, "Invalid bucket name")
}
extension CredentialReference {
    public func validate() throws {
        try require(["environment", "keychain", "hardware"].contains(provider), "Unsupported credential provider")
        try require(reference.range(of: "^[A-Za-z0-9_.:-]{1,128}$", options: .regularExpression) != nil, "Invalid credential reference")
    }
}

// Reserved V1 recovery contracts. No replica adapter or encrypted writer is implied.
public struct Destination: Codable, Equatable {
    public let id: String
    public let provider: String
    public let role: String
    public let credentialReference: String
    public let resource: String
    public let independentRestoreRequired: Bool
}
public struct VerificationPolicy: Codable {
    public let mode: String
    public let maximumReadBytesPerRun: UInt64
    public let maximumRequestsPerRun: UInt64
    public let intervalSeconds: UInt64
    public let minimumSampleCount: UInt64
}
public struct VaultConfiguration: Codable {
    public let id: String
    public let encryptionFormat: String // "pending-review" until approved
    public let deduplicationScope: String
    public let evictPrimaryAfterReplication: Bool
    public let recoveryReferences: [String]
    public let destinations: [Destination]
    public let verification: VerificationPolicy
    public func validate() throws {
        try require(!id.isEmpty && deduplicationScope == "vault", "Deduplication must be vault scoped")
        try require(!evictPrimaryAfterReplication, "Primary eviction is forbidden")
        try require(destinations.filter { $0.role == "primary" && $0.provider == "r2" }.count == 1, "Exactly one R2 primary required")
        try require(Set(destinations.map { $0.id }).count == destinations.count, "Duplicate destination ID")
        for d in destinations {
            try require(["r2", "b2", "google-drive"].contains(d.provider) && ["primary", "replica"].contains(d.role), "Invalid replica contract")
            try require(d.independentRestoreRequired, "Every destination requires independent restore coverage")
        }
        try require(["full", "metadata", "sampled"].contains(verification.mode), "Invalid verification policy")
    }
}
public struct DestinationVerification: Codable {
    public let destinationID: String
    public let mode: String
    public let checkedAt: Date
    public let checkedBytes: UInt64
    public let checkedObjects: UInt64
    public let totalObjects: UInt64
    public let selectionSeed: String?
    public let manifestDigest: String
    public let independentRestore: String // pending, verified, failed
    public let status: String
}
