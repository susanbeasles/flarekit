import Foundation
import FoundationXML
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct ObjectInput: Codable {
    public let key: String?
    public let file: String?
    public let destination: String?
    public let expectedSHA256: String?
    public let prefix: String?
    public let continuationToken: String?
    public let verification: String?
}
final class XMLValues: NSObject, XMLParserDelegate {
    var values: [String:[String]] = [:]; var entries: [[String:String]] = []
    private var stack: [String] = []; private var text = ""; private var entry: [String:String]?
    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String:String]) { stack.append(name); text = ""; if name == "Contents" || name == "Part" { entry = [:] } }
    func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }
    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        values[name,default: []].append(text)
        if entry != nil { entry?[name] = text }
        if name == "Contents" || name == "Part" { entries.append(entry ?? [:]); entry = nil }
        _ = stack.popLast(); text = ""
    }
    static func read(_ data: Data) throws -> XMLValues {
        try require(data.count <= 16 * 1024 * 1024, "XML response exceeds limit")
        // External entities and DTDs are never accepted.
        let text = String(decoding: data, as: UTF8.self)
        try require(!text.contains("<!DOCTYPE") && !text.contains("<!ENTITY"), "Unsafe XML response")
        let result = XMLValues(); let parser = XMLParser(data: data); parser.shouldResolveExternalEntities = false; parser.delegate = result
        guard parser.parse() else { throw FKError("integrity", "Malformed storage XML", stage: "response") }; return result
    }
}
public final class R2 {
    let profile: Profile; let signer: S3Signer; let transport: Transport
    var endpoint: String {
        "https://" + profile.accountID + (profile.jurisdiction.map { "." + $0 } ?? "") + ".r2.cloudflarestorage.com"
    }
    public init(profile: Profile, credentials: Credentials, transport: Transport = Network()) throws {
        self.profile = profile; self.transport = transport
        signer = try S3Signer(accessKey: credentials.get(profile.accessKeyID), secretKey: credentials.get(profile.secretAccessKey))
    }
    func request(_ method: String, key: String? = nil, query: [(String,String)] = [], headers: [String:String] = [:], hash: String = sha256(Data())) throws -> URLRequest {
        guard let bucket = profile.bucket else { throw FKError("validation", "Profile has no bucket") }
        let segments = [bucket] + (key.map { $0.components(separatedBy: "/") } ?? [])
        return try signer.sign(method: method, endpoint: endpoint, path: segments, query: query, headers: headers, payloadHash: hash)
    }
    func send(_ req: URLRequest, file: URL? = nil, retry: Bool = true) async throws -> HTTPReply {
        let action = { let r = try await self.transport.send(req, upload: file); try checkHTTP(r.response); return r }
        return try await boundedRetry(attempts: retry ? 3 : 1, action: action)
    }
    public func inspect(key: String) async throws -> JSON {
        let r = try await send(request("HEAD", key: key))
        return .object(["key": .string(key), "size": .string(r.response.value(forHTTPHeaderField: "content-length") ?? "unknown"), "etag": .string(r.response.value(forHTTPHeaderField: "etag") ?? "unknown"), "declaredSHA256": .string(r.response.value(forHTTPHeaderField: "x-amz-meta-sha256") ?? "unknown"), "verification": .string("metadata"), "contentVerified": .bool(false)])
    }
    public func list(prefix: String, token: String?) async throws -> JSON {
        var q = [("list-type","2"),("prefix",prefix),("max-keys","1000")]
        if let token { q.append(("continuation-token",token)) }
        let r = try await send(request("GET", query: q)); let xml = try XMLValues.read(r.data)
        return .object(["objects": .array(xml.entries.map { .object(["key": .string($0["Key"] ?? ""), "size": .string($0["Size"] ?? ""), "etag": .string($0["ETag"] ?? "")]) }), "continuationToken": xml.values["NextContinuationToken"]?.first.map(JSON.string) ?? .null, "truncated": .bool(xml.values["IsTruncated"]?.first == "true")])
    }
    public func verify(key: String, expected: String) async throws -> JSON {
        try require(expected.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil, "Expected SHA-256 required")
        let (url, response) = try await boundedRetry { let result = try await self.transport.download(self.request("GET", key: key)); try checkHTTP(result.1); return result }
        defer { try? FileManager.default.removeItem(at: url) }
        let actual = try hashFile(url)
        guard actual.digest == expected else { throw FKError("integrity", "Downloaded content checksum mismatch", stage: "verification") }
        return .object(["key": .string(key), "sha256": .string(actual.digest), "checkedBytes": .string(String(actual.size)), "verification": .string("full"), "contentVerified": .bool(true)])
    }
    public func download(key: String, destination: URL, expected: String) async throws -> JSON {
        try require(!FileManager.default.fileExists(atPath: destination.path), "Restore destination already exists")
        try require(expected.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil, "Expected SHA-256 required")
        let (url, response) = try await boundedRetry { let result = try await self.transport.download(self.request("GET", key: key)); try checkHTTP(result.1); return result }
        defer { try? FileManager.default.removeItem(at: url) }
        let actual = try hashFile(url)
        guard actual.digest == expected else { throw FKError("integrity", "Downloaded content checksum mismatch", stage: "verification") }
        // Copy never overwrites and preserves a private destination file.
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        try FileManager.default.copyItem(at: url, to: destination)
        return .object(["key": .string(key), "sha256": .string(actual.digest), "checkedBytes": .string(String(actual.size)), "verification": .string("full"), "contentVerified": .bool(true)])
    }
    public func upload(key: String, source: URL, verification: String) async throws -> JSON {
        try require(!key.isEmpty && key.utf8.count <= 1024 && !key.contains("\0"), "Invalid object key")
        try require(["full","metadata"].contains(verification), "Upload verification must be full or metadata")
        let values = try source.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        try require(values.isRegularFile == true && values.isSymbolicLink != true, "Upload source must be a regular file")
        // Capture bytes once so the signed body cannot diverge from a changing source.
        let stage = try privateDirectory(); defer { try? FileManager.default.removeItem(at: stage) }
        let file = stage.appendingPathComponent("payload")
        try FileManager.default.copyItem(at: source, to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let hash = try hashFile(file)
        try require(hash.size <= 5 * 1024 * 1024 * 1024, "Single PUT limit exceeded; multipart upload is not released yet")
        let req = try request("PUT", key: key, headers: ["if-none-match":"*", "x-amz-meta-sha256": hash.digest, "content-type":"application/octet-stream", "x-amz-meta-fk-project":profile.group.project,"x-amz-meta-fk-environment":profile.group.environment,"x-amz-meta-fk-purpose":profile.group.purpose,"x-amz-meta-fk-content-type":profile.group.contentType], hash: hash.digest)
        // On an uncertain result do not blindly retry a create. Read and verify the target.
        do { _ = try await send(req, file: file, retry: false) }
        catch let e as FKError where e.retryable {
            do { return try await verify(key: key, expected: hash.digest) }
            catch { throw FKError("network", "Upload outcome uncertain; verify target before another upload", stage: "upload", retryable: false) }
        }
        if verification == "full" { return try await verify(key: key, expected: hash.digest) }
        let readback = try await inspect(key: key)
        try require(readback["declaredSHA256"].string == hash.digest && readback["size"].string == String(hash.size), "Upload metadata readback mismatch")
        return .object(["key": .string(key), "sha256": .string(hash.digest), "size": .string(String(hash.size)), "verification": .string("metadata"), "contentVerified": .bool(false), "checkedBytes": .string("0")])
    }
}
