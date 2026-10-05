import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
public final class Cloudflare {
    let profile: Profile; let token: String; let transport: Transport
    public init(profile: Profile, credentials: Credentials, worker: Bool = false, transport: Transport = Network()) throws {
        self.profile = profile; self.transport = transport; self.token = try credentials.get(worker ? profile.workerCredential : profile.managementCredential)
    }
    public func call(_ method: String, path: [String], body: JSON? = nil) async throws -> JSON {
        let address = "https://api.cloudflare.com/client/v4/accounts/" + profile.accountID + "/" + path.map(S3Signer.escape).joined(separator: "/")
        var req = URLRequest(url: URL(string: address)!); req.httpMethod = method
        req.setValue("Bearer " + token, forHTTPHeaderField: "Authorization"); req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let jurisdiction = profile.jurisdiction { req.setValue(jurisdiction, forHTTPHeaderField: "cf-r2-jurisdiction") }
        req.httpBody = try body?.encoded()
        let r = try await boundedRetry(attempts: method == "GET" ? 3 : 1) { let x = try await self.transport.send(req, upload: nil); try checkHTTP(x.response); return x }
        let value = try JSONDecoder().decode(JSON.self, from: r.data)
        guard value["success"].bool == true else { throw FKError("network", "Cloudflare rejected operation; response body omitted", stage: "remote", httpStatus: r.response.statusCode, requestID: r.response.value(forHTTPHeaderField: "cf-ray")) }
        return value["result"]
    }
    public func inspectBucket(_ name: String) async throws -> JSON {
        try validateBucket(name)
        let bucket = try await call("GET", path: ["r2","buckets",name])
        let managed = try await call("GET", path: ["r2","buckets",name,"domains","managed"])
        let custom = try await call("GET", path: ["r2","buckets",name,"domains","custom"])
        return .object(["bucket":bucket, "managedDomain":managed, "customDomains":custom])
    }
    public func createBucket(_ name: String) async throws -> JSON {
        try validateBucket(name)
        do { _ = try await call("GET", path: ["r2","buckets",name]); throw FKError("collision", "Bucket exists; explicit adoption is required") }
        catch let e as FKError where e.httpStatus == 404 {}
        var body: [String:JSON] = ["name":.string(name)]
        if let j = profile.jurisdiction { body["jurisdiction"] = .string(j) }
        _ = try await call("POST", path: ["r2","buckets"], body: .object(body))
        let result = try await inspectBucket(name)
        guard result["managedDomain"]["enabled"].bool == false, (result["customDomains"]["domains"].array ?? []).isEmpty else { throw FKError("drift", "Bucket public exposure could not be excluded", stage: "verification") }
        return .object(["resource":result, "group":try .value(profile.group), "privateVerified":.bool(true)])
    }
    public func locks(_ name: String) async throws -> JSON { try await call("GET", path:["r2","buckets",name,"lock"]) }
    public func applyLocks(_ name: String, expectedDigest: String, rules: JSON) async throws -> JSON {
        try validateBucket(name)
        let current = try await locks(name)
        try require(sha256(try current.encoded()) == expectedDigest, "Lock configuration changed since review")
        try validateLockRules(rules)
        _ = try await call("PUT", path:["r2","buckets",name,"lock"], body: rules)
        let actual = try await locks(name)
        guard actual == rules else { throw FKError("drift", "Retention readback differs from approved rules", stage:"verification") }
        return .object(["configuration":actual, "verified":.bool(true), "administratorRemovable":.bool(true)])
    }
}
public func validateLockRules(_ body: JSON) throws {
    guard let rules = body["rules"].array else { throw FKError("validation", "Lock rules required") }
    try require(rules.count <= 1000, "Too many lock rules")
    var ids = Set<String>()
    for rule in rules {
        guard let id = rule["id"].string, rule["enabled"].bool == true else { throw FKError("validation", "Only enabled named lock rules are accepted") }
        try require(ids.insert(id).inserted, "Duplicate lock rule")
        let condition = rule["condition"]
        try require(["Age", "Indefinite"].contains(condition["type"].string ?? ""), "Supported retention types: Age and Indefinite")
        if condition["type"].string == "Age" {
            if case .number(let seconds) = condition["maxAgeSeconds"] { try require(seconds > 0 && seconds.rounded() == seconds, "Invalid retention duration") }
            else { throw FKError("validation", "Retention seconds required") }
        }
    }
    try require(!rules.isEmpty, "Removing all retention rules requires a separate administrative operation")
}
