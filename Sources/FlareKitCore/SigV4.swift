import Foundation
import Crypto
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct S3Signer {
    public let accessKey: String
    public let secretKey: String
    public init(accessKey: String, secretKey: String) { self.accessKey = accessKey; self.secretKey = secretKey }
    public static func escape(_ value: String) -> String {
        value.utf8.map { b in
            ((b >= 65 && b <= 90) || (b >= 97 && b <= 122) || (b >= 48 && b <= 57) || [45,46,95,126].contains(b)) ? String(UnicodeScalar(b)) : String(format: "%%%02X", b)
        }.joined()
    }
    public static func hmac(_ key: Data, _ value: String) -> Data { Data(HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: SymmetricKey(data: key))) }
    public func sign(method: String, endpoint: String, path: [String], query: [(String,String)] = [], headers: [String:String] = [:], payloadHash: String, now: Date = Date()) throws -> URLRequest {
        let uri = "/" + path.map(Self.escape).joined(separator: "/")
        let escaped: [(String,String)] = query.map { (Self.escape($0.0),Self.escape($0.1)) }
        let ordered = escaped.sorted { a,b in a.0 == b.0 ? a.1 < b.1 : a.0 < b.0 }
        let canonicalQuery = ordered.map { $0.0 + "=" + $0.1 }.joined(separator: "&")
        guard let url = URL(string: endpoint + uri + (canonicalQuery.isEmpty ? "" : "?" + canonicalQuery)), let host = url.host else { throw FKError("validation", "Invalid S3 URL") }
        let fmt = DateFormatter(); fmt.locale = Locale(identifier: "en_US_POSIX"); fmt.timeZone = TimeZone(secondsFromGMT: 0); fmt.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        let timestamp = fmt.string(from: now); let day = String(timestamp.prefix(8)); let scope = day + "/auto/s3/aws4_request"
        var all = headers.reduce(into: [String:String]()) { $0[$1.key.lowercased()] = $1.value.trimmingCharacters(in: .whitespacesAndNewlines) }
        all["host"] = host; all["x-amz-date"] = timestamp; all["x-amz-content-sha256"] = payloadHash
        let names = all.keys.sorted(); let signed = names.joined(separator: ";")
        let canonicalHeaders = names.map { $0 + ":" + all[$0]! + "\n" }.joined()
        let canonical = [method, uri, canonicalQuery, canonicalHeaders, signed, payloadHash].joined(separator: "\n")
        let toSign = "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + sha256(Data(canonical.utf8))
        let key = Self.hmac(Self.hmac(Self.hmac(Self.hmac(Data(("AWS4"+secretKey).utf8),day),"auto"),"s3"),"aws4_request")
        let signature = Self.hmac(key,toSign).map { String(format: "%02x", $0) }.joined()
        var request = URLRequest(url: url); request.httpMethod = method
        for (k,v) in all { request.setValue(v, forHTTPHeaderField: k) }
        request.setValue("AWS4-HMAC-SHA256 Credential=\(accessKey)/\(scope), SignedHeaders=\(signed), Signature=\(signature)", forHTTPHeaderField: "Authorization")
        return request
    }
}
