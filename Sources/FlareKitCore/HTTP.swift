import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct HTTPReply { public let data: Data; public let response: HTTPURLResponse }
public protocol Transport {
    func send(_ request: URLRequest, upload: URL?) async throws -> HTTPReply
    func download(_ request: URLRequest) async throws -> (URL, HTTPURLResponse)
}
private final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
public final class Network: Transport {
    private let delegate = NoRedirect()
    private lazy var session: URLSession = {
        let c = URLSessionConfiguration.ephemeral; c.timeoutIntervalForRequest = 60; c.timeoutIntervalForResource = 3600; c.httpCookieStorage = nil; c.urlCredentialStorage = nil
        return URLSession(configuration: c, delegate: delegate, delegateQueue: nil)
    }()
    public init() {}
    public func send(_ request: URLRequest, upload: URL? = nil) async throws -> HTTPReply {
        do {
            let (data, r) = try await (upload != nil ? session.upload(for: request, fromFile: upload!) : session.data(for: request))
            guard let response = r as? HTTPURLResponse else { throw FKError("network", "Missing HTTP response", stage: "transport") }
            return HTTPReply(data: data, response: response)
        } catch let e as FKError { throw e }
        catch { throw FKError("network", "Transport failed; credentials and response bodies omitted", stage: "transport", retryable: true) }
    }
    public func download(_ request: URLRequest) async throws -> (URL, HTTPURLResponse) {
        do {
            let (url, r) = try await session.download(for: request)
            guard let response = r as? HTTPURLResponse else { throw FKError("network", "Missing HTTP response") }
            return (url, response)
        } catch { throw FKError("network", "Download failed", stage: "transport", retryable: true) }
    }
}
public func checkHTTP(_ r: HTTPURLResponse) throws {
    guard (200..<300).contains(r.statusCode) else {
        let s = r.statusCode
        let code = [401,403].contains(s) ? "authorization" : [409,412].contains(s) ? "collision" : s == 404 ? "not-found" : "network"
        throw FKError(code, "Remote request rejected; check permissions, target and retention", stage: "remote", retryable: s == 429 || s >= 500, httpStatus: s, requestID: r.value(forHTTPHeaderField: "cf-ray") ?? r.value(forHTTPHeaderField: "x-amz-request-id"))
    }
}
public func boundedRetry<T>(attempts: Int = 3, action: () async throws -> T) async throws -> T {
    for n in 0..<attempts {
        do { return try await action() }
        catch let e as FKError where e.retryable && n + 1 < attempts {
            try await Task.sleep(nanoseconds: UInt64(250_000_000 * (1 << n)) + UInt64.random(in: 0...100_000_000))
        }
    }
    throw FKError("network", "Retry budget exhausted", stage: "transport")
}
