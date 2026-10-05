import Foundation
import Crypto

public func sha256(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
public func hashFile(_ url: URL) throws -> (digest: String, size: UInt64) {
    let f = try FileHandle(forReadingFrom: url); defer { try? f.close() }
    var h = SHA256(); var size: UInt64 = 0
    while let b = try f.read(upToCount: 1024 * 1024), !b.isEmpty { h.update(data: b); size += UInt64(b.count) }
    return (h.finalize().map { String(format: "%02x", $0) }.joined(), size)
}
public func privateDirectory(parent: URL = FileManager.default.temporaryDirectory) throws -> URL {
    let url = parent.appendingPathComponent("fk-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]); return url
}
public func writePrivate(_ bytes: Data, to url: URL) throws {
    try bytes.write(to: url, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}
public func safeRelative(_ path: String) throws {
    try require(!path.isEmpty && !path.hasPrefix("/") && !path.contains("\\") && !path.contains("\0"), "Unsafe relative path")
    try require(!path.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." || $0.isEmpty }), "Unsafe relative path")
}
