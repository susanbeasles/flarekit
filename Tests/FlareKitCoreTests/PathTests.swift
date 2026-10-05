import XCTest
@testable import FlareKitCore
import Foundation

final class PathTests: XCTestCase {
    func testDirectoryAliasesTrailingSlashAndFinalSymlink() throws {
        let temp=try privateDirectory()
        defer { try? FileManager.default.removeItem(at:temp) }
        let root=temp.appendingPathComponent("source",isDirectory:true)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false)
        let file=root.appendingPathComponent("payload")
        try Data("fixture".utf8).write(to:file)
        let alias=temp.appendingPathComponent("alias",isDirectory:true)
        try FileManager.default.createSymbolicLink(at:alias,withDestinationURL:root)
        XCTAssertEqual(try relativeEntryPath(file,under:alias),"payload")
        XCTAssertEqual(try relativeEntryPath(alias.appendingPathComponent("payload"),under:root),"payload")
        let link=root.appendingPathComponent("external-link")
        try FileManager.default.createSymbolicLink(at:link,withDestinationURL:temp.appendingPathComponent("outside"))
        XCTAssertEqual(try relativeEntryPath(link,under:root),"external-link")
        XCTAssertThrowsError(try relativeEntryPath(temp.appendingPathComponent("outside"),under:root))
        // A similarly named sibling is not contained by a string prefix.
        let sibling=temp.appendingPathComponent("source-other",isDirectory:true)
        try FileManager.default.createDirectory(at:sibling,withIntermediateDirectories:false)
        XCTAssertThrowsError(try relativeEntryPath(sibling.appendingPathComponent("payload"),under:root))
    }
}
