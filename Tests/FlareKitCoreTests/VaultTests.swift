import XCTest
@testable import FlareKitCore
import Foundation

final class VaultTests:XCTestCase {
    func testCrossSnapshotReuseAndIndependentStandardAgeRecovery() throws {
        let env=ProcessInfo.processInfo.environment
        guard let age=env["FK_TEST_AGE"],let keygen=env["FK_TEST_AGE_KEYGEN"] else { throw XCTSkip("Set pinned age test executable paths") }
        let tools=AgeTools(age:URL(fileURLWithPath:age),keygen:URL(fileURLWithPath:keygen))
        let root=try privateDirectory(); defer { try? FileManager.default.removeItem(at:root) }
        let first=root.appendingPathComponent("primary"); let second=root.appendingPathComponent("recovery")
        try tools.run(tools.keygen,[],output:first); try tools.run(tools.keygen,[],output:second)
        let primary=try String(contentsOf:first); let recovery=try String(contentsOf:second)
        let credentials=Credentials(environment:["PRIMARY":primary,"RECOVERY":recovery])
        let primaryRef=CredentialReference(provider:"environment",reference:"PRIMARY",expiresAt:nil)
        let recoveryRef=CredentialReference(provider:"environment",reference:"RECOVERY",expiresAt:nil)
        let vaultPath=root.appendingPathComponent("vault"); let vault=AgeVault(root:vaultPath,tools:tools,credentials:credentials)
        _=try vault.initialize(primary:primaryRef,recovery:recoveryRef)
        let source=root.appendingPathComponent("source"); try FileManager.default.createDirectory(at:source,withIntermediateDirectories:false)
        try Data("reused across snapshots".utf8).write(to:source.appendingPathComponent("a"))
        let one=try vault.create(source:source,identityRef:primaryRef)
        try Data("new content".utf8).write(to:source.appendingPathComponent("b"))
        let two=try vault.create(source:source,identityRef:primaryRef)
        XCTAssertEqual(two["reusedChunks"],.number(1)); XCTAssertEqual(two["newChunks"],.number(1))
        // Recovery must not need the local dedup index or primary identity.
        try FileManager.default.removeItem(at:vaultPath.appendingPathComponent("indexes"))
        try FileManager.default.removeItem(at:vaultPath.appendingPathComponent("index-head.json"))
        let recoveryVault=AgeVault(root:vaultPath,tools:tools,credentials:Credentials(environment:["RECOVERY":recovery]))
        let restore=root.appendingPathComponent("restored")
        _=try recoveryVault.restore(snapshotID:two["snapshotID"].string!,destination:restore,expectedManifestDigest:two["manifestDigest"].string!,identityRef:recoveryRef)
        XCTAssertEqual(try Data(contentsOf:restore.appendingPathComponent("a")),Data("reused across snapshots".utf8))
        XCTAssertEqual(try Data(contentsOf:restore.appendingPathComponent("b")),Data("new content".utf8))
        // Explicit use of the stock age tool, independently of FlareKit's restore wrapper.
        let manifest=root.appendingPathComponent("standard-age-manifest")
        try tools.run(tools.age,["-d","-i","-",vaultPath.appendingPathComponent("snapshots/"+one["snapshotID"].string!+".json.age").path],input:Data(recovery.utf8),output:manifest)
        let m=try JSONDecoder().decode(SnapshotManifest.self,from:Data(contentsOf:manifest))
        XCTAssertEqual(m.files[0].path,"a")
        let standard=root.appendingPathComponent("standard-age-content")
        try tools.run(tools.age,["-d","-i","-",vaultPath.appendingPathComponent("blobs/sha256/"+m.files[0].chunks[0].ciphertextSHA256+".age").path],input:Data(recovery.utf8),output:standard)
        XCTAssertEqual(try Data(contentsOf:standard),Data("reused across snapshots".utf8))
        let cost=try vault.verify(snapshotID:two["snapshotID"].string!,expectedManifestDigest:two["manifestDigest"].string!,mode:"sampled",byteBudget:0,requestBudget:10,seed:"repeatable")
        XCTAssertEqual(cost["completeCoverage"].bool,false); XCTAssertEqual(cost["checkedBytes"].string,"0")
        let c=try vault.completion(snapshotID:two["snapshotID"].string!,expectedManifestDigest:two["manifestDigest"].string!)
        let blob=vaultPath.appendingPathComponent("blobs/sha256/"+c.blobCiphertextSHA256[0]+".age")
        var bytes=try Data(contentsOf:blob); bytes[bytes.count-1]^=1; try bytes.write(to:blob)
        XCTAssertThrowsError(try recoveryVault.restore(snapshotID:two["snapshotID"].string!,destination:root.appendingPathComponent("tampered-restore"),expectedManifestDigest:two["manifestDigest"].string!,identityRef:recoveryRef))
        XCTAssertFalse(FileManager.default.fileExists(atPath:root.appendingPathComponent("tampered-restore").path))
    }
}
