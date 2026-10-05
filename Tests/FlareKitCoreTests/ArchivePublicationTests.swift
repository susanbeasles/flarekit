import XCTest
@testable import FlareKitCore
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class ObjectStoreTransport:Transport {
    var objects:[String:(Data,String)]=[:]
    var failManifest=false
    func key(_ request:URLRequest)->String { request.url!.path.components(separatedBy:"/").dropFirst(2).joined(separator:"/") }
    func send(_ r:URLRequest,upload:URL?) async throws -> HTTPReply {
        let k=key(r); var status=200
        if r.httpMethod=="PUT" {
            if failManifest && k.hasSuffix(".json.age") { status=503 }
            else if objects[k] != nil { status=412 }
            else { objects[k]=(try Data(contentsOf:upload!),r.value(forHTTPHeaderField:"x-amz-meta-sha256")!) }
        } else if objects[k]==nil { status=404 }
        let object=objects[k]
        let headers=object.map{["content-length":String($0.0.count),"x-amz-meta-sha256":$0.1]} ?? [:]
        return HTTPReply(data:Data(),response:HTTPURLResponse(url:r.url!,statusCode:status,httpVersion:nil,headerFields:headers)!)
    }
    func download(_ r:URLRequest) async throws -> (URL,HTTPURLResponse) {
        let object=objects[key(r)]; let f=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try (object?.0 ?? Data()).write(to:f)
        return (f,HTTPURLResponse(url:r.url!,statusCode:object==nil ? 404:200,httpVersion:nil,headerFields:[:])!)
    }
}
final class ArchivePublicationTests:XCTestCase {
    func testIncompletePublicationCannotCompleteAndR2RecoveryIsIndependent() async throws {
        let env=ProcessInfo.processInfo.environment
        guard let age=env["FK_TEST_AGE"],let keygen=env["FK_TEST_AGE_KEYGEN"] else { throw XCTSkip("Pinned age tools required") }
        let tools=AgeTools(age:URL(fileURLWithPath:age),keygen:URL(fileURLWithPath:keygen))
        let dir=try privateDirectory(); defer { try? FileManager.default.removeItem(at:dir) }
        let p=dir.appendingPathComponent("p");let r=dir.appendingPathComponent("r")
        try tools.run(tools.keygen,[],output:p);try tools.run(tools.keygen,[],output:r)
        let primary=try String(contentsOf:p);let recovery=try String(contentsOf:r)
        let creds=Credentials(environment:["PRIMARY":primary,"RECOVERY":recovery,"KEY":"id","SECRET":"object-secret"])
        let primaryRef=CredentialReference(provider:"environment",reference:"PRIMARY",expiresAt:nil)
        let recoveryRef=CredentialReference(provider:"environment",reference:"RECOVERY",expiresAt:nil)
        let vaultPath=dir.appendingPathComponent("vault");let vault=AgeVault(root:vaultPath,tools:tools,credentials:creds)
        _=try vault.initialize(primary:primaryRef,recovery:recoveryRef)
        let source=dir.appendingPathComponent("source");try FileManager.default.createDirectory(at:source,withIntermediateDirectories:false)
        try Data("independent remote restore".utf8).write(to:source.appendingPathComponent("file"))
        let snapshot=try vault.create(source:source,identityRef:primaryRef)
        let profile=try JSONDecoder().decode(Profile.self,from:Data("""
        {"accountID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bucket":"private-fixture","group":{"project":"fixture","environment":"test","purpose":"repository-archives","contentType":"encrypted"},"allowedOperations":[],"accessKeyID":{"provider":"environment","reference":"KEY"},"secretAccessKey":{"provider":"environment","reference":"SECRET"}}
        """.utf8))
        let transport=ObjectStoreTransport();transport.failManifest=true
        let store=try R2(profile:profile,credentials:creds,transport:transport)
        do { _=try await vault.publish(snapshotID:snapshot["snapshotID"].string!,expectedManifestDigest:snapshot["manifestDigest"].string!,storage:store,verification:"metadata");XCTFail() } catch {}
        XCTAssertFalse(transport.objects.keys.contains{$0.hasSuffix(".complete.json")})
        transport.failManifest=false
        _=try await vault.publish(snapshotID:snapshot["snapshotID"].string!,expectedManifestDigest:snapshot["manifestDigest"].string!,storage:store,verification:"metadata")
        let recovered=AgeVault(root:dir.appendingPathComponent("fetched"),tools:tools,credentials:Credentials(environment:["RECOVERY":recovery]))
        _=try await recovered.fetch(snapshotID:snapshot["snapshotID"].string!,vaultID:snapshot["vaultID"].string!,expectedManifestDigest:snapshot["manifestDigest"].string!,identityRef:recoveryRef,storage:store)
        XCTAssertFalse(FileManager.default.fileExists(atPath:dir.appendingPathComponent("fetched/indexes").path))
        let output=dir.appendingPathComponent("restored")
        _=try recovered.restore(snapshotID:snapshot["snapshotID"].string!,destination:output,expectedManifestDigest:snapshot["manifestDigest"].string!,identityRef:recoveryRef)
        XCTAssertEqual(try String(contentsOf:output.appendingPathComponent("file")),"independent remote restore")
    }
}
