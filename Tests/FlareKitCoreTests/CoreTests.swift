import XCTest
@testable import FlareKitCore
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class MockTransport:Transport {
    var requests:[URLRequest]=[]
    var contents=Data("payload".utf8)
    var status=200
    var failures=0
    func send(_ r:URLRequest,upload:URL?) async throws -> HTTPReply {
        requests.append(r)
        if failures>0 { failures-=1; throw FKError("network","retry",retryable:true) }
        if let file=upload { contents=try Data(contentsOf:file) }
        let headers=["content-length":String(contents.count),"x-amz-meta-sha256":sha256(contents)]
        return HTTPReply(data:Data(),response:HTTPURLResponse(url:r.url!,statusCode:status,httpVersion:nil,headerFields:headers)!)
    }
    func download(_ r:URLRequest) async throws -> (URL,HTTPURLResponse) {
        requests.append(r); let file=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try contents.write(to:file)
        return (file,HTTPURLResponse(url:r.url!,statusCode:status,httpVersion:nil,headerFields:[:])!)
    }
}
final class CoreTests:XCTestCase {
    func configuration() throws -> Configuration {
        try JSONDecoder().decode(Configuration.self,from:Data("""
        {"schemaVersion":1,"profiles":{"test":{"accountID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bucket":"private-fixture","group":{"project":"fixture","environment":"disposable","purpose":"test","contentType":"binary"},"allowedOperations":["storage.object.upload","storage.object.verify"],"accessKeyID":{"provider":"environment","reference":"KEY"},"secretAccessKey":{"provider":"environment","reference":"SECRET"}}},"vaults":[]}
        """.utf8))
    }
    func testSHA256KnownVector() { XCTAssertEqual(sha256(Data("abc".utf8)),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") }
    func testUnsafePaths() {
        for path in ["/root","../escape","a/../b","a//b","a\\b","a/./b"] { XCTAssertThrowsError(try safeRelative(path)) }
        XCTAssertNoThrow(try safeRelative("nested/README.md"))
    }
    func testPolicyBeforeCredentialAccess() async throws {
        let e=Engine(configuration:try configuration(),credentials:Credentials(environment:[:]))
        let r=Request(operation:.objectUpload,profile:"test",parameters:.object(["key":.string("x")]))
        do { _=try await e.execute(r); XCTFail("should reject parameters") }
        catch let error as FKError { XCTAssertEqual(error.code,"validation") }
    }
    func testUnauthorizedOperationBeforeCredentialAccess() async throws {
        let e=Engine(configuration:try configuration(),credentials:Credentials(environment:[:]))
        let r=Request(operation:.bucketCreate,profile:"test",parameters:.object(["bucket":.string("test-bucket")]))
        do { _=try await e.execute(r); XCTFail() } catch let error as FKError { XCTAssertEqual(error.stage,"validation") }
    }
    func testNoHardwareFallback() throws {
        let ref=CredentialReference(provider:"hardware",reference:"KEY",expiresAt:nil)
        XCTAssertThrowsError(try Credentials(environment:["KEY":"software-secret"]).get(ref)) { XCTAssertEqual(($0 as? FKError)?.code,"unsupported") }
    }
    func testExpiredCredential() {
        XCTAssertThrowsError(try Credentials(environment:["KEY":"secret"]).get(.init(provider:"environment",reference:"KEY",expiresAt:Date(timeIntervalSince1970:0))))
    }
    func testSignatureEncodesPathsAndQuery() throws {
        let r=try S3Signer(accessKey:"key",secretKey:"secret").sign(method:"GET",endpoint:"https://example.com",path:["bucket","a b","é+%"],query:[("z","a+b"),("a","/ space")],payloadHash:sha256(Data()),now:Date(timeIntervalSince1970:0))
        XCTAssertEqual(r.url!.absoluteString,"https://example.com/bucket/a%20b/%C3%A9%2B%25?a=%2F%20space&z=a%2Bb")
        XCTAssertTrue(r.value(forHTTPHeaderField:"Authorization")!.contains("19700101/auto/s3/aws4_request"))
        XCTAssertFalse(r.url!.absoluteString.contains("secret"))
    }
    func testConditionalStreamingUploadAndMetadataGuarantee() async throws {
        let dir=try privateDirectory(); defer { try? FileManager.default.removeItem(at:dir) }
        let f=dir.appendingPathComponent("source"); try Data("input".utf8).write(to:f)
        let t=MockTransport(); let r=try R2(profile:configuration().profiles["test"]!,credentials:Credentials(environment:["KEY":"id","SECRET":"secret"]),transport:t)
        let result=try await r.upload(key:"immutable/key",source:f,verification:"metadata")
        XCTAssertEqual(t.requests[0].value(forHTTPHeaderField:"if-none-match"),"*")
        XCTAssertEqual(result["contentVerified"].bool,false)
        XCTAssertEqual(result["checkedBytes"].string,"0")
    }
    func testCollisionNotRetried() async throws {
        let dir=try privateDirectory(); defer { try? FileManager.default.removeItem(at:dir) }
        let f=dir.appendingPathComponent("source"); try Data("input".utf8).write(to:f)
        let t=MockTransport(); t.status=412
        let r=try R2(profile:configuration().profiles["test"]!,credentials:Credentials(environment:["KEY":"id","SECRET":"secret"]),transport:t)
        do { _=try await r.upload(key:"key",source:f,verification:"metadata"); XCTFail() }
        catch let error as FKError { XCTAssertEqual(error.code,"collision"); XCTAssertEqual(t.requests.count,1) }
    }
    func testCorruptDownloadDoesNotPublishDestination() async throws {
        let dir=try privateDirectory(); defer { try? FileManager.default.removeItem(at:dir) }
        let target=dir.appendingPathComponent("restored")
        let t=MockTransport(); t.contents=Data("corrupt".utf8)
        let r=try R2(profile:configuration().profiles["test"]!,credentials:Credentials(environment:["KEY":"id","SECRET":"secret"]),transport:t)
        do { _=try await r.download(key:"key",destination:target,expected:sha256(Data("original".utf8))); XCTFail() }
        catch let error as FKError { XCTAssertEqual(error.code,"integrity"); XCTAssertFalse(FileManager.default.fileExists(atPath:target.path)) }
    }
    func testBoundedRetry() async throws {
        var tries=0
        do { let _:Int=try await boundedRetry(attempts:2) { tries+=1; throw FKError("network","temporary",retryable:true) }; XCTFail() }
        catch { XCTAssertEqual(tries,2) }
    }
    func testXMLRejectsEntityInjectionAndParsesPagination() throws {
        XCTAssertThrowsError(try XMLValues.read(Data("<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///etc/passwd'>]><x>&y;</x>".utf8)))
        let x=try XMLValues.read(Data("<ListBucketResult><Contents><Key>a</Key><Size>3</Size></Contents><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken></ListBucketResult>".utf8))
        XCTAssertEqual(x.entries[0]["Key"],"a"); XCTAssertEqual(x.values["NextContinuationToken"]?.first,"next")
    }
    func testRetentionExplicitDuration() throws {
        XCTAssertThrowsError(try validateLockRules(.object(["rules":.array([.object(["id":.string("lock"),"enabled":.bool(true),"condition":.object(["type":.string("Age"),"maxAgeSeconds":.number(-1)])])])])))
    }
    func testWorkerRejectsBuildHook() {
        XCTAssertThrowsError(try validateWorkerConfig(.object(["build":.object(["command":.string("steal tokens")])]),account:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    }
    func testGitAllObjectsIndexAndQuarantinedRestore() throws {
        let dir=try privateDirectory(); defer { try? FileManager.default.removeItem(at:dir) }
        let source=dir.appendingPathComponent("source"); try FileManager.default.createDirectory(at:source,withIntermediateDirectories:false)
        _=try git(["init"],cwd:source)
        let tracked=source.appendingPathComponent("tracked"); try Data("committed".utf8).write(to:tracked)
        _=try git(["add","tracked"],cwd:source)
        _=try git(["-c","user.name=Fixture","-c","user.email=fixture@example.invalid","-c","commit.gpgsign=false","commit","-m","fixture"],cwd:source)
        try Data("staged".utf8).write(to:tracked); _=try git(["add","tracked"],cwd:source)
        try Data("unstaged".utf8).write(to:tracked)
        let extra=source.appendingPathComponent("dangling"); try Data("unreachable".utf8).write(to:extra)
        let dangling=try git(["hash-object","-w",extra.path],cwd:source).trimmingCharacters(in:.whitespacesAndNewlines)
        let hook=source.appendingPathComponent(".git/hooks/post-checkout"); try Data("#!/bin/sh\nexit 77".utf8).write(to:hook)
        let indexBefore=try hashFile(source.appendingPathComponent(".git/index")).digest
        let capture=dir.appendingPathComponent("capture"); let result=try GitCapture().capture(source:source,destination:capture)
        let restore=dir.appendingPathComponent("restore")
        let receipt=try GitCapture().restore(capture:capture,destination:restore,expectedManifestDigest:result["manifestDigest"].string!)
        XCTAssertEqual(receipt["allLocalObjectsRestored"].bool,true)
        XCTAssertEqual(try git(["cat-file","-p",dangling],cwd:restore),"unreachable")
        XCTAssertEqual(try hashFile(restore.appendingPathComponent(".git/index")).digest,indexBefore)
        XCTAssertEqual(try String(contentsOf:restore.appendingPathComponent("tracked")),"unstaged")
        XCTAssertFalse(FileManager.default.fileExists(atPath:restore.appendingPathComponent(".git/hooks/post-checkout").path))
        XCTAssertEqual(try hashFile(source.appendingPathComponent(".git/index")).digest,indexBefore)
        try Data("tampered".utf8).write(to:capture.appendingPathComponent("working-tree/tracked"))
        XCTAssertThrowsError(try GitCapture().verify(capture:capture,expectedManifestDigest:result["manifestDigest"].string!))
    }
}
