import XCTest
@testable import FlareKitCore
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class MultipartTransport:Transport {
    var locked=true; var failSecond=false; var completed=false
    var parts:[Int:Data]=[:]; var partCalls:[Int:Int]=[:]
    var objectSHA=""
    func send(_ r:URLRequest,upload:URL?) async throws -> HTTPReply {
        let query=URLComponents(url:r.url!,resolvingAgainstBaseURL:false)!.queryItems ?? []
        let values=Dictionary(uniqueKeysWithValues:query.map{($0.name,$0.value ?? "")})
        var status=200; var data=Data(); var headers:[String:String]=[:]
        if r.url!.host=="api.cloudflare.com" {
            data=try JSON.object(["success":.bool(true),"result":.object(["rules":.array(locked ? [.object(["enabled":.bool(true),"prefix":.string("large/"),"condition":.object(["type":.string("Indefinite")])])]:[])])]).encoded()
        } else if r.httpMethod=="HEAD" {
            if !completed { status=404 } else { headers=["content-length":String(parts.values.reduce(0){$0+$1.count}),"x-amz-meta-sha256":objectSHA] }
        } else if r.httpMethod=="POST" && values["uploads"] != nil {
            objectSHA=r.value(forHTTPHeaderField:"x-amz-meta-sha256")!
            data=Data("<InitiateMultipartUploadResult><UploadId>fixture-upload</UploadId></InitiateMultipartUploadResult>".utf8)
        } else if r.httpMethod=="PUT",let number=Int(values["partNumber"] ?? "") {
            partCalls[number,default:0]+=1
            if number==2 && failSecond { failSecond=false; throw FKError("network","interruption",retryable:false) }
            parts[number]=try Data(contentsOf:upload!); headers["etag"]="\"part-\(number)\""
        } else if r.httpMethod=="GET" && values["uploadId"] != nil {
            let xml="<ListPartsResult>"+parts.keys.sorted().map{"<Part><PartNumber>\($0)</PartNumber><ETag>\"part-\($0)\"</ETag></Part>"}.joined()+"<IsTruncated>false</IsTruncated></ListPartsResult>"
            data=Data(xml.utf8)
        } else if r.httpMethod=="POST" && values["uploadId"] != nil { completed=true; data=Data("<CompleteMultipartUploadResult/>".utf8) }
        return HTTPReply(data:data,response:HTTPURLResponse(url:r.url!,statusCode:status,httpVersion:nil,headerFields:headers)!)
    }
    func download(_ r:URLRequest) async throws -> (URL,HTTPURLResponse) {
        let bytes=parts.keys.sorted().reduce(into:Data()){$0.append(parts[$1]!)}
        let f=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString); try bytes.write(to:f)
        return (f,HTTPURLResponse(url:r.url!,statusCode:200,httpVersion:nil,headerFields:[:])!)
    }
}
final class MultipartTests:XCTestCase {
    func testInterruptedMultipartResumesAcknowledgedPartsAndVerifiesContent() async throws {
        let dir=try privateDirectory(); defer { try? FileManager.default.removeItem(at:dir) }
        let file=dir.appendingPathComponent("source"); try Data(repeating:42,count:8*1024*1024+31).write(to:file)
        let profile=try JSONDecoder().decode(Profile.self,from:Data("""
        {"accountID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bucket":"private-fixture","group":{"project":"fixture","environment":"test","purpose":"archives","contentType":"binary"},"allowedOperations":[],"managementCredential":{"provider":"environment","reference":"MANAGE"},"accessKeyID":{"provider":"environment","reference":"KEY"},"secretAccessKey":{"provider":"environment","reference":"SECRET"}}
        """.utf8))
        let credentials=Credentials(environment:["KEY":"id","SECRET":"secret","MANAGE":"management"])
        let transport=MultipartTransport(); transport.failSecond=true
        let r2=try R2(profile:profile,credentials:credentials,transport:transport)
        let admin=try Cloudflare(profile:profile,credentials:credentials,transport:transport)
        let journal=dir.appendingPathComponent("upload.json")
        do { _=try await r2.multipartUpload(key:"large/file",source:file,journalURL:journal,management:admin,verification:"full"); XCTFail() } catch {}
        XCTAssertTrue(FileManager.default.fileExists(atPath:journal.path)); XCTAssertFalse(transport.completed)
        let result=try await r2.multipartUpload(key:"large/file",source:file,journalURL:journal,management:admin,verification:"full")
        XCTAssertEqual(result["object"]["contentVerified"].bool,true)
        XCTAssertEqual(transport.partCalls[1],1); XCTAssertEqual(transport.partCalls[2],2)
        XCTAssertFalse(FileManager.default.fileExists(atPath:journal.path))
        transport.locked=false
        do { _=try await r2.multipartUpload(key:"large/other",source:file,journalURL:journal,management:admin,verification:"metadata"); XCTFail() }
        catch let error as FKError { XCTAssertEqual(error.code,"validation") }
    }
}
