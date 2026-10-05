import Foundation
import Crypto

struct MultipartPart:Codable { let number:Int; let etag:String }
struct MultipartJournal:Codable {
    let schemaVersion:Int; let accountID:String; let bucket:String; let key:String
    let sourceSHA256:String; let sourceSize:UInt64; let partSize:UInt64; let uploadID:String
    var parts:[MultipartPart]
}
extension R2 {
    public func multipartUpload(key:String,source:URL,journalURL:URL,management:Cloudflare,verification:String) async throws -> JSON {
        try require(["full","metadata"].contains(verification),"Choose multipart verification mode")
        try require(!key.isEmpty && key.utf8.count<=1024,"Invalid multipart key")
        guard let bucket=profile.bucket else { throw FKError("validation","Bucket required") }
        func guardRetention() async throws {
            let locks=try await management.locks(bucket)
            let covers=(locks["rules"].array ?? []).contains { rule in
                rule["enabled"].bool==true && rule["condition"]["type"].string=="Indefinite" && key.hasPrefix(rule["prefix"].string ?? "")
            }
            try require(covers,"Multipart create requires a verified covering Indefinite R2 lock; conditional completion is not assumed")
        }
        try await guardRetention()
        let attributes=try source.resourceValues(forKeys:[.isRegularFileKey,.isSymbolicLinkKey,.fileSizeKey,.contentModificationDateKey])
        try require(attributes.isRegularFile==true && attributes.isSymbolicLink != true,"Regular multipart source required")
        let fingerprint=try hashFile(source)
        let partSize=max(UInt64(8*1024*1024),(fingerprint.size+9998)/9999)
        try require(partSize<=128*1024*1024,"Multipart part memory bound exceeded")
        let lock=journalURL.appendingPathExtension("lock")
        do { try FileManager.default.createDirectory(at:lock,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]) }
        catch { throw FKError("collision","Multipart journal is locked; reconcile interrupted process before retry") }
        defer { try? FileManager.default.removeItem(at:lock) }
        func save(_ journal:MultipartJournal) throws {
            let data=try JSONEncoder().encode(journal); try data.write(to:journalURL,options:.atomic)
            try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:journalURL.path)
        }
        var journal:MultipartJournal
        if FileManager.default.fileExists(atPath:journalURL.path) {
            journal=try JSONDecoder().decode(MultipartJournal.self,from:Data(contentsOf:journalURL))
            try require(journal.schemaVersion==1 && journal.accountID==profile.accountID && journal.bucket==bucket && journal.key==key && journal.sourceSHA256==fingerprint.digest && journal.sourceSize==fingerprint.size,"Resume journal differs from source or destination")
            // List parts before resuming. Keep only parts with the same acknowledged ETag.
            var remote:[Int:String]=[:]; var marker:String?
            repeat {
                var q=[("uploadId",journal.uploadID),("max-parts","1000")]; if let marker { q.append(("part-number-marker",marker)) }
                let result=try await send(request("GET",key:key,query:q)); let xml=try XMLValues.read(result.data)
                for part in xml.entries { if let n=Int(part["PartNumber"] ?? ""),let etag=part["ETag"] { remote[n]=etag } }
                marker=xml.values["IsTruncated"]?.first=="true" ? xml.values["NextPartNumberMarker"]?.first : nil
            } while marker != nil
            journal.parts=journal.parts.filter { remote[$0.number]==$0.etag }; try save(journal)
        } else {
            do { _=try await inspect(key:key); throw FKError("collision","Object exists; multipart replacement is forbidden") }
            catch let e as FKError where e.httpStatus==404 {}
            let create=try await send(request("POST",key:key,query:[("uploads","")],headers:["content-type":"application/octet-stream","x-amz-meta-sha256":fingerprint.digest]),retry:false)
            let xml=try XMLValues.read(create.data)
            guard let uploadID=xml.values["UploadId"]?.first,!uploadID.isEmpty else { throw FKError("integrity","Multipart upload ID missing") }
            journal=MultipartJournal(schemaVersion:1,accountID:profile.accountID,bucket:bucket,key:key,sourceSHA256:fingerprint.digest,sourceSize:fingerprint.size,partSize:partSize,uploadID:uploadID,parts:[])
            try save(journal)
        }
        let temp=try privateDirectory(); defer { try? FileManager.default.removeItem(at:temp) }
        let handle=try FileHandle(forReadingFrom:source); defer { try? handle.close() }
        let count=Int((fingerprint.size+journal.partSize-1)/journal.partSize)
        for number in 1...max(1,count) {
            if journal.parts.contains(where:{$0.number==number}) { continue }
            try Task.checkCancellation()
            let offset=UInt64(number-1)*journal.partSize; try handle.seek(toOffset:offset)
            let bytes=try handle.read(upToCount:Int(journal.partSize)) ?? Data()
            let file=temp.appendingPathComponent("part"); try bytes.write(to:file); try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:file.path)
            let md5=Data(Insecure.MD5.hash(data:bytes)).base64EncodedString()
            let req=try request("PUT",key:key,query:[("partNumber",String(number)),("uploadId",journal.uploadID)],headers:["content-md5":md5],hash:sha256(bytes))
            let uploaded=try await send(req,file:file)
            guard let etag=uploaded.response.value(forHTTPHeaderField:"etag") else { throw FKError("integrity","Multipart part acknowledgement missing") }
            journal.parts.append(.init(number:number,etag:etag)); try save(journal)
        }
        let after=try source.resourceValues(forKeys:[.fileSizeKey,.contentModificationDateKey])
        try require(attributes.fileSize==after.fileSize && attributes.contentModificationDate==after.contentModificationDate && hashFile(source).digest==fingerprint.digest,"Source changed; multipart completion blocked")
        try await guardRetention()
        func escape(_ x:String)->String { x.replacingOccurrences(of:"&",with:"&amp;").replacingOccurrences(of:"<",with:"&lt;").replacingOccurrences(of:">",with:"&gt;") }
        let xml="<CompleteMultipartUpload>"+journal.parts.sorted{$0.number<$1.number}.map{"<Part><PartNumber>\($0.number)</PartNumber><ETag>\(escape($0.etag))</ETag></Part>"}.joined()+"</CompleteMultipartUpload>"
        let body=Data(xml.utf8); var req=try request("POST",key:key,query:[("uploadId",journal.uploadID)],headers:["content-type":"application/xml"],hash:sha256(body)); req.httpBody=body
        let completed=try await send(req,retry:false)
        if String(decoding:completed.data,as:UTF8.self).contains("<Error>") { throw FKError("network","Multipart completion returned an embedded error; retain journal for reconciliation") }
        let result=verification=="full" ? try await verify(key:key,expected:fingerprint.digest) : try await inspect(key:key)
        try FileManager.default.removeItem(at:journalURL)
        return .object(["object":result,"sha256":.string(fingerprint.digest),"verification":.string(verification),"multipart":.bool(true),"retentionGuard":.string("verified-Indefinite-lock; administrator-removable")])
    }
    public func abortMultipart(journalURL:URL) async throws -> JSON {
        let j=try JSONDecoder().decode(MultipartJournal.self,from:Data(contentsOf:journalURL))
        try require(j.schemaVersion==1 && j.accountID==profile.accountID && j.bucket==profile.bucket,"Journal destination mismatch")
        _=try await send(request("DELETE",key:j.key,query:[("uploadId",j.uploadID)]),retry:false)
        try FileManager.default.removeItem(at:journalURL)
        return .object(["aborted":.bool(true),"completedObjectsDeleted":.bool(false)])
    }
}
