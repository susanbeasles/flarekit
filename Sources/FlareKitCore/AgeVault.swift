import Foundation
import Crypto

public struct AgeTools {
    public let age:URL
    public let keygen:URL
    public init(age:URL,keygen:URL) { self.age=age; self.keygen=keygen }
    public func run(_ executable:URL,_ arguments:[String],input:Data=Data(),output:URL) throws {
        do { try runChild(executable:executable,arguments:arguments,input:input,output:output) }
        catch { try? FileManager.default.removeItem(at:output); throw FKError("integrity","age operation failed; secret identity and subprocess output omitted",stage:"encryption") }
    }
    public func validate() throws {
        let temp=try privateDirectory(); defer { try? FileManager.default.removeItem(at:temp) }
        let output=temp.appendingPathComponent("version"); try run(age,["--version"],output:output)
        try require(try String(contentsOf:output).trimmingCharacters(in:.whitespacesAndNewlines)=="v1.3.1","age runtime must be pinned to v1.3.1")
    }
    public func recipient(identity:String) throws -> String {
        try require(identity.contains("AGE-SECRET-KEY-1") && identity.utf8.count<4096,"Native X25519 age identity required")
        let temp=try privateDirectory(); defer { try? FileManager.default.removeItem(at:temp) }
        let output=temp.appendingPathComponent("recipient"); try run(keygen,["-y"],input:Data((identity+"\n").utf8),output:output)
        let value=try String(contentsOf:output).trimmingCharacters(in:.whitespacesAndNewlines)
        try require(value.hasPrefix("age1") && !value.contains("\n"),"Exactly one native recipient required"); return value
    }
    public func encrypt(_ input:URL,to output:URL,recipients:[String]) throws {
        var args=[String](); for r in recipients { args += ["-r",r] }; args.append(input.path)
        try run(age,args,output:output)
    }
    public func decrypt(_ input:URL,to output:URL,identity:String) throws { try run(age,["-d","-i","-",input.path],input:Data((identity+"\n").utf8),output:output) }
}
public struct VaultDescriptor:Codable {
    public let schemaVersion:Int
    public let vaultID:String
    public let format:String
    public let chunker:String
    public let recipients:[String]
    public let recipientDigest:String
    public let recoveryVerifiedAt:String
    public let evictPrimaryAfterReplication:Bool
}
public struct VaultBlob:Codable,Equatable {
    public let ciphertextSHA256:String
    public let ciphertextSize:UInt64
    public let plaintextSHA256:String
    public let plaintextSize:UInt64
}
public struct SnapshotFile:Codable {
    public let path:String
    public let size:UInt64
    public let plaintextSHA256:String
    public let chunks:[VaultBlob]
}
public struct SnapshotManifest:Codable {
    public let schemaVersion:Int
    public let vaultID:String
    public let snapshotID:String
    public let chunker:String
    public let capturedAt:String
    public let files:[SnapshotFile]
    public let coverage:JSON
}
public struct SnapshotCompletion:Codable {
    public let schemaVersion:Int
    public let vaultID:String
    public let snapshotID:String
    public let manifestCiphertextSHA256:String
    public let blobCiphertextSHA256:[String]
}
public struct SnapshotInput:Codable {
    public let vault:String
    public let source:String?
    public let snapshotID:String?
    public let destination:String?
    public let expectedManifestDigest:String?
    public let identity:CredentialReference
    public let recoveryIdentity:CredentialReference?
    public let verification:String?
}
public final class AgeVault {
    let root:URL; let tools:AgeTools; let credentials:Credentials
    public init(root:URL,tools:AgeTools,credentials:Credentials) { self.root=root.standardizedFileURL; self.tools=tools; self.credentials=credentials }
    func descriptor() throws -> VaultDescriptor {
        let d=try JSONDecoder().decode(VaultDescriptor.self,from:Data(contentsOf:root.appendingPathComponent("vault.json")))
        try require(d.schemaVersion==1 && d.format=="fk-age-v1" && d.chunker=="fixed-8mib-v1" && !d.evictPrimaryAfterReplication,"Unsupported vault descriptor")
        try require(d.recipients.count==2 && Set(d.recipients).count==2,"Independent recipient coverage required")
        try require(sha256(try JSONEncoder().encode(d.recipients))==d.recipientDigest,"Recipient set modified")
        return d
    }
    public func initialize(primary:CredentialReference,recovery:CredentialReference) throws -> JSON {
        try tools.validate(); try require(!FileManager.default.fileExists(atPath:root.path),"Vault exists; rotation cannot silently change recipients")
        let first=try credentials.get(primary); let second=try credentials.get(recovery)
        let recipients=try [tools.recipient(identity:first),tools.recipient(identity:second)]
        try require(recipients[0] != recipients[1],"Recovery identity must be independently generated")
        let temp=try privateDirectory(); defer { try? FileManager.default.removeItem(at:temp) }
        let challenge=Data(UUID().uuidString.utf8); let plain=temp.appendingPathComponent("challenge"); try writePrivate(challenge,to:plain)
        for i in 0..<2 {
            let cipher=temp.appendingPathComponent("test-\(i).age"); let restored=temp.appendingPathComponent("restore-\(i)")
            try tools.encrypt(plain,to:cipher,recipients:[recipients[i]])
            try tools.decrypt(cipher,to:restored,identity:i==0 ? first : second)
            try require(try Data(contentsOf:restored)==challenge,"Recipient challenge failed")
        }
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        for name in ["blobs/sha256","snapshots","indexes"] { try FileManager.default.createDirectory(at:root.appendingPathComponent(name),withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]) }
        let d=VaultDescriptor(schemaVersion:1,vaultID:UUID().uuidString.lowercased(),format:"fk-age-v1",chunker:"fixed-8mib-v1",recipients:recipients,recipientDigest:sha256(try JSONEncoder().encode(recipients)),recoveryVerifiedAt:ISO8601DateFormatter().string(from:Date()),evictPrimaryAfterReplication:false)
        try writePrivate(JSONEncoder().encode(d),to:root.appendingPathComponent("vault.json"))
        return .object(["vaultID":.string(d.vaultID),"recoveryVerified":.bool(true),"recipientDigest":.string(d.recipientDigest),"custodyWarning":.string("Retain recovery identity independently; verification does not establish ongoing custody")])
    }
    func blobURL(_ digest:String) throws -> URL {
        try require(digest.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil,"Invalid ciphertext digest")
        return root.appendingPathComponent("blobs/sha256/"+digest+".age")
    }
    public func create(source:URL,identityRef:CredentialReference) throws -> JSON {
        try tools.validate(); let d=try descriptor(); let identity=try credentials.get(identityRef)
        try require(d.recipients.contains(try tools.recipient(identity:identity)),"Identity not in this vault recipient epoch")
        let source=source.standardizedFileURL.resolvingSymlinksInPath()
        try require(!root.path.hasPrefix(source.path+"/") && source.path != root.path,"Vault cannot be inside capture source")
        let lock=root.appendingPathComponent("writer.lock")
        do { try FileManager.default.createDirectory(at:lock,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700]) }
        catch { throw FKError("collision","Vault writer lock exists; reconcile interrupted writer before retry",stage:"capture") }
        defer { try? FileManager.default.removeItem(at:lock) }
        let temp=try privateDirectory(parent:root); defer { try? FileManager.default.removeItem(at:temp) }
        var index:[String:VaultBlob]=[:]
        let head=root.appendingPathComponent("index-head.json")
        if FileManager.default.fileExists(atPath:head.path) {
            let pointer=try JSONDecoder().decode([String:String].self,from:Data(contentsOf:head))
            guard let filename=pointer["file"],let expected=pointer["sha256"] else { throw FKError("integrity","Invalid encrypted index pointer") }
            try safeRelative(filename); let encrypted=root.appendingPathComponent(filename)
            try require((try encrypted.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? Int.max)<=128*1024*1024,"Encrypted index exceeds supported memory budget")
            try require(try hashFile(encrypted).digest==expected,"Encrypted index digest mismatch")
            let decrypted=temp.appendingPathComponent("index"); try tools.decrypt(encrypted,to:decrypted,identity:identity)
            index=try JSONDecoder().decode([String:VaultBlob].self,from:Data(contentsOf:decrypted))
        }
        guard let iterator=FileManager.default.enumerator(at:source,includingPropertiesForKeys:[.isRegularFileKey,.isDirectoryKey,.isSymbolicLinkKey,.fileSizeKey,.contentModificationDateKey],options:[]) else { throw FKError("validation","Snapshot source unavailable") }
        var files:[SnapshotFile]=[]; var created=0; var reused=0
        for case let file as URL in iterator {
            let values=try file.resourceValues(forKeys:[.isRegularFileKey,.isDirectoryKey,.isSymbolicLinkKey,.fileSizeKey,.contentModificationDateKey])
            if values.isDirectory==true && values.isSymbolicLink != true { continue }
            try require(values.isRegularFile==true && values.isSymbolicLink != true,"Snapshot rejects symlinks/special files; use reviewed capture records instead")
            let relative=try relativeEntryPath(file,under:source)
            try require(!relative.split(separator:"/").contains(".git"),"Raw Git administration files require archive.git.capture so configuration and hooks stay quarantined")
            let fh=try FileHandle(forReadingFrom:file); var chunks:[VaultBlob]=[]; var fileHasher=SHA256(); var fileSize:UInt64=0
            do {
                while let bytes=try fh.read(upToCount:8*1024*1024),!bytes.isEmpty {
                    fileHasher.update(data:bytes); fileSize+=UInt64(bytes.count)
                    let plainDigest=sha256(bytes); let lookup=plainDigest+":"+String(bytes.count)
                    if let existing=index[lookup] {
                        try require(existing.plaintextSHA256==plainDigest && existing.plaintextSize==UInt64(bytes.count) && existing.ciphertextSize<=9*1024*1024,"Encrypted dedup index entry is inconsistent")
                        let stored=try blobURL(existing.ciphertextSHA256)
                        // Recurring full checks are budgeted separately; reuse checks existence/size.
                        let size=try stored.resourceValues(forKeys:[.fileSizeKey]).fileSize
                        try require(size==Int(existing.ciphertextSize),"Dedup index references missing or truncated blob")
                        chunks.append(existing); reused+=1
                    } else {
                        let plain=temp.appendingPathComponent(UUID().uuidString); let encrypted=temp.appendingPathComponent(UUID().uuidString+".age")
                        try writePrivate(bytes,to:plain); try tools.encrypt(plain,to:encrypted,recipients:d.recipients)
                        let h=try hashFile(encrypted); let blob=VaultBlob(ciphertextSHA256:h.digest,ciphertextSize:h.size,plaintextSHA256:plainDigest,plaintextSize:UInt64(bytes.count))
                        try FileManager.default.moveItem(at:encrypted,to:blobURL(h.digest)); try FileManager.default.removeItem(at:plain)
                        index[lookup]=blob; chunks.append(blob); created+=1
                    }
                }
                try fh.close()
            } catch { try? fh.close(); throw error }
            let after=try file.resourceValues(forKeys:[.fileSizeKey,.contentModificationDateKey])
            try require(values.fileSize==after.fileSize && values.contentModificationDate==after.contentModificationDate,"File changed during snapshot")
            let digest=fileHasher.finalize().map { String(format:"%02x",$0) }.joined()
            files.append(.init(path:relative,size:fileSize,plaintextSHA256:digest,chunks:chunks))
        }
        let id=UUID().uuidString.lowercased()
        let m=SnapshotManifest(schemaVersion:1,vaultID:d.vaultID,snapshotID:id,chunker:d.chunker,capturedAt:ISO8601DateFormatter().string(from:Date()),files:files.sorted{$0.path<$1.path},coverage:.object(["selection":.string("all-regular-files; no exclusions"),"symlinks":.string("rejected"),"pointInTime":.bool(false),"modeACLXattrs":.string("not-preserved")]))
        let plainManifest=temp.appendingPathComponent("manifest.json"); try writePrivate(JSONEncoder().encode(m),to:plainManifest)
        let encryptedManifest=root.appendingPathComponent("snapshots/"+id+".json.age"); try tools.encrypt(plainManifest,to:encryptedManifest,recipients:d.recipients)
        let mh=try hashFile(encryptedManifest)
        let plainIndex=temp.appendingPathComponent("new-index"); try writePrivate(JSONEncoder().encode(index),to:plainIndex)
        let indexName="indexes/"+UUID().uuidString.lowercased()+".json.age"; let encryptedIndex=root.appendingPathComponent(indexName)
        try tools.encrypt(plainIndex,to:encryptedIndex,recipients:d.recipients)
        let pointer=try JSONEncoder().encode(["file":indexName,"sha256":hashFile(encryptedIndex).digest]); try pointer.write(to:head,options:.atomic)
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:head.path)
        let completion=SnapshotCompletion(schemaVersion:1,vaultID:d.vaultID,snapshotID:id,manifestCiphertextSHA256:mh.digest,blobCiphertextSHA256:Array(Set(files.flatMap{$0.chunks.map{$0.ciphertextSHA256}})).sorted())
        try writePrivate(JSONEncoder().encode(completion),to:root.appendingPathComponent("snapshots/"+id+".complete.json"))
        return .object(["snapshotID":.string(id),"vaultID":.string(d.vaultID),"manifestDigest":.string(mh.digest),"newChunks":.number(Double(created)),"reusedChunks":.number(Double(reused)),"verification":.string("new-local-ciphertext-hashes-and-reused-metadata"),"remotePublication":.string("not-performed")])
    }
    public func completion(snapshotID:String,expectedManifestDigest:String) throws -> SnapshotCompletion {
        try require(UUID(uuidString:snapshotID) != nil,"Invalid snapshot ID")
        let c=try JSONDecoder().decode(SnapshotCompletion.self,from:Data(contentsOf:root.appendingPathComponent("snapshots/"+snapshotID+".complete.json")))
        try require(c.schemaVersion==1 && c.vaultID==descriptor().vaultID && c.snapshotID==snapshotID && c.manifestCiphertextSHA256==expectedManifestDigest,"Completion differs from trusted manifest digest")
        try require(try hashFile(root.appendingPathComponent("snapshots/"+snapshotID+".json.age")).digest==expectedManifestDigest,"Manifest ciphertext corrupted")
        return c
    }
    public func restore(snapshotID:String,destination:URL,expectedManifestDigest:String,identityRef:CredentialReference) throws -> JSON {
        try tools.validate(); let c=try completion(snapshotID:snapshotID,expectedManifestDigest:expectedManifestDigest)
        try require(!FileManager.default.fileExists(atPath:destination.path),"Restore destination exists")
        let identity=try credentials.get(identityRef); let temp=try privateDirectory(); defer { try? FileManager.default.removeItem(at:temp) }
        let manifestFile=temp.appendingPathComponent("manifest"); try tools.decrypt(root.appendingPathComponent("snapshots/"+snapshotID+".json.age"),to:manifestFile,identity:identity)
        let m=try JSONDecoder().decode(SnapshotManifest.self,from:Data(contentsOf:manifestFile))
        try require(m.schemaVersion==1 && m.vaultID==c.vaultID && m.snapshotID==snapshotID && m.chunker=="fixed-8mib-v1","Manifest identity mismatch")
        try require(Set(m.files.flatMap{$0.chunks.map{$0.ciphertextSHA256}})==Set(c.blobCiphertextSHA256),"Completion blob inventory mismatch")
        var paths=Set<String>(); var normalized=Set<String>(); var bytes:UInt64=0
        for f in m.files {
            try safeRelative(f.path)
            try require(!f.path.split(separator:"/").contains(".git"),"Git configuration/hooks cannot be automatically activated by generic restore")
            try require(paths.insert(f.path).inserted && normalized.insert(f.path.precomposedStringWithCanonicalMapping.lowercased()).inserted,"Path collision in manifest")
        }
        // Assemble privately, then publish the fresh destination only after complete verification.
        let staged=try privateDirectory(parent:destination.deletingLastPathComponent()); defer { try? FileManager.default.removeItem(at:staged) }
        for f in m.files {
            let output=staged.appendingPathComponent(f.path); try FileManager.default.createDirectory(at:output.deletingLastPathComponent(),withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
            FileManager.default.createFile(atPath:output.path,contents:Data(),attributes:[.posixPermissions:0o600]); let handle=try FileHandle(forWritingTo:output)
            do {
                for b in f.chunks {
                    try require(b.plaintextSize<=8*1024*1024 && b.ciphertextSize<=9*1024*1024,"Chunk size exceeds format bounds")
                    let encrypted=try blobURL(b.ciphertextSHA256); let hash=try hashFile(encrypted)
                    try require(hash.digest==b.ciphertextSHA256 && hash.size==b.ciphertextSize,"Ciphertext blob checksum mismatch")
                    let plain=temp.appendingPathComponent(UUID().uuidString); try tools.decrypt(encrypted,to:plain,identity:identity)
                    let h=try hashFile(plain); try require(h.digest==b.plaintextSHA256 && h.size==b.plaintextSize,"Plaintext chunk checksum mismatch")
                    try handle.write(contentsOf:Data(contentsOf:plain)); try FileManager.default.removeItem(at:plain)
                }
                try handle.close()
            } catch { try? handle.close(); throw error }
            let h=try hashFile(output); try require(h.digest==f.plaintextSHA256 && h.size==f.size,"Restored file checksum mismatch"); bytes+=h.size
        }
        try FileManager.default.moveItem(at:staged,to:destination)
        return .object(["snapshotID":.string(snapshotID),"manifestDigest":.string(expectedManifestDigest),"verification":.string("full-ciphertext-and-authenticated-plaintext"),"checkedPlaintextBytes":.string(String(bytes)),"files":.number(Double(m.files.count)),"coverage":m.coverage])
    }
    public func publish(snapshotID:String,expectedManifestDigest:String,storage:R2,verification:String) async throws -> JSON {
        try require(["metadata","full"].contains(verification),"Select metadata or full publication verification")
        let c=try completion(snapshotID:snapshotID,expectedManifestDigest:expectedManifestDigest)
        let prefix="v1/vaults/"+c.vaultID+"/"; var receipts:[JSON]=[]
        func ensure(_ file:URL,_ key:String) async throws -> JSON {
            let h=try hashFile(file)
            do { return try await storage.upload(key:key,source:file,verification:verification) }
            catch let e as FKError where e.code=="collision" {
                if verification=="full" { return try await storage.verify(key:key,expected:h.digest) }
                let actual=try await storage.inspect(key:key)
                try require(actual["declaredSHA256"].string==h.digest && actual["size"].string==String(h.size),"Existing object metadata differs; collision rejected")
                return actual
            }
        }
        for digest in c.blobCiphertextSHA256 { receipts.append(try await ensure(blobURL(digest),prefix+"blobs/sha256/"+digest+".age")) }
        receipts.append(try await ensure(root.appendingPathComponent("vault.json"),prefix+"vault.json"))
        receipts.append(try await ensure(root.appendingPathComponent("snapshots/"+snapshotID+".json.age"),prefix+"snapshots/"+snapshotID+".json.age"))
        receipts.append(try await ensure(root.appendingPathComponent("snapshots/"+snapshotID+".complete.json"),prefix+"snapshots/"+snapshotID+".complete.json"))
        return .object(["snapshotID":.string(snapshotID),"destination":.string("r2-primary"),"verification":.string(verification),"objects":.array(receipts),"completed":.bool(true),"replicas":.string("not-yet-implemented"),"primaryEvicted":.bool(false)])
    }
    public func verify(snapshotID:String,expectedManifestDigest:String,mode:String,byteBudget:UInt64,requestBudget:UInt64,seed:String) throws -> JSON {
        try require(["metadata","full","sampled"].contains(mode),"Invalid verification mode")
        let c=try completion(snapshotID:snapshotID,expectedManifestDigest:expectedManifestDigest)
        var digests=c.blobCiphertextSHA256
        if mode=="sampled" { digests.sort { sha256(Data((seed+$0).utf8)) < sha256(Data((seed+$1).utf8)) } }
        var checked:UInt64=0; var bytes:UInt64=0
        for digest in digests {
            if checked>=requestBudget { break }
            let f=try blobURL(digest); let size=UInt64(try f.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? 0)
            if mode != "metadata" {
                if size>byteBudget-bytes { break }
                guard try hashFile(f).digest==digest else { throw FKError("integrity","Ciphertext checksum mismatch",stage:"verification") }; bytes+=size
            }
            checked+=1
        }
        return .object(["verification":.string(mode),"selectionSeed":mode=="sampled" ? .string(seed):.null,"checkedBytes":.string(String(bytes)),"checkedObjects":.string(String(checked)),"totalObjects":.string(String(digests.count)),"completeCoverage":.bool(checked==digests.count),"plaintextAuthenticated":.bool(false),"scope":.string("local-ciphertext; remote checks use storage.object.verify")])
    }
    public func fetch(snapshotID:String,vaultID:String,expectedManifestDigest:String,identityRef:CredentialReference,storage:R2) async throws -> JSON {
        try require(UUID(uuidString:snapshotID) != nil && UUID(uuidString:vaultID) != nil,"Invalid vault/snapshot ID")
        try require(!FileManager.default.fileExists(atPath:root.path),"Fetch destination exists")
        let stage=try privateDirectory(parent:root.deletingLastPathComponent()); defer { try? FileManager.default.removeItem(at:stage) }
        for name in ["snapshots","blobs/sha256"] { try FileManager.default.createDirectory(at:stage.appendingPathComponent(name),withIntermediateDirectories:true,attributes:[.posixPermissions:0o700]) }
        let prefix="v1/vaults/"+vaultID+"/"
        // Descriptor/completion checksums are discovered metadata; trusted manifest digest
        // and subsequent authenticated restore establish the meaningful integrity boundary.
        for relative in ["vault.json","snapshots/"+snapshotID+".complete.json"] {
            let metadata=try await storage.inspect(key:prefix+relative)
            guard let declared=metadata["declaredSHA256"].string else { throw FKError("integrity","Metadata checksum missing") }
            _ = try await storage.download(key:prefix+relative,destination:stage.appendingPathComponent(relative),expected:declared)
        }
        let c=try JSONDecoder().decode(SnapshotCompletion.self,from:Data(contentsOf:stage.appendingPathComponent("snapshots/"+snapshotID+".complete.json")))
        try require(c.schemaVersion==1 && c.vaultID==vaultID && c.snapshotID==snapshotID && c.manifestCiphertextSHA256==expectedManifestDigest,"Remote completion differs from trusted digest")
        _ = try await storage.download(key:prefix+"snapshots/"+snapshotID+".json.age",destination:stage.appendingPathComponent("snapshots/"+snapshotID+".json.age"),expected:expectedManifestDigest)
        let plainManifest=stage.appendingPathComponent("manifest-verification")
        try tools.validate()
        try tools.decrypt(stage.appendingPathComponent("snapshots/"+snapshotID+".json.age"),to:plainManifest,identity:credentials.get(identityRef))
        let trustedManifest=try JSONDecoder().decode(SnapshotManifest.self,from:Data(contentsOf:plainManifest))
        try require(trustedManifest.schemaVersion==1 && trustedManifest.vaultID==vaultID && trustedManifest.snapshotID==snapshotID,"Manifest target mismatch")
        try require(Set(trustedManifest.files.flatMap{$0.chunks.map{$0.ciphertextSHA256}})==Set(c.blobCiphertextSHA256),"Completion blob inventory differs from trusted authenticated manifest")
        try FileManager.default.removeItem(at:plainManifest)
        for digest in Set(c.blobCiphertextSHA256) {
            try require(digest.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil,"Invalid blob digest")
            let relative="blobs/sha256/"+digest+".age"
            _ = try await storage.download(key:prefix+relative,destination:stage.appendingPathComponent(relative),expected:digest)
        }
        try FileManager.default.moveItem(at:stage,to:root)
        return .object(["snapshotID":.string(snapshotID),"verification":.string("full-ciphertext-and-authenticated-manifest"),"plaintextAuthenticated":.bool(false),"dedupIndexRequired":.bool(false),"nextAction":.string("Restore with primary or independent recovery identity and trusted manifest digest")])
    }
}
