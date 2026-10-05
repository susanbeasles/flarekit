import Foundation

public struct CaptureEntry: Codable {
    public let path:String
    public let sha256:String
    public let size:UInt64
}
public struct GitCaptureManifest: Codable {
    public let schemaVersion:Int
    public let kind:String
    public let capturedAt:String
    public let objectFormat:String
    public let objectIDs:[String]
    public let refs:String
    public let worktrees:String
    public let coverage:JSON
    public let entries:[CaptureEntry]
}
public func git(_ args:[String], cwd:URL) throws -> String {
    let temp=try privateDirectory(); defer { try? FileManager.default.removeItem(at:temp) }
    let file=temp.appendingPathComponent("output"); FileManager.default.createFile(atPath:file.path,contents:Data(),attributes:[.posixPermissions:0o600])
    try runChild(executable:URL(fileURLWithPath:"/usr/bin/git"),arguments:["-c","core.fsmonitor=false","-c","core.hooksPath=/dev/null"]+args,environment:["PATH":"/usr/bin:/bin","GIT_OPTIONAL_LOCKS":"0","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_TERMINAL_PROMPT":"0"],cwd:cwd,output:file)
    return String(decoding:try Data(contentsOf:file),as:UTF8.self)
}
public final class GitCapture {
    public init() {}
    public func capture(source:URL,destination:URL) throws -> JSON {
        try require(!FileManager.default.fileExists(atPath:destination.path),"Capture destination exists")
        let common=URL(fileURLWithPath:try git(["rev-parse","--path-format=absolute","--git-common-dir"],cwd:source).trimmingCharacters(in:.whitespacesAndNewlines)).standardizedFileURL
        let selectedGit=URL(fileURLWithPath:try git(["rev-parse","--absolute-git-dir"],cwd:source).trimmingCharacters(in:.whitespacesAndNewlines)).standardizedFileURL
        let sourceRoot=source.standardizedFileURL.resolvingSymlinksInPath()
        let destRoot=destination.standardizedFileURL
        try require(!destRoot.path.hasPrefix(sourceRoot.path+"/") && !destRoot.path.hasPrefix(common.path+"/"),"Capture destination must be outside repository")
        let refs=try git(["for-each-ref","--format=%(refname) %(objectname)"],cwd:source)
        let objects=try git(["cat-file","--batch-all-objects","--batch-check=%(objectname)"],cwd:source).split(separator:"\n").map(String.init).sorted()
        let format=try git(["rev-parse","--show-object-format"],cwd:source).trimmingCharacters(in:.whitespacesAndNewlines)
        let worktrees=try git(["worktree","list","--porcelain"],cwd:source)
        try FileManager.default.createDirectory(at:destination,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        var entries:[CaptureEntry]=[]; var links:[String:String]=[:]; var visited=Set<String>()
        func copyFile(_ from:URL,_ relative:String) throws {
            try safeRelative(relative)
            let values=try from.resourceValues(forKeys:[.isSymbolicLinkKey,.isRegularFileKey,.fileSizeKey,.contentModificationDateKey])
            if values.isSymbolicLink == true { links[relative]=try FileManager.default.destinationOfSymbolicLink(atPath:from.path); return }
            try require(values.isRegularFile==true,"Special files cannot be captured")
            let target=destination.appendingPathComponent(relative)
            if FileManager.default.fileExists(atPath:target.path) {
                try require(try hashFile(from).digest == hashFile(target).digest,"Object store collision"); return
            }
            try FileManager.default.createDirectory(at:target.deletingLastPathComponent(),withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
            try FileManager.default.copyItem(at:from,to:target)
            try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:target.path)
            let after=try from.resourceValues(forKeys:[.fileSizeKey,.contentModificationDateKey])
            try require(values.fileSize==after.fileSize && values.contentModificationDate==after.contentModificationDate,"File changed during capture")
            let h=try hashFile(target); entries.append(CaptureEntry(path:relative,sha256:h.digest,size:h.size))
        }
        func copyTree(_ root:URL,_ prefix:String,skip:(String)->Bool) throws {
            guard let iterator=FileManager.default.enumerator(at:root,includingPropertiesForKeys:[.isDirectoryKey,.isSymbolicLinkKey],options:[]) else { return }
            for case let file as URL in iterator {
                let relative=try relativeEntryPath(file,under:root)
                if skip(relative) { iterator.skipDescendants(); continue }
                let values=try file.resourceValues(forKeys:[.isDirectoryKey,.isSymbolicLinkKey])
                if values.isDirectory==true && values.isSymbolicLink != true { continue }
                try copyFile(file,prefix+"/"+relative)
            }
        }
        func copyObjectStore(_ root:URL) throws {
            let resolved=root.resolvingSymlinksInPath().standardizedFileURL
            guard visited.insert(resolved.path).inserted else { return }
            try require(FileManager.default.fileExists(atPath:resolved.path),"Alternate object store is unavailable")
            try copyTree(resolved,"git/objects",skip:{ $0=="info/alternates" || $0=="info/http-alternates" || $0.hasSuffix(".lock") })
            let alternates=resolved.appendingPathComponent("info/alternates")
            if FileManager.default.fileExists(atPath:alternates.path) {
                for path in try String(contentsOf:alternates,encoding:.utf8).split(separator:"\n").map(String.init) {
                    try require(!path.hasPrefix("\""),"Quoted alternates require explicit handling")
                    let next=path.hasPrefix("/") ? URL(fileURLWithPath:path) : resolved.appendingPathComponent(path)
                    try copyObjectStore(next)
                }
            }
            if FileManager.default.fileExists(atPath:resolved.appendingPathComponent("info/http-alternates").path) { throw FKError("unsupported","HTTP alternate data is not locally available",stage:"capture") }
        }
        do {
            try copyObjectStore(common.appendingPathComponent("objects"))
            for name in ["refs","logs"] { try copyTree(common.appendingPathComponent(name),"git/"+name,skip:{ $0.hasSuffix(".lock") }) }
            for name in ["packed-refs","shallow"] { let f=common.appendingPathComponent(name); if FileManager.default.fileExists(atPath:f.path) { try copyFile(f,"git/"+name) } }
            for name in ["HEAD","index"] { let f=selectedGit.appendingPathComponent(name); if FileManager.default.fileExists(atPath:f.path) { try copyFile(f,"git/"+name) } }
            // Unsafe executable/configuration material is retained only in quarantine.
            for name in ["config","config.worktree"] { let f=common.appendingPathComponent(name); if FileManager.default.fileExists(atPath:f.path) { try copyFile(f,"quarantine/"+name) } }
            try copyTree(common.appendingPathComponent("hooks"),"quarantine/hooks",skip:{_ in false})
            try copyTree(common.appendingPathComponent("worktrees"),"relationships/worktrees",skip:{$0.hasSuffix(".lock")})
            try copyTree(common.appendingPathComponent("lfs/objects"),"external/lfs",skip:{_ in false})
            // The selected working directory includes staged/unstaged/untracked/ignored bytes.
            let bare=try git(["rev-parse","--is-bare-repository"],cwd:source).trimmingCharacters(in:.whitespacesAndNewlines)=="true"
            if !bare { try copyTree(source,"working-tree",skip:{$0==".git" || $0.hasSuffix("/.git") || $0.hasPrefix(".git/")}) }
            var linkedTrees:[String:String]=[:]
            for line in worktrees.split(separator:"\n").map(String.init) where line.hasPrefix("worktree ") {
                let path=String(line.dropFirst(9)); try require(!path.hasPrefix("\""),"Quoted worktree paths require explicit handling")
                let tree=URL(fileURLWithPath:path).standardizedFileURL.resolvingSymlinksInPath()
                if tree.path==sourceRoot.path || bare { continue }
                let id=String(sha256(Data(path.utf8)).prefix(24)); linkedTrees[id]=path
                try copyTree(tree,"linked-trees/"+id,skip:{$0==".git" || $0.hasSuffix("/.git") || $0.hasPrefix(".git/")})
            }
            // Retain every locally present nested Git store, including deinitialized
            // submodule stores. Their configuration and hooks remain quarantined.
            try copyTree(common.appendingPathComponent("modules"),"relationships/submodule-stores",skip:{$0.hasSuffix(".lock")})
            let relationshipData=try JSONEncoder().encode(linkedTrees)
            try writePrivate(relationshipData,to:destination.appendingPathComponent("linked-trees.json"))
            let relationshipsHash=try hashFile(destination.appendingPathComponent("linked-trees.json")); entries.append(.init(path:"linked-trees.json",sha256:relationshipsHash.digest,size:relationshipsHash.size))
            let linkData=try JSONEncoder().encode(links); try writePrivate(linkData,to:destination.appendingPathComponent("symlinks.json"))
            let linkHash=try hashFile(destination.appendingPathComponent("symlinks.json")); entries.append(.init(path:"symlinks.json",sha256:linkHash.digest,size:linkHash.size))
            let currentRefs=try git(["for-each-ref","--format=%(refname) %(objectname)"],cwd:source)
            try require(refs==currentRefs,"Refs changed during capture; retry with a quiescent source")
            let coverage:JSON = .object(["refs":.string("captured"),"reflogs":.string("captured"),"objects":.string("all-locally-available"),"index":.string("selected-index-and-linked-index-records"),"workingTree":.string(bare ? "not-applicable" : "selected-tree-including-ignored-and-untracked"),"linkedWorktrees":.string("working-directories-and-admin-records-captured; automatic-reconstruction-deferred"),"configuration":.string("local-files-quarantined; include-files-and-global-config-not-captured"),"hooks":.string("quarantined-never-activated"),"alternates":.string("primary-object-store-materialized-locally"),"lfs":.string("locally-present-only; external-completeness-unverified"),"submodules":.string("local-module-stores-and-tree-bytes-retained; nested-alternates-and-external-history-unverified"),"symlinks":.string("targets-recorded-never-followed"),"pointInTime":.bool(false),"modeACLXattrs":.string("not-captured")])
            let m=GitCaptureManifest(schemaVersion:1,kind:"git-local-capture",capturedAt:ISO8601DateFormatter().string(from:Date()),objectFormat:format,objectIDs:objects,refs:refs,worktrees:worktrees,coverage:coverage,entries:entries.sorted{$0.path<$1.path})
            let data=try JSONEncoder().encode(m); try writePrivate(data,to:destination.appendingPathComponent("manifest.json"))
            _ = try verify(capture:destination,expectedManifestDigest:sha256(data))
            return .object(["manifestDigest":.string(sha256(data)),"objectCount":.number(Double(objects.count)),"coverage":coverage,"encrypted":.bool(false),"completedArchive":.bool(false),"warning":.string("Private local capture only; remote encrypted archive publication awaits format review")])
        } catch { try? FileManager.default.removeItem(at:destination); throw error }
    }
    public func verify(capture:URL,expectedManifestDigest:String) throws -> JSON {
        let capture=capture.standardizedFileURL.resolvingSymlinksInPath()
        let data=try Data(contentsOf:capture.appendingPathComponent("manifest.json"))
        try require(sha256(data)==expectedManifestDigest,"Manifest digest differs from trusted input")
        let manifest=try JSONDecoder().decode(GitCaptureManifest.self,from:data)
        try require(manifest.schemaVersion==1 && manifest.kind=="git-local-capture","Unsupported capture format")
        var paths=Set<String>(); var bytes:UInt64=0
        for entry in manifest.entries {
            try safeRelative(entry.path); try require(paths.insert(entry.path).inserted,"Duplicate capture path")
            let file=capture.appendingPathComponent(entry.path)
            try require(file.resolvingSymlinksInPath().path==file.standardizedFileURL.path,"Symlink traversal in capture")
            let hash=try hashFile(file); guard hash.digest==entry.sha256 && hash.size==entry.size else { throw FKError("integrity","Capture content checksum mismatch",stage:"verification") }; bytes+=hash.size
        }
        return .object(["verification":.string("full"),"checkedBytes":.string(String(bytes)),"checkedFiles":.number(Double(paths.count)),"manifestDigest":.string(expectedManifestDigest)])
    }
    public func restore(capture:URL,destination:URL,expectedManifestDigest:String) throws -> JSON {
        let verified=try verify(capture:capture,expectedManifestDigest:expectedManifestDigest)
        try require(!FileManager.default.fileExists(atPath:destination.path),"Restore destination exists")
        let m=try JSONDecoder().decode(GitCaptureManifest.self,from:Data(contentsOf:capture.appendingPathComponent("manifest.json")))
        try require(["sha1","sha256"].contains(m.objectFormat),"Unsupported Git object format")
        try FileManager.default.createDirectory(at:destination,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        do {
            _ = try git(["init","--object-format="+m.objectFormat],cwd:destination)
            for entry in m.entries {
                var relative:String?
                if entry.path.hasPrefix("git/") {
                    let path=String(entry.path.dropFirst(4))
                    if ["HEAD","packed-refs","shallow","index"].contains(path) || path.hasPrefix("objects/") || path.hasPrefix("refs/") || path.hasPrefix("logs/") { relative=".git/"+path }
                } else if entry.path.hasPrefix("working-tree/") { relative=String(entry.path.dropFirst(13)); try require(!relative!.split(separator:"/").contains(".git"),"Unsafe nested Git control directory") }
                guard let relative else { continue }; try safeRelative(relative)
                let target=destination.appendingPathComponent(relative)
                try FileManager.default.createDirectory(at:target.deletingLastPathComponent(),withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
                if FileManager.default.fileExists(atPath:target.path) { try FileManager.default.removeItem(at:target) }
                try FileManager.default.copyItem(at:capture.appendingPathComponent(entry.path),to:target)
                try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:target.path)
            }
            _ = try git(["fsck","--full"],cwd:destination)
            let ids=try git(["cat-file","--batch-all-objects","--batch-check=%(objectname)"],cwd:destination).split(separator:"\n").map(String.init).sorted()
            try require(ids==m.objectIDs,"Restored object inventory differs")
            let refs=try git(["for-each-ref","--format=%(refname) %(objectname)"],cwd:destination)
            try require(refs==m.refs,"Restored refs differ")
            return .object(["verified":verified,"gitFsck":.bool(true),"allLocalObjectsRestored":.bool(true),"refsRestored":.bool(true),"unsafeConfigAndHooksActivated":.bool(false),"linkedWorktreesReconstructed":.bool(false),"symlinksActivated":.bool(false),"coverage":m.coverage])
        } catch { try? FileManager.default.removeItem(at:destination); throw error }
    }
}
