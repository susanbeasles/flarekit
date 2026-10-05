import Foundation
import FlareKitCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

@main struct CLI {
    static func main() async {
        var id="unknown"; var jsonMode=false
        do {
            let args=Array(CommandLine.arguments.dropFirst())
            if args.isEmpty || args.contains("--help") || args.contains("-h") {
                let words=args.prefix(while:{!$0.hasPrefix("-")})
                if let operation=Operation(rawValue:words.joined(separator:".")),let details=commandDetails[operation] {
                    print("fk \(words.joined(separator:" ")) — \(details.0)\n\nUsage: fk \(words.joined(separator:" ")) --parameters FILE [--profile NAME] [--config FILE] [--json]\nRequired JSON parameters: \(details.1)\nEffects/credentials: \(details.2)\nOutput: schema-v1 JSON with status, output or redacted error.\nRecovery: collisions preserve existing data; after uncertain mutation, inspect remote state before retrying.\nReference: docs/CLI.md\n"); exit(0)
                }
                print(help); exit(0)
            }
            if args==["--version"] { print("FlareKit 0.1.0-dev (schema 1)"); exit(0) }
            var options:[String:String]=[:]; var words:[String]=[]; var i=0
            while i<args.count {
                let arg=args[i]
                if arg=="--json" { jsonMode=true; i+=1; continue }
                if arg.hasPrefix("--") {
                    try require(i+1<args.count,"Option value required")
                    try require(options[arg]==nil,"Duplicate option")
                    options[arg]=args[i+1]; i+=2
                } else { words.append(arg); i+=1 }
            }
            let allowed:Set<String>=["--request","--config","--parameters","--profile"]
            try require(Set(options.keys).isSubset(of:allowed),"Unknown option; see --help")
            let request:Request
            if words==["run"] {
                jsonMode=true
                guard let path=options["--request"] else { throw FKError("validation","fk run requires --request FILE or -") }
                let data=path=="-" ? FileHandle.standardInput.readDataToEndOfFile() : try Data(contentsOf:URL(fileURLWithPath:path))
                try require(data.count<=2*1024*1024,"Request exceeds limit")
                request=try JSONDecoder().decode(Request.self,from:data)
            } else {
                guard let op=Operation(rawValue:words.joined(separator:".")),let path=options["--parameters"] else { throw FKError("validation","Use a documented operation and --parameters FILE") }
                let data=try Data(contentsOf:URL(fileURLWithPath:path)); try require(data.count<=2*1024*1024,"Parameters exceed limit")
                request=Request(operation:op,profile:options["--profile"],parameters:try JSONDecoder().decode(JSON.self,from:data))
            }
            id=request.requestID
            let config:Configuration
            if let path=options["--config"] {
                let data=try Data(contentsOf:URL(fileURLWithPath:path)); try require(data.count<=2*1024*1024,"Configuration exceeds limit")
                let decoder=JSONDecoder(); decoder.dateDecodingStrategy = .iso8601; config=try decoder.decode(Configuration.self,from:data)
            } else { config=try JSONDecoder().decode(Configuration.self,from:Data("{\"schemaVersion\":1,\"profiles\":{},\"vaults\":[]}".utf8)) }
            let environment=ProcessInfo.processInfo.environment
            var adapter:AdapterPaths?
            if let node=environment["FK_NODE"],let script=environment["FK_WORKER_ADAPTER"] {
                try require(node.hasPrefix("/") && script.hasPrefix("/"),"Adapter paths must be absolute and trusted")
                adapter=AdapterPaths(node:URL(fileURLWithPath:node),script:URL(fileURLWithPath:script))
            }
            let secret=request.operation == .credentialEnroll ? FileHandle.standardInput.readDataToEndOfFile() : nil
            var age:AgeTools?
            if let binary=environment["FK_AGE"],let keygen=environment["FK_AGE_KEYGEN"] {
                try require(binary.hasPrefix("/") && keygen.hasPrefix("/"),"age executable paths must be absolute and trusted")
                age=AgeTools(age:URL(fileURLWithPath:binary),keygen:URL(fileURLWithPath:keygen))
            }
            let result=try await Engine(configuration:config,adapter:adapter,age:age).execute(request,secretInput:secret)
            let e=JSONEncoder(); e.outputFormatting=[.sortedKeys,.withoutEscapingSlashes]; e.dateEncodingStrategy = .iso8601
            if jsonMode { print(String(decoding:try e.encode(result),as:UTF8.self)) }
            else { print("\(result.operation.rawValue): \(result.status)"); print(String(decoding:try result.output.encoded(),as:UTF8.self)) }
            exit(0)
        } catch {
            let failure=(error as? FKError) ?? FKError("validation","Local operation failed; raw error omitted to protect paths and secrets")
            let envelope:JSON = .object(["schemaVersion":.number(1),"requestID":.string(id),"status":.string("failed"),"error":(try? .value(failure)) ?? .null])
            if jsonMode { print(String(decoding:(try? envelope.encoded()) ?? Data(),as:UTF8.self)) }
            else { FileHandle.standardError.write(Data("\(failure.code) at \(failure.stage): \(failure.message)\n".utf8)) }
            exit(failure.exitCode)
        }
    }
    static let help="""
    FlareKit — fk 0.1.0-dev
    Native operations for private Cloudflare storage and generic Worker deployment.

    Usage:
      fk run --request FILE|- [--config FILE]
      fk OPERATION WORDS --parameters FILE [--profile NAME] [--config FILE] [--json]
      fk --version

    Examples:
      fk storage object upload --parameters upload.json --profile personal --config config.json --json
      fk worker plan --parameters worker.json --profile personal --config config.json --json
      fk archive git capture --parameters capture.json --json

    Implemented operations:
      configuration validate       Validate policy before retrieving any credentials.
      credential enroll            Add a new macOS Keychain identity; secret from stdin.
      storage bucket create        Create private destination; requires approveCreate=true.
      storage bucket inspect       Inspect metadata and public domain exposure.
      storage retention inspect    Read lock rules and review digest.
      storage retention apply      Apply reviewed lock rules and verify readback.
      storage object upload        Conditional streaming PUT; full or metadata verification.
      storage object download      Download and validate trusted SHA-256; never overwrite.
      storage object list          List one page; return continuationToken explicitly.
      storage object inspect       Metadata only; does not prove content integrity.
      storage object verify        Read complete object and compare trusted SHA-256.
      worker plan                  Hash prebuilt code/config and read deployment baseline.
      worker apply                 Apply exact reviewed plan; migrations activate code.
      worker inspect               Read deployment and binding IDs; omit secret values.
      worker promote               Activate an existing version; code-only rollback.
      worker secret stage          Create a secret-bearing version without traffic activation.
      storage multipart upload     Resumable parts; requires existing Indefinite lock.
      storage multipart abort      Explicitly abort an incomplete upload using its journal.
      archive git capture          Private local staging capture; NOT encrypted publication.
      archive git verify           Full local capture hash verification.
      archive git restore          Fresh restore, fsck, refs and all-object inventory check.
      archive vault initialize     Test independent age identities and initialize a vault.
      archive snapshot create      Encrypt new chunks and reuse vault ciphertext across snapshots.
      archive snapshot publish     R2 blobs first, completion last; explicit verification mode.
      archive snapshot fetch       Fetch from R2 and authenticate the manifest/blob inventory.
      archive snapshot restore     Verify/decrypt with primary or independent recovery identity.
      archive snapshot verify      Budgeted metadata/full/sampled local ciphertext checks.

    Security and requirements:
      Select an explicit profile for remote operations; credentials are references only.
      R2 object access needs bucket-scoped S3 credentials; administration needs a separate token.
      Workers use pinned adapter; configure trusted absolute FK_NODE and FK_WORKER_ADAPTER.
      Credential enrollment reads stdin; use a request FILE, never --request - for enrollment.
      Git operations require /usr/bin/git. No source Git mutation or automatic hook activation.
      Exit codes: 0 success; 2 validation; 3 authorization; 4 collision; 5 integrity;
                  6 drift; 7 transport/deployment; 8 unavailable capability.
      --json emits one schema-v1 result; secrets and raw remote/subprocess errors are omitted.
      No hosted service, replica adapter, distributed writer or tail is released.
      Live Cloudflare and macOS release qualification remain pending.
      See docs/CLI.md for parameters, costs, exact guarantees and recovery.
    """
    static let commandDetails:[FlareKitCore.Operation:(String,String,String)] = [
      .configurationValidate:("Validate local policy","{}","No credential access or remote mutation"),
      .credentialEnroll:("Enroll a new Keychain identity","reference; secret bytes from stdin","macOS Keychain only; existing value is never replaced"),
      .bucketCreate:("Create a private R2 destination","bucket, approveCreate=true","Bucket management credential; creates remotely and reads public exposure"),
      .bucketInspect:("Inspect private/public bucket state","bucket","Bucket management read; no mutation"),
      .retentionInspect:("Read retention rules and review digest","bucket","Bucket management read; no mutation"),
      .retentionApply:("Apply explicit reviewed retention","bucket, expectedDigest, rules={rules:[...]}, acknowledgeAdministratorRemoval=true","Management write; replaces rules, reads back; administrators can remove locks"),
      .objectUpload:("Conditionally upload an object","key, file, verification=metadata|full","Bucket-scoped S3 write/read; collision never overwrites; full mode rereads all bytes"),
      .objectDownload:("Download and verify into a fresh file","key, destination, expectedSHA256","Bucket-scoped S3 read; full read and SHA-256 validation"),
      .objectInspect:("Inspect declared metadata","key","Bucket-scoped S3 read; does not verify content"),
      .objectList:("List one paginated object page","optional prefix, continuationToken","Bucket-scoped S3 list; return token for next page"),
      .objectVerify:("Read and checksum all object bytes","key, expectedSHA256","Bucket-scoped S3 read; full-read costs apply"),
      .multipartUpload:("Upload/resume bounded parts","key, file, journal, verification=metadata|full","S3 read/write and separate management read; existing Indefinite lock required"),
      .multipartAbort:("Abort an unfinished upload","journal, approveAbort=true","S3 multipart abort; no completed object deletion"),
      .workerPlan:("Review code/config/deployment effects","sourceDirectory, configuration, mode; optional secretReferences","Worker token reads baseline; only references enter plan; migrations activate in deploy mode"),
      .workerApply:("Apply the exact reviewed deployment","sourceDirectory, configuration, mode, approvedPlan, approvedPlanDigest","Worker deployment token plus allowed secret refs; upload or activation; API readback"),
      .workerInspect:("Inspect deployment and binding IDs","name","Worker read token; returns deploymentDigest and safe bindings"),
      .workerPromote:("Activate an existing version","configuration, versionID, expectedDeploymentDigest","Worker deployment token; activates 100%; does not undo data/migrations"),
      .workerSecretStage:("Stage secrets without activating traffic","configuration, secretReferences, expectedDeploymentDigest","Worker token plus allowed secret refs; creates version; traffic readback"),
      .gitCapture:("Capture local Git objects and relationship records","source, destination","Local Git; private plaintext staging, explicit coverage; source not rewritten"),
      .gitVerify:("Verify private local capture","capture, expectedManifestDigest","Local full read; rejects tampered paths/content"),
      .gitRestore:("Restore primary Git history into fresh destination","capture, destination, expectedManifestDigest","Local Git; refs/all objects/fsck; hooks/config remain quarantined"),
      .vaultInitialize:("Initialize a recoverable age vault","vault, identity, recoveryIdentity","Both independently generated native age identities tested locally; no remote operation"),
      .snapshotCreate:("Create an incremental encrypted snapshot","vault, source, identity","Operational age identity; immutable ciphertext reuse; local writer lock"),
      .snapshotPublish:("Publish complete encrypted snapshot to R2","vault, snapshotID, expectedManifestDigest, identity, verification","S3 credentials only retrieved; blobs first, completion last; no primary eviction"),
      .snapshotFetch:("Fetch independently restorable ciphertext","vault, vaultID, snapshotID, expectedManifestDigest, identity","S3 read and selected restore identity; authenticated manifest bounds blob fetches"),
      .snapshotRestore:("Restore with primary or recovery identity","vault, snapshotID, destination, expectedManifestDigest, identity","Selected age identity; full authenticated plaintext; fresh destination only"),
      .snapshotVerify:("Budget local integrity checks","vault, snapshotID, expectedManifestDigest, identity, verification, byteBudget, requestBudget; optional seed","No identity retrieved for ciphertext-only checks; reports actual coverage")
    ]
}
