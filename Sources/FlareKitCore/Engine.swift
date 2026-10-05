import Foundation

public final class Engine {
    public let configuration:Configuration
    public let credentials:Credentials
    public let transport:Transport
    public let adapter:AdapterPaths?
    public let age:AgeTools?
    public init(configuration:Configuration,credentials:Credentials = Credentials(),transport:Transport = Network(),adapter:AdapterPaths? = nil,age:AgeTools? = nil) {
        self.configuration=configuration; self.credentials=credentials; self.transport=transport; self.adapter=adapter; self.age=age
    }
    public func execute(_ request:Request,secretInput:Data?=nil) async throws -> Result {
        try require(request.schemaVersion==1 && !request.requestID.isEmpty,"Unsupported request version or missing requestID")
        try configuration.validate()
        let params=request.parameters
        func string(_ name:String) throws -> String { guard let value=params[name].string, !value.isEmpty else { throw FKError("validation","Missing required parameter: "+name) }; return value }
        var output:JSON
        switch request.operation {
        case .vaultInitialize,.snapshotCreate,.snapshotRestore,.snapshotPublish,.snapshotFetch,.snapshotVerify:
            guard let age else { throw FKError("unsupported","Set trusted FK_AGE and FK_AGE_KEYGEN executable paths") }
            let input=try params.decode(SnapshotInput.self); try input.identity.validate(); try input.recoveryIdentity?.validate()
            let vault=AgeVault(root:URL(fileURLWithPath:input.vault),tools:age,credentials:credentials)
            switch request.operation {
            case .vaultInitialize:
                guard let recovery=input.recoveryIdentity else { throw FKError("validation","Independent recovery identity required") }
                output=try vault.initialize(primary:input.identity,recovery:recovery)
            case .snapshotCreate: output=try vault.create(source:URL(fileURLWithPath:string("source")),identityRef:input.identity)
            case .snapshotRestore: output=try vault.restore(snapshotID:string("snapshotID"),destination:URL(fileURLWithPath:string("destination")),expectedManifestDigest:string("expectedManifestDigest"),identityRef:input.identity)
            case .snapshotVerify: output=try vault.verify(snapshotID:string("snapshotID"),expectedManifestDigest:string("expectedManifestDigest"),mode:string("verification"),byteBudget:UInt64(params["byteBudget"].string ?? "") ?? 0,requestBudget:UInt64(params["requestBudget"].string ?? "") ?? 0,seed:params["seed"].string ?? request.requestID)
            default:
                let profile=try configuration.selected(request.profile,operation:request.operation)
                try require(profile.group.purpose != "controller-receipts","Archive operations cannot target controller receipt profiles")
                let storage=try R2(profile:profile,credentials:credentials,transport:transport)
                if request.operation == .snapshotPublish { output=try await vault.publish(snapshotID:string("snapshotID"),expectedManifestDigest:string("expectedManifestDigest"),storage:storage,verification:string("verification")) }
                else { output=try await vault.fetch(snapshotID:string("snapshotID"),vaultID:string("vaultID"),expectedManifestDigest:string("expectedManifestDigest"),identityRef:input.identity,storage:storage) }
            }
        case .configurationValidate: output = .object(["valid":.bool(true)])
        case .credentialEnroll:
            let reference=try string("reference")
            guard let secretInput else { throw FKError("validation","Enrollment requires secret stdin with a request file") }
            try credentials.enroll(reference:reference,secret:secretInput); output = .object(["enrolled":.bool(true)])
        case .gitCapture:
            output=try GitCapture().capture(source:URL(fileURLWithPath:string("source")),destination:URL(fileURLWithPath:string("destination")))
        case .gitVerify:
            output=try GitCapture().verify(capture:URL(fileURLWithPath:string("capture")),expectedManifestDigest:string("expectedManifestDigest"))
        case .gitRestore:
            output=try GitCapture().restore(capture:URL(fileURLWithPath:string("capture")),destination:URL(fileURLWithPath:string("destination")),expectedManifestDigest:string("expectedManifestDigest"))
        default:
            let profile=try configuration.selected(request.profile,operation:request.operation)
            switch request.operation {
            case .multipartUpload,.multipartAbort:
                let journal=URL(fileURLWithPath:try string("journal"))
                if request.operation == .multipartUpload { _ = try string("key"); _ = try string("file"); _ = try string("verification") }
                let storage=try R2(profile:profile,credentials:credentials,transport:transport)
                if request.operation == .multipartAbort { try require(params["approveAbort"].bool==true,"Explicit abort approval required"); output=try await storage.abortMultipart(journalURL:journal) }
                else {
                    let management=try Cloudflare(profile:profile,credentials:credentials,transport:transport)
                    output=try await storage.multipartUpload(key:string("key"),source:URL(fileURLWithPath:string("file")),journalURL:journal,management:management,verification:string("verification"))
                }
            case .objectUpload,.objectDownload,.objectList,.objectInspect,.objectVerify:
                let input=try params.decode(ObjectInput.self)
                if request.operation != .objectList { _ = try string("key") }
                if request.operation == .objectUpload { _ = try string("file"); try require(["full","metadata"].contains(input.verification ?? ""),"Choose verification: full or metadata") }
                if request.operation == .objectDownload { _ = try string("destination"); _ = try string("expectedSHA256") }
                if request.operation == .objectVerify { _ = try string("expectedSHA256") }
                let storage=try R2(profile:profile,credentials:credentials,transport:transport)
                switch request.operation {
                case .objectUpload: output=try await storage.upload(key:string("key"),source:URL(fileURLWithPath:string("file")),verification:input.verification!)
                case .objectDownload: output=try await storage.download(key:string("key"),destination:URL(fileURLWithPath:string("destination")),expected:string("expectedSHA256"))
                case .objectInspect: output=try await storage.inspect(key:string("key"))
                case .objectVerify: output=try await storage.verify(key:string("key"),expected:string("expectedSHA256"))
                default: output=try await storage.list(prefix:input.prefix ?? "",token:input.continuationToken)
                }
            case .bucketInspect,.bucketCreate,.retentionInspect,.retentionApply:
                let bucket=try params["bucket"].string ?? profile.bucket ?? string("bucket")
                try validateBucket(bucket)
                if request.operation == .retentionApply { _ = try string("expectedDigest"); try validateLockRules(params["rules"]); try require(params["acknowledgeAdministratorRemoval"].bool == true,"Acknowledge administrator-removable retention") }
                let cloud=try Cloudflare(profile:profile,credentials:credentials,transport:transport)
                switch request.operation {
                case .bucketCreate: try require(params["approveCreate"].bool == true,"Explicit bucket create approval required"); output=try await cloud.createBucket(bucket)
                case .bucketInspect: output=try await cloud.inspectBucket(bucket)
                case .retentionInspect: let locks=try await cloud.locks(bucket); output = .object(["rules":locks,"digest":.string(sha256(try locks.encoded())),"administratorRemovable":.bool(true)])
                default: output=try await cloud.applyLocks(bucket,expectedDigest:string("expectedDigest"),rules:params["rules"])
                }
            case .workerPlan,.workerApply:
                let input=try params.decode(WorkerInput.self); try validateWorkerConfig(input.configuration,account:profile.accountID)
                guard let root=input.sourceDirectory else { throw FKError("validation","sourceDirectory required") }
                let artifact=try workerArtifact(URL(fileURLWithPath:root).standardizedFileURL)
                try require(artifact.array!.contains{$0["path"].string==input.configuration["main"].string},"Main module not present in reviewed source directory")
                for ref in (input.secretReferences ?? [:]).values { try ref.validate() }
                for ref in (input.secretReferences ?? [:]).values { try require((profile.allowedWorkerSecretReferences ?? []).contains(ref.reference),"Worker secret reference is not allowed by the profile") }
                let recoveryRefs=Set(configuration.vaults.flatMap{$0.recoveryReferences})
                for ref in (input.secretReferences ?? [:]).values { try require(!recoveryRefs.contains(ref.reference),"Archive recovery material cannot be installed into a Worker") }
                for b in input.configuration["r2_buckets"].array ?? [] { try require((profile.allowedWorkerBucketNames ?? []).contains(b["bucket_name"].string ?? ""),"Worker bucket binding is not allowed by the profile") }
                if profile.group.purpose=="controller-receipts" {
                    let archiveBuckets=Set(configuration.profiles.values.filter{$0.accountID==profile.accountID && $0.group.purpose=="repository-archives"}.compactMap{$0.bucket})
                    for b in input.configuration["r2_buckets"].array ?? [] { try require(!archiveBuckets.contains(b["bucket_name"].string ?? ""),"Controller Workers cannot bind registered repository archive buckets") }
                }
                let workers=try Workers(profile:profile,credentials:credentials,adapter:adapter,transport:transport)
                if request.operation == .workerPlan { let plan=try await workers.plan(input); output = .object(["plan":plan,"planDigest":.string(sha256(try plan.encoded()))]) }
                else { output=try await workers.apply(input) }
            case .workerInspect:
                let name=try string("name"); try require(name.range(of:"^[a-z0-9][a-z0-9-]{0,62}$",options:.regularExpression) != nil,"Invalid Worker name")
                output=try await Workers(profile:profile,credentials:credentials,adapter:adapter,transport:transport).inspect(name)
            case .workerPromote,.workerSecretStage:
                let input=try params.decode(WorkerInput.self); try validateWorkerConfig(input.configuration,account:profile.accountID)
                let expected=try string("expectedDeploymentDigest")
                for ref in (input.secretReferences ?? [:]).values { try ref.validate(); try require((profile.allowedWorkerSecretReferences ?? []).contains(ref.reference),"Worker secret reference is not allowed by profile") }
                let workers=try Workers(profile:profile,credentials:credentials,adapter:adapter,transport:transport)
                output=try await workers.changeVersion(input,action:request.operation == .workerPromote ? "promote" : "secret-stage",expectedDeploymentDigest:expected)
            default: throw FKError("unsupported","Operation not implemented")
            }
        }
        return Result(requestID:request.requestID,operation:request.operation,status:"succeeded",output:output)
    }
}
