import Foundation

public struct WorkerInput: Codable {
    public let sourceDirectory: String?
    public let configuration: JSON
    public let secretReferences: [String: CredentialReference]?
    public let mode: String?
    public let sourceSHA: String?
    public let approvedPlan: JSON?
    public let approvedPlanDigest: String?
    public let versionID: String?
}
public struct AdapterPaths { public let node: URL; public let script: URL; public init(node: URL, script: URL) { self.node = node; self.script = script } }
public func processJSON(executable: URL, arguments: [String], input: Data, environment: [String:String]) throws -> JSON {
    let stage = try privateDirectory(); defer { try? FileManager.default.removeItem(at: stage) }
    let result = stage.appendingPathComponent("result"); FileManager.default.createFile(atPath: result.path, contents: Data(), attributes:[.posixPermissions:0o600])
    try runChild(executable:executable,arguments:arguments,input:input,environment:environment,output:result,timeout:200)
    let data = try Data(contentsOf:result); try require(data.count <= 1024 * 1024, "Adapter response exceeds limit")
    return try JSONDecoder().decode(JSON.self, from:data)
}
public func validateWorkerConfig(_ config: JSON, account: String) throws {
    guard let fields = config.object else { throw FKError("validation", "Worker configuration must be an object") }
    let allowed: Set<String> = ["name","main","account_id","compatibility_date","compatibility_flags","workers_dev","routes","durable_objects","migrations","r2_buckets","vars","rules","find_additional_modules"]
    try require(Set(fields.keys).isSubset(of:allowed), "Worker configuration contains unsupported fields; build hooks and implicit tool configuration are forbidden")
    guard let name = config["name"].string else { throw FKError("validation", "Worker name required") }
    try require(name.range(of:"^[a-z0-9][a-z0-9-]{0,62}$",options:.regularExpression) != nil, "Invalid Worker name")
    try require(config["account_id"].string == nil || config["account_id"].string == account, "Worker account differs from selected profile")
    try require(config["workers_dev"].bool != nil, "Explicit workers_dev selection is required")
    guard let date = config["compatibility_date"].string else { throw FKError("validation", "Compatibility date required") }
    try require(date.range(of:"^20[0-9]{2}-[0-9]{2}-[0-9]{2}$", options:.regularExpression) != nil,"Invalid compatibility date")
    if let main = config["main"].string { try safeRelative(main) }
    for b in config["r2_buckets"].array ?? [] { guard let name = b["bucket_name"].string else { throw FKError("validation","R2 bucket name required") }; try validateBucket(name) }
}
public func workerArtifact(_ root: URL) throws -> JSON {
    guard let iterator = FileManager.default.enumerator(at:root,includingPropertiesForKeys:[.isRegularFileKey,.isDirectoryKey,.isSymbolicLinkKey],options:[]) else { throw FKError("validation","Source directory unavailable") }
    var entries:[JSON] = []
    for case let file as URL in iterator {
        let values = try file.resourceValues(forKeys:[.isRegularFileKey,.isDirectoryKey,.isSymbolicLinkKey])
        try require(values.isSymbolicLink != true,"Worker source cannot contain symlinks")
        if values.isDirectory == true { continue }
        try require(values.isRegularFile == true && ["js","mjs","wasm"].contains(file.pathExtension),"Worker source must contain only prebuilt JS/MJS/WASM modules")
        let relative = try relativeEntryPath(file,under:root)
        let h = try hashFile(file)
        entries.append(.object(["path":.string(relative),"sha256":.string(h.digest),"size":.string(String(h.size))]))
    }
    return .array(entries.sorted { $0["path"].string! < $1["path"].string! })
}
public final class Workers {
    let profile:Profile; let credentials:Credentials; let cloud:Cloudflare; let adapter:AdapterPaths?
    public init(profile:Profile,credentials:Credentials,adapter:AdapterPaths?,transport:Transport = Network()) throws {
        self.profile=profile; self.credentials=credentials; self.adapter=adapter; self.cloud=try Cloudflare(profile:profile,credentials:credentials,worker:true,transport:transport)
    }
    func current(_ name:String) async throws -> JSON {
        do { return try await cloud.call("GET",path:["workers","scripts",name,"deployments"]) }
        catch let e as FKError where e.httpStatus == 404 { return .null }
    }
    public func validateAuthority(_ input:WorkerInput) throws {
        try validateWorkerConfig(input.configuration,account:profile.accountID)
        let allowedBuckets=Set(profile.allowedWorkerBucketNames ?? [])
        for binding in input.configuration["r2_buckets"].array ?? [] {
            try require(allowedBuckets.contains(binding["bucket_name"].string ?? ""),"Worker R2 binding is not allowed by the profile")
        }
        let allowedSecrets=Set(profile.allowedWorkerSecretReferences ?? [])
        for ref in (input.secretReferences ?? [:]).values { try ref.validate(); try require(allowedSecrets.contains(ref.reference),"Worker secret reference is not allowed by the profile") }
    }
    public func inspect(_ name:String) async throws -> JSON {
        try require(name.range(of:"^[a-z0-9][a-z0-9-]{0,62}$", options:.regularExpression) != nil,"Invalid Worker name")
        let deployments=try await current(name)
        let settings=try await cloud.call("GET",path:["workers","scripts",name,"settings"])
        let bindings = (settings["bindings"].array ?? []).map { b in
            JSON.object(Dictionary(uniqueKeysWithValues:["name","type","namespace_id","bucket_name","class_name"].compactMap { k in b[k] == .null ? nil : (k,b[k]) }))
        }
        return .object(["deployments":deployments,"deploymentDigest":.string(sha256(try deployments.encoded())),"bindings":.array(bindings)])
    }
    public func plan(_ input:WorkerInput) async throws -> JSON {
        try validateAuthority(input)
        guard let root=input.sourceDirectory else { throw FKError("validation","Prebuilt sourceDirectory required") }
        let artifact=try workerArtifact(URL(fileURLWithPath:root).standardizedFileURL)
        try require(!artifact.array!.isEmpty,"Worker artifact is empty")
        let mode=input.mode ?? "upload"
        try require(["upload","deploy","dry-run"].contains(mode),"Invalid deployment mode")
        let migrations = input.configuration["migrations"].array ?? []
        try require(mode != "upload" || migrations.isEmpty,"Migration-bearing configuration requires activating deploy mode")
        for (key,ref) in input.secretReferences ?? [:] { try require(key.range(of:"^[A-Z][A-Z0-9_]{0,127}$",options:.regularExpression) != nil,"Invalid secret binding name"); try ref.validate() }
        let current = mode == "dry-run" ? JSON.null : try await current(input.configuration["name"].string!)
        return .object(["schemaVersion":.number(1),"accountID":.string(profile.accountID),"configuration":input.configuration,"configurationDigest":.string(sha256(try input.configuration.encoded())),"artifact":artifact,"artifactDigest":.string(sha256(try artifact.encoded())),"sourceSHA":input.sourceSHA.map(JSON.string) ?? .null,"secretReferences":try .value(input.secretReferences ?? [:]),"baseline":current,"baselineDigest":.string(sha256(try current.encoded())),"mode":.string(mode),"activates":.bool(mode=="deploy"),"migrationWarning":.string(migrations.isEmpty ? "none" : "Code activation and stateful migrations; code rollback cannot undo data changes"),"archiveCredentialsAutomaticallyProvided":.bool(false),"configurationWarning":.string("Target Worker configuration is replaced; omitted nonsecret vars/bindings may be removed. Full infrastructure inventory reconciliation is not implemented.")])
    }
    func invoke(_ input:WorkerInput,action:String,configuration:JSON,versionID:String?=nil) throws -> JSON {
        guard let adapter else { throw FKError("unsupported","Set trusted FK_NODE and FK_WORKER_ADAPTER paths",stage:"deployment") }
        var secrets:[String:JSON]=[:]
        for (name,ref) in input.secretReferences ?? [:] { secrets[name] = .string(try credentials.get(ref)) }
        let payload:JSON = .object(["schemaVersion":.number(1),"action":.string(action),"configuration":configuration,"hasSecrets":.bool(!secrets.isEmpty),"versionID":versionID.map(JSON.string) ?? .null])
        let workspace=try privateDirectory(); defer { try? FileManager.default.removeItem(at:workspace) }
        let control=workspace.appendingPathComponent("control.json"); try writePrivate(payload.encoded(),to:control)
        return try processJSON(executable:adapter.node,arguments:[adapter.script.path,control.path],input:JSON.object(secrets).encoded(),environment:["PATH":adapter.node.deletingLastPathComponent().path,"FK_DEPLOYMENT_TOKEN":try credentials.get(profile.workerCredential)])
    }
    public func apply(_ input:WorkerInput) async throws -> JSON {
        guard let approved=input.approvedPlan, let digest=input.approvedPlanDigest else { throw FKError("validation","Reviewed approvedPlan and its digest required") }
        try require(sha256(try approved.encoded())==digest,"Approved plan digest mismatch")
        let fresh=try await plan(input)
        guard fresh==approved else { throw FKError("drift","Artifact, secrets, config or remote deployment changed since planning",stage:"deployment") }
        guard let source=input.sourceDirectory else { throw FKError("validation","Source required") }
        let root=URL(fileURLWithPath:source).standardizedFileURL
        let stage=try privateDirectory(); defer { try? FileManager.default.removeItem(at:stage) }
        for entry in fresh["artifact"].array! {
            let relative=entry["path"].string!; let target=stage.appendingPathComponent(relative)
            try FileManager.default.createDirectory(at:target.deletingLastPathComponent(),withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
            try FileManager.default.copyItem(at:root.appendingPathComponent(relative),to:target)
            try require(try hashFile(target).digest == entry["sha256"].string,"Artifact changed while staging")
        }
        var fields=input.configuration.object!; fields["account_id"] = .string(profile.accountID)
        guard let main=fields["main"]?.string else { throw FKError("validation","Main module required") }
        fields["main"] = .string(stage.appendingPathComponent(main).path)
        if fields["find_additional_modules"] == nil { fields["find_additional_modules"] = .bool(true) }
        if fields["rules"] == nil { fields["rules"] = .array([.object(["type":.string("ESModule"),"globs":.array([.string("**/*.mjs"),.string("**/*.js")]),"fallthrough":.bool(true)]),.object(["type":.string("CompiledWasm"),"globs":.array([.string("**/*.wasm")]),"fallthrough":.bool(true)])]) }
        let result=try invoke(input,action:fresh["mode"].string!,configuration:.object(fields))
        let readback = fresh["mode"].string == "dry-run" ? JSON.null : try await inspect(fields["name"]!.string!)
        let records=result["records"].array ?? []
        let version=records.compactMap { $0["version_id"].string }.last
        if fresh["mode"].string != "dry-run" { try require(version != nil,"Structured version ID missing; inspect remote state before retry") }
        if fresh["mode"].string == "deploy", let version {
            let versions=(readback["deployments"]["deployments"].array ?? readback["deployments"].array ?? []).flatMap { $0["versions"].array ?? [] }
            guard versions.contains(where:{$0["version_id"].string == version}) else { throw FKError("drift","Deployment readback does not include returned version",stage:"verification") }
            let bindings=readback["bindings"].array ?? []
            for binding in input.configuration["r2_buckets"].array ?? [] {
                try require(bindings.contains{$0["name"]==binding["binding"] && $0["bucket_name"]==binding["bucket_name"]},"R2 binding readback differs")
            }
            for binding in input.configuration["durable_objects"]["bindings"].array ?? [] {
                try require(bindings.contains{$0["name"]==binding["name"] && $0["namespace_id"].string != nil},"Durable Object namespace readback missing")
            }
            for name in (input.secretReferences ?? [:]).keys { try require(bindings.contains{$0["name"].string==name && $0["type"].string=="secret_text"},"Secret binding readback missing") }
        }
        var endpoints:[JSON]=[]
        if fresh["mode"].string == "deploy" && input.configuration["workers_dev"].bool==true {
            let subdomain=try await cloud.call("GET",path:["workers","subdomain"])
            if let subdomain=subdomain["subdomain"].string { endpoints.append(.string("https://"+fields["name"]!.string!+"."+subdomain+".workers.dev")) }
        }
        for route in input.configuration["routes"].array ?? [] { if route["custom_domain"].bool==true,let host=route["pattern"].string,!host.contains("*") { endpoints.append(.string("https://"+host)) } }
        return .object(["adapter":result,"resources":readback,"endpoints":.array(endpoints),"planDigest":.string(digest),"artifactDigest":fresh["artifactDigest"],"sourceSHA":fresh["sourceSHA"],"verification":.string(fresh["mode"].string == "dry-run" ? "local-dry-run" : "api-readback"),"archiveOutcome":.string("independent")])
    }
    public func changeVersion(_ input:WorkerInput,action:String,expectedDeploymentDigest:String) async throws -> JSON {
        try validateAuthority(input)
        let name=input.configuration["name"].string!
        let baseline=try await current(name)
        guard sha256(try baseline.encoded())==expectedDeploymentDigest else { throw FKError("drift","Deployment changed since review",stage:"deployment") }
        if action=="promote" {
            guard let id=input.versionID,UUID(uuidString:id) != nil else { throw FKError("validation","Version ID required") }
            _ = try await cloud.call("GET",path:["workers","scripts",name,"versions",id])
        } else {
            try require(!(input.secretReferences ?? [:]).isEmpty,"Secret references required")
            for ref in input.secretReferences!.values { try ref.validate() }
        }
        var config=input.configuration.object!; config["account_id"] = .string(profile.accountID)
        let result=try invoke(input,action:action,configuration:.object(config),versionID:input.versionID)
        let deployments=try await current(name)
        if action=="secret-stage" {
            guard deployments==baseline else { throw FKError("drift","Secret staging unexpectedly changed traffic",stage:"verification") }
            let versions=try await cloud.call("GET",path:["workers","scripts",name,"versions"])
            let safeVersions=(versions["items"].array ?? versions.array ?? []).map { v in JSON.object(["id":v["id"],"createdOn":v["metadata"]["created_on"]]) }
            return .object(["adapter":result,"versions":.array(safeVersions),"activates":.bool(false),"deploymentUnchanged":.bool(true)])
        }
        return .object(["adapter":result,"deployments":deployments,"activates":.bool(true),"rollbackScope":.string("Code only; stored data and migrations are not rolled back")])
    }
}
