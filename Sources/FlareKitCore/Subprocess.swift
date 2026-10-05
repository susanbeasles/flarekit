import Foundation
import FKProcess
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public func runChild(executable:URL,arguments:[String],input:Data=Data(),environment:[String:String]=["PATH":"/usr/bin:/bin"],cwd:URL?=nil,output:URL,timeout:UInt32=180) throws {
    let args=([executable.path]+arguments).map { strdup($0) }+[nil]
    let env=environment.map { strdup($0.key+"="+$0.value) }+[nil]
    defer { for a in args { free(a) }; for e in env { free(e) } }
    let immutableArgs=args.map { $0.map { UnsafePointer<CChar>($0) } }
    let immutableEnv=env.map { $0.map { UnsafePointer<CChar>($0) } }
    let status:Int32 = try immutableArgs.withUnsafeBufferPointer { a in
        try immutableEnv.withUnsafeBufferPointer { e in
            try input.withUnsafeBytes { bytes in
                try executable.path.withCString { path in
                    try output.path.withCString { out in
                        if let cwd { return cwd.path.withCString { dir in fk_run(path,a.baseAddress,e.baseAddress,dir,bytes.baseAddress?.assumingMemoryBound(to:UInt8.self),bytes.count,out,timeout) } }
                        return fk_run(path,a.baseAddress,e.baseAddress,nil,bytes.baseAddress?.assumingMemoryBound(to:UInt8.self),bytes.count,out,timeout)
                    }
                }
            }
        }
    }
    guard status==0 else { throw FKError("network",status==124 ? "Subprocess timed out; reconcile before retry" : "Subprocess failed; sensitive output omitted",stage:"subprocess") }
}
