// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "FlareKit", platforms: [.macOS(.v15)], products: [
    .library(name: "FlareKitCore", targets: ["FlareKitCore"]),
    .executable(name: "fk", targets: ["fk"])
], dependencies: [.package(url: "https://github.com/apple/swift-crypto.git", exact: "4.3.1")], targets: [
    .target(name: "FKProcess"),
    .target(name: "FlareKitCore", dependencies: ["FKProcess", .product(name: "Crypto", package: "swift-crypto")]),
    .executableTarget(name: "fk", dependencies: ["FlareKitCore"]),
    .testTarget(name: "FlareKitCoreTests", dependencies: ["FlareKitCore"])
], swiftLanguageModes: [.v5])
