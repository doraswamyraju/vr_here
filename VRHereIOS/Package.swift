 // swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VRHereIOS",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "VRHereIOS",
            targets: ["VRHereIOS"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "VRHereIOS",
            dependencies: [],
            path: "VRHereIOS"
        )
    ]
)
