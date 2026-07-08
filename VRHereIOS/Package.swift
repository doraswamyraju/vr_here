 // swift-tools-version: 5.9
import PackageDescription
import AppleProductTypes

let package = Package(
    name: "VRHereIOS",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .iOSApplication(
            name: "VR Here BMS",
            targets: ["VRHereIOS"],
            bundleIdentifier: "com.sbr.vrherebms.ios",
            teamIdentifier: "",
            displayVersion: "1.0",
            bundleVersion: "1",
            appIcon: .asset("AppIcon"),
            supportedDeviceFamilies: [
                .pad,
                .phone
            ],
            supportedInterfaceOrientations: [
                .portrait,
                .landscapeLeft,
                .landscapeRight,
                .portraitUpsideDown
            ]
        )
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "VRHereIOS",
            dependencies: [],
            path: "VRHereIOS"
        )
    ]
)
