// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "MacWatch",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "MacWatchCore", targets: ["MacWatchCore"]),
        .executable(name: "MacWatch", targets: ["MacWatchApp"])
    ],
    targets: [
        .target(
            name: "MacWatchCore",
            linkerSettings: [
                .linkedFramework("AVFoundation"),
                .linkedFramework("AppKit"),
                .linkedFramework("CoreAudio"),
                .linkedFramework("CoreMediaIO"),
                .linkedFramework("Security"),
                .linkedFramework("UserNotifications")
            ]
        ),
        .executableTarget(
            name: "MacWatchApp",
            dependencies: ["MacWatchCore"],
            exclude: ["MacWatch.entitlements", "SystemExtensionController.swift"],
            linkerSettings: [
                .linkedFramework("AVFoundation"),
                .linkedFramework("AppKit"),
                .linkedFramework("CoreAudio"),
                .linkedFramework("CoreMediaIO"),
                .linkedFramework("Security"),
                .linkedFramework("UserNotifications")
            ]
        ),
        .executableTarget(name: "MacWatchSelfTest", dependencies: ["MacWatchCore"]),
        .testTarget(name: "MacWatchCoreTests", dependencies: ["MacWatchCore"])
    ]
)
