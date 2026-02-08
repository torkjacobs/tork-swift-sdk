// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TorkGovernance",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "TorkGovernance",
            targets: ["TorkGovernance"]
        ),
    ],
    targets: [
        .target(
            name: "TorkGovernance",
            path: "Sources/TorkGovernance"
        ),
        .testTarget(
            name: "TorkGovernanceTests",
            dependencies: ["TorkGovernance"],
            path: "Tests/TorkGovernanceTests"
        ),
    ]
)
