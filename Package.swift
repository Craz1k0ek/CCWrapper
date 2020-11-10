// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "CCWrapper",
    platforms: [
        .iOS(.v12), .macOS(.v10_13)
    ],
    products: [
        .library(name: "CCWrapper", targets: ["CCWrapper"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "CommonCryptoSPI"),
        .target(name: "CCWrapper", dependencies: ["CommonCryptoSPI"]),
        .testTarget(name: "CCWrapperTests", dependencies: ["CCWrapper"]),
    ]
)
