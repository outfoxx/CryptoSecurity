// swift-tools-version:5.0

import PackageDescription

let package = Package(
  name: "CryptoSecurity",
  platforms: [
    .iOS("10.0"),
    .macOS("10.12"),
    .watchOS("3.0"),
    .tvOS("10.0"),
  ],
  products: [
    .library(
      name: "CryptoSecurity",
      targets: ["CryptoSecurity"]),
    .library(
      name: "CryptoSecurityObjC",
      targets: ["CryptoSecurityObjC"]),
  ],
  dependencies: [
  ],
  targets: [
    .target(
      name: "CryptoSecurity",
      dependencies: ["CryptoSecurityObjC"],
      path: "Sources"),
    .target(
      name: "CryptoSecurityObjC",
      path: "CSources"),
    .testTarget(
      name: "CryptoSecurityTests",
      dependencies: ["CryptoSecurity"],
      path: "Tests"),
  ]
)
