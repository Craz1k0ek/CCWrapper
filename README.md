# CCWrapper

A CommonCrypto wrapper in Swift, including some of the SPI implementations.

### Swift Package manager
In order to use the package using the Swift package manager, add the following as dependency to your `Package.swift`.
```swift
.package(url: "https://github.com/Craz1k0ek/CCWrapper.git", .branch("master"))
```
Afterwards, add `CCWrapper` as dependency to the target where you need the package. Lastly, update the package.
```shell
swift package update
```

### Requirements
* iOS 12.0 or higher
* macOS 10.13 or higher
