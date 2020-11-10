import CommonCryptoSPI
import Foundation

public typealias HmacContextRef = CCHmacContextRef

public func HmacCreate(algorithm: DigestAlgorithm, key: Data) -> HmacContextRef {
    key.withUnsafeBytes { keyPtr -> HmacContextRef in
        CCHmacCreate(algorithm.rawValue, keyPtr.baseAddress, keyPtr.count)
    }
}

/// Create a clone of an initialized CCHmacContextRef - you must do this before use.
public func HmacClone(_ reference: HmacContextRef) -> HmacContextRef {
    CCHmacClone(reference)
}

/// Process some data.
/// - Parameters:
///   - reference: An HMAC context.
///   - data: Data to process.
public func HmacUpdate(_ reference: HmacContextRef, data: Data) {
    data.withUnsafeBytes { dataPtr in
        CCHmacUpdate(reference, dataPtr.baseAddress, dataPtr.count)
    }
}

/// Obtain the final Message Authentication Code.
/// - Parameter reference: An HMAC context.
/// - Returns: The final MAC
public func HmacFinalize(_ reference: HmacContextRef) -> Data {
    var output = [UInt8](repeating: 0, count: HmacOutputSizeFromRef(reference))
    CCHmacFinal(reference, &output)
    return Data(output)
}

public func HmacDestroy(_ reference: HmacContextRef) {
    CCHmacDestroy(reference)
}

public func HmacOutputSizeFromRef(_ reference: HmacContextRef) -> Int {
    CCHmacOutputSizeFromRef(reference)
}

public func HmacOutputSize(algorithm: DigestAlgorithm) -> Int {
    CCHmacOutputSize(algorithm.rawValue)
}

public func HmacOneShot(algorithm: DigestAlgorithm, key: Data, data: Data) -> Data {
    var output = [UInt8](repeating: 0, count: HmacOutputSize(algorithm: algorithm))
    key.withUnsafeBytes { keyPtr in
        data.withUnsafeBytes { dataPtr in
            CCHmacOneShot(algorithm.rawValue, keyPtr.baseAddress, keyPtr.count, dataPtr.baseAddress, dataPtr.count, &output)
        }
    }
    return Data(output)
}
