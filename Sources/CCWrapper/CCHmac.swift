import CommonCryptoSPI
import Foundation

public typealias CCHmacContextRef = CommonCryptoSPI.CCHmacContextRef

public func CCHmacCreate(algorithm: CCDigestAlgorithm, key: Data) -> CCHmacContextRef {
    key.withUnsafeBytes { keyPtr -> CCHmacContextRef in
        CommonCryptoSPI.CCHmacCreate(algorithm.rawValue, keyPtr.baseAddress, keyPtr.count)
    }
}

/// Create a clone of an initialized CCHmacContextRef - you must do this before use.
public func CCHmacClone(_ reference: CCHmacContextRef) -> CCHmacContextRef {
    CommonCryptoSPI.CCHmacClone(reference)
}

/// Process some data.
/// - Parameters:
///   - reference: An HMAC context.
///   - data: Data to process.
public func CCHmacUpdate(_ reference: CCHmacContextRef, data: Data) {
    data.withUnsafeBytes { dataPtr in
        CommonCryptoSPI.CCHmacUpdate(reference, dataPtr.baseAddress, dataPtr.count)
    }
}

/// Obtain the final Message Authentication Code.
/// - Parameter reference: An HMAC context.
/// - Returns: The final MAC
public func CCHmacFinalize(_ reference: CCHmacContextRef) -> Data {
    var output = [UInt8](repeating: 0, count: CCHmacOutputSizeFromRef(reference))
    CommonCryptoSPI.CCHmacFinal(reference, &output)
    return Data(output)
}

public func CCHmacDestroy(_ reference: CCHmacContextRef) {
    CommonCryptoSPI.CCHmacDestroy(reference)
}

public func CCHmacOutputSizeFromRef(_ reference: CCHmacContextRef) -> Int {
    CommonCryptoSPI.CCHmacOutputSizeFromRef(reference)
}

public func CCHmacOutputSize(algorithm: CCDigestAlgorithm) -> Int {
    CommonCryptoSPI.CCHmacOutputSize(algorithm.rawValue)
}

public func CCHmacOneShot(algorithm: CCDigestAlgorithm, key: Data, data: Data) -> Data {
    var output = [UInt8](repeating: 0, count: CCHmacOutputSize(algorithm: algorithm))
    key.withUnsafeBytes { keyPtr in
        data.withUnsafeBytes { dataPtr in
            CommonCryptoSPI.CCHmacOneShot(algorithm.rawValue, keyPtr.baseAddress, keyPtr.count, dataPtr.baseAddress, dataPtr.count, &output)
        }
    }
    return Data(output)
}
