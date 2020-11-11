import CommonCryptoSPI
import Foundation

public typealias CCCmacContextRef = CommonCryptoSPI.CCCmacContextPtr

/// Stateless, one-shot AES CMAC function.
/// - Parameters:
///   - key: Raw key bytes.
///   - data: The data to process.
/// - Returns: The MAC bytes.
public func CCAESCmac(key: Data, data: Data) -> Data {
    var output = [UInt8](repeating: 0, count: 16)
    key.withUnsafeBytes { keyPtr in
        data.withUnsafeBytes { dataPtr in
            CommonCryptoSPI.CCAESCmac(keyPtr.baseAddress, Array(dataPtr), dataPtr.count, &output)
        }
    }
    return Data(output)
}

/// Create a CMac context.
/// - Parameter key: The bytes of the AES key.
/// - Returns: This returns an AES-CMac context to be used.
public func CCAESCmacCreate(key: Data) -> CCCmacContextRef {
    key.withUnsafeBytes { keyPtr in
        CommonCryptoSPI.CCAESCmacCreate(keyPtr.baseAddress, keyPtr.count)
    }
}

/// Process some data.
/// - Note: This can be called multiple times.
/// - Parameters:
///   - reference: A CMAC context.
///   - data: Data to process.
public func CCAESCmacUpdate(_ reference: CCCmacContextRef, data: Data) {
    data.withUnsafeBytes { dataPtr in
        CommonCryptoSPI.CCAESCmacUpdate(reference, dataPtr.baseAddress, dataPtr.count)
    }
}

/// Obtain the final Message Authentication Code.
/// - Parameter reference: A CMAC context.
/// - Returns: The MAC bytes.
public func CCAESCmacFinalize(_ reference: CCCmacContextRef) -> Data {
    var output = [UInt8](repeating: 0, count: CCAESCmacOutputSizeFromContext(reference))
    CommonCryptoSPI.CCAESCmacFinal(reference, &output)
    return Data(output)
}

public func CCAESCmacDestroy(_ reference: CCCmacContextRef) {
    CommonCryptoSPI.CCAESCmacDestroy(reference)
}

public func CCAESCmacOutputSizeFromContext(_ reference: CCCmacContextRef) -> Int {
    CommonCryptoSPI.CCAESCmacOutputSizeFromContext(reference)
}
