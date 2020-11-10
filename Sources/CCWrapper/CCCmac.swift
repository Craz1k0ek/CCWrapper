import CommonCryptoSPI
import Foundation

public typealias CmacContextRef = CCCmacContextPtr

/// Stateless, one-shot AES CMAC function.
/// - Parameters:
///   - key: Raw key bytes.
///   - data: The data to process.
/// - Returns: The MAC bytes.
public func AESCmac(key: Data, data: Data) -> Data {
    var output = [UInt8](repeating: 0, count: 16)
    key.withUnsafeBytes { keyPtr in
        data.withUnsafeBytes { dataPtr in
            CCAESCmac(keyPtr.baseAddress, Array(dataPtr), dataPtr.count, &output)
        }
    }
    return Data(output)
}

/// Create a CMac context.
/// - Parameter key: The bytes of the AES key.
/// - Returns: This returns an AES-CMac context to be used.
public func AESCmacCreate(key: Data) -> CmacContextRef {
    key.withUnsafeBytes { keyPtr in
        CCAESCmacCreate(keyPtr.baseAddress, keyPtr.count)
    }
}

/// Process some data.
/// - Note: This can be called multiple times.
/// - Parameters:
///   - reference: A CMAC context.
///   - data: Data to process.
public func AESCmacUpdate(_ reference: CmacContextRef, data: Data) {
    data.withUnsafeBytes { dataPtr in
        CCAESCmacUpdate(reference, dataPtr.baseAddress, dataPtr.count)
    }
}

/// Obtain the final Message Authentication Code.
/// - Parameter reference: A CMAC context.
/// - Returns: The MAC bytes.
public func AESCmacFinalize(_ reference: CmacContextRef) -> Data {
    var output = [UInt8](repeating: 0, count: AESCmacOutputSizeFromContext(reference))
    CCAESCmacFinal(reference, &output)
    return Data(output)
}

public func AESCmacDestroy(_ reference: CmacContextRef) {
    CCAESCmacDestroy(reference)
}

public func AESCmacOutputSizeFromContext(_ reference: CmacContextRef) -> Int {
    CCAESCmacOutputSizeFromContext(reference)
}
