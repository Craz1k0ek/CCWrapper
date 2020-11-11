import CommonCryptoSPI
import Foundation

/// Digest context.
public typealias CCDigestRef = CommonCryptoSPI.CCDigestRef

/// Algorithms implemented in this module.
public enum CCDigestAlgorithm: RawRepresentable {
    /// MD5 digest.
    @available(iOS, deprecated: 13.0)
    @available(macOS, deprecated: 10.15)
    case md5
    /// RMD 160 bit digest.
    @available(iOS, deprecated: 13.0)
    @available(macOS, deprecated: 10.15)
    case rmd160
    /// SHA-1 digest.
    @available(iOS, deprecated: 13.0)
    @available(macOS, deprecated: 10.15)
    case sha1
    /// SHA-2 224 bit digest.
    case sha224
    /// SHA-2 256 bit digest.
    case sha256
    /// SHA-2 384 bit digest.
    case sha384
    /// SHA-2 512 bit digest.
    case sha512
    
    public typealias RawValue = CommonCryptoSPI.CCDigestAlgorithm
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCryptoSPI.CCDigestAlgorithm(kCCDigestMD5):       self = .md5
        case CommonCryptoSPI.CCDigestAlgorithm(kCCDigestRMD160):    self = .rmd160
        case CommonCryptoSPI.CCDigestAlgorithm(kCCDigestSHA1):      self = .sha1
        case CommonCryptoSPI.CCDigestAlgorithm(kCCDigestSHA224):    self = .sha224
        case CommonCryptoSPI.CCDigestAlgorithm(kCCDigestSHA256):    self = .sha256
        case CommonCryptoSPI.CCDigestAlgorithm(kCCDigestSHA384):    self = .sha384
        case CommonCryptoSPI.CCDigestAlgorithm(kCCDigestSHA512):    self = .sha512
        default: return nil
        }
    }
    
    public var rawValue: CommonCryptoSPI.CCDigestAlgorithm {
        switch self {
        case .md5:      return CommonCryptoSPI.CCDigestAlgorithm(kCCDigestMD5)
        case .rmd160:   return CommonCryptoSPI.CCDigestAlgorithm(kCCDigestRMD160)
        case .sha1:     return CommonCryptoSPI.CCDigestAlgorithm(kCCDigestSHA1)
        case .sha224:   return CommonCryptoSPI.CCDigestAlgorithm(kCCDigestSHA224)
        case .sha256:   return CommonCryptoSPI.CCDigestAlgorithm(kCCDigestSHA256)
        case .sha384:   return CommonCryptoSPI.CCDigestAlgorithm(kCCDigestSHA384)
        case .sha512:   return CommonCryptoSPI.CCDigestAlgorithm(kCCDigestSHA512)
        }
    }
}

/// Initialize a digest context for a digest.
/// - Parameters:
///   - algorithm: The digest algorithm to perform.
///   - reference: The reference to set.
/// - Throws: A `CryptoError` describing the issue.
public func CCDigestInit(algorithm: CCDigestAlgorithm, reference: CCDigestRef?) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCDigestInit(algorithm.rawValue, reference))
    guard status == .success else { throw CryptoError(status) }
}

/// Stateless, one-shot Digest function.
/// - Parameters:
///   - algorithm: Digest algorithm to perform.
///   - data: The data to digest.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The digest bytes.
public func CCDigest(algorithm: CCDigestAlgorithm, data: Data) throws -> Data {
    var output = [UInt8](repeating: 0, count: CCDigestGetOutputSize(algorithm))
    let status = withUnsafeBytes(of: data) { dataPtr -> CCCryptorStatus in
        CCCryptorStatus(CommonCryptoSPI.CCDigest(algorithm.rawValue, Array(dataPtr), data.count, &output))
    }
    guard status == .success else { throw CryptoError(status) }
    return Data(output)
}

/// Allocate and initialize a CCDigestCtx for a digest.
/// - Parameter algorithm: Digest algorithm to setup.
/// - Returns: Returns a pointer to a digestRef on success.
public func CCDigestCreate(algorithm: CCDigestAlgorithm) -> CCDigestRef {
    CommonCryptoSPI.CCDigestCreate(algorithm.rawValue)
}

/// Continue to digest data.
/// - Parameters:
///   - reference: A digest context.
///   - data: The data to digest.
/// - Throws: A `CryptoError` describing the issue.
public func CCDigestUpdate(_ reference: CCDigestRef?, data: Data) throws {
    let status = data.withUnsafeBytes { dataPtr -> CCCryptorStatus in
        CCCryptorStatus(CommonCryptoSPI.CCDigestUpdate(reference, dataPtr.baseAddress, dataPtr.count))
    }
    guard status == .success else { throw CryptoError(status) }
}

/// Conclude digest operations and produce the digest output.
/// - Parameter reference: A digest context.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The digest bytes.
public func CCDigestFinalize(_ reference: CCDigestRef?) throws -> Data {
    var output = [UInt8](repeating: 0, count: CCDigestGetOutputSizeFromRef(reference))
    let status = CCCryptorStatus(CommonCryptoSPI.CCDigestFinal(reference, &output))
    guard status == .success else { throw CryptoError(status) }
    return Data(output)
}

/// Clear and free a CCDigestCtx
/// - Parameter reference: A digest context.
public func CCDigestDestroy(_ reference: CCDigestRef?) {
    CommonCryptoSPI.CCDigestDestroy(reference)
}

/// Clear and re-initialize a CCDigestCtx for the same algorithm.
/// - Parameter reference: A digest context.
public func CCDigestReset(_ reference: CCDigestRef?) {
    CommonCryptoSPI.CCDigestReset(reference)
}

/// Provides the block size of the digest algorithm.
/// - Parameter algorithm: A digest algorithm selector.
/// - Returns: Returns 0 on failure or the block size on success.
public func CCDigestGetBlockSize(_ algorithm: CCDigestAlgorithm) -> Int {
    CommonCryptoSPI.CCDigestGetBlockSize(algorithm.rawValue)
}

/// Provides the digest output size of the digest algorithm
/// - Parameter algorithm: A digest algorithm selector.
/// - Returns: Returns 0 on failure or the digest output size on success.
public func CCDigestGetOutputSize(_ algorithm: CCDigestAlgorithm) -> Int {
    CommonCryptoSPI.CCDigestGetOutputSize(algorithm.rawValue)
}

/// Provides the block size of the digest algorithm
/// - Parameter reference: A digest context.
/// - Returns: Returns 0 on failure or the block size on success.
public func CCDigestGetBlockSizeFromRef(_ reference: CCDigestRef?) -> Int {
    CommonCryptoSPI.CCDigestGetBlockSizeFromRef(reference)
}

/// Provides the digest output size of the digest algorithm
/// - Parameter reference: A digest context.
/// - Returns: Returns 0 on failure or the digest output size on success.
public func CCDigestGetOutputSizeFromRef(_ reference: CCDigestRef?) -> Int {
    CommonCryptoSPI.CCDigestGetOutputSizeFromRef(reference)
}
