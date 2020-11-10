import CommonCryptoSPI
import Foundation

/// Digest context.
public typealias DigestRef = CCDigestRef

/// Algorithms implemented in this module.
public enum DigestAlgorithm: RawRepresentable {
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
    
    public typealias RawValue = CCDigestAlgorithm
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CCDigestAlgorithm(kCCDigestMD5):       self = .md5
        case CCDigestAlgorithm(kCCDigestRMD160):    self = .rmd160
        case CCDigestAlgorithm(kCCDigestSHA1):      self = .sha1
        case CCDigestAlgorithm(kCCDigestSHA224):    self = .sha224
        case CCDigestAlgorithm(kCCDigestSHA256):    self = .sha256
        case CCDigestAlgorithm(kCCDigestSHA384):    self = .sha384
        case CCDigestAlgorithm(kCCDigestSHA512):    self = .sha512
        default: return nil
        }
    }
    
    public var rawValue: CCDigestAlgorithm {
        switch self {
        case .md5:      return CCDigestAlgorithm(kCCDigestMD5)
        case .rmd160:   return CCDigestAlgorithm(kCCDigestRMD160)
        case .sha1:     return CCDigestAlgorithm(kCCDigestSHA1)
        case .sha224:   return CCDigestAlgorithm(kCCDigestSHA224)
        case .sha256:   return CCDigestAlgorithm(kCCDigestSHA256)
        case .sha384:   return CCDigestAlgorithm(kCCDigestSHA384)
        case .sha512:   return CCDigestAlgorithm(kCCDigestSHA512)
        }
    }
}

/// Initialize a digest context for a digest.
/// - Parameters:
///   - algorithm: The digest algorithm to perform.
///   - reference: The reference to set.
/// - Throws: A `CryptoError` describing the issue.
public func DigestInit(algorithm: DigestAlgorithm, reference: DigestRef?) throws {
    let status = CryptorStatus(CCDigestInit(algorithm.rawValue, reference))
    guard status == .success else { throw CryptoError(status) }
}

/// Stateless, one-shot Digest function.
/// - Parameters:
///   - algorithm: Digest algorithm to perform.
///   - data: The data to digest.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The digest bytes.
public func Digest(algorithm: DigestAlgorithm, data: Data) throws -> Data {
    var output = [UInt8](repeating: 0, count: DigestGetOutputSize(algorithm))
    let status = withUnsafeBytes(of: data) { dataPtr -> CryptorStatus in
        CryptorStatus(CCDigest(algorithm.rawValue, Array(dataPtr), data.count, &output))
    }
    guard status == .success else { throw CryptoError(status) }
    return Data(output)
}

/// Allocate and initialize a CCDigestCtx for a digest.
/// - Parameter algorithm: Digest algorithm to setup.
/// - Returns: Returns a pointer to a digestRef on success.
public func DigestCreate(algorithm: DigestAlgorithm) -> DigestRef {
    CCDigestCreate(algorithm.rawValue)
}

/// Continue to digest data.
/// - Parameters:
///   - reference: A digest context.
///   - data: The data to digest.
/// - Throws: A `CryptoError` describing the issue.
public func DigestUpdate(_ reference: DigestRef?, data: Data) throws {
    let status = data.withUnsafeBytes { dataPtr -> CryptorStatus in
        CryptorStatus(CCDigestUpdate(reference, dataPtr.baseAddress, dataPtr.count))
    }
    guard status == .success else { throw CryptoError(status) }
}

/// Conclude digest operations and produce the digest output.
/// - Parameter reference: A digest context.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The digest bytes.
public func DigestFinalize(_ reference: DigestRef?) throws -> Data {
    var output = [UInt8](repeating: 0, count: DigestGetOutputSizeFromRef(reference))
    let status = CryptorStatus(CCDigestFinal(reference, &output))
    guard status == .success else { throw CryptoError(status) }
    return Data(output)
}

/// Clear and free a CCDigestCtx
/// - Parameter reference: A digest context.
public func DigestDestroy(_ reference: DigestRef?) {
    CCDigestDestroy(reference)
}

/// Clear and re-initialize a CCDigestCtx for the same algorithm.
/// - Parameter reference: A digest context.
public func DigestReset(_ reference: DigestRef?) {
    CCDigestReset(reference)
}

/// Provides the block size of the digest algorithm.
/// - Parameter algorithm: A digest algorithm selector.
/// - Returns: Returns 0 on failure or the block size on success.
public func DigestGetBlockSize(_ algorithm: DigestAlgorithm) -> Int {
    CCDigestGetBlockSize(algorithm.rawValue)
}

/// Provides the digest output size of the digest algorithm
/// - Parameter algorithm: A digest algorithm selector.
/// - Returns: Returns 0 on failure or the digest output size on success.
public func DigestGetOutputSize(_ algorithm: DigestAlgorithm) -> Int {
    CCDigestGetOutputSize(algorithm.rawValue)
}

/// Provides the block size of the digest algorithm
/// - Parameter reference: A digest context.
/// - Returns: Returns 0 on failure or the block size on success.
public func DigestGetBlockSizeFromRef(_ reference: DigestRef?) -> Int {
    CCDigestGetBlockSizeFromRef(reference)
}

/// Provides the digest output size of the digest algorithm
/// - Parameter reference: A digest context.
/// - Returns: Returns 0 on failure or the digest output size on success.
public func DigestGetOutputSizeFromRef(_ reference: DigestRef?) -> Int {
    CCDigestGetOutputSizeFromRef(reference)
}
