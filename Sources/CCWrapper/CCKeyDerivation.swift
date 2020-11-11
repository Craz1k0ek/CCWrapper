import CommonCryptoSPI
import Foundation

public typealias CCKDFParametersRef = CommonCryptoSPI.CCKDFParametersRef

/// Key Derivation algorithms implemented by this module.
public enum CCKDFAlgorithm: RawRepresentable {
    case pbkdf2Hmac
    case ctrHmac
    case ctrHmacFixed
    case hkdf
    case ansiX963
    
    public typealias RawValue = CommonCryptoSPI.CCKDFAlgorithm
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCryptoSPI.CCKDFAlgorithm(kCCKDFAlgorithmPBKDF2_HMAC):    self = .pbkdf2Hmac
        case CommonCryptoSPI.CCKDFAlgorithm(kCCKDFAlgorithmCTR_HMAC):       self = .ctrHmac
        case CommonCryptoSPI.CCKDFAlgorithm(kCCKDFAlgorithmCTR_HMAC_FIXED): self = .ctrHmacFixed
        case CommonCryptoSPI.CCKDFAlgorithm(kCCKDFAlgorithmHKDF):           self = .hkdf
        case CommonCryptoSPI.CCKDFAlgorithm(kCCKDFAlgorithmAnsiX963):       self = .ansiX963
        default: return nil
        }
    }
    
    public var rawValue: CommonCryptoSPI.CCKDFAlgorithm {
        switch self {
        case .pbkdf2Hmac:   return CommonCryptoSPI.CCKDFAlgorithm(kCCKDFAlgorithmPBKDF2_HMAC)
        case .ctrHmac:      return CommonCryptoSPI.CCKDFAlgorithm(kCCKDFAlgorithmCTR_HMAC)
        case .ctrHmacFixed: return CommonCryptoSPI.CCKDFAlgorithm(kCCKDFAlgorithmCTR_HMAC_FIXED)
        case .hkdf:         return CommonCryptoSPI.CCKDFAlgorithm(kCCKDFAlgorithmHKDF)
        case .ansiX963:     return CommonCryptoSPI.CCKDFAlgorithm(kCCKDFAlgorithmAnsiX963)
        }
    }
}

public enum CCPBKDFAlgorithm: RawRepresentable {
    case pbkdf2
    
    public typealias RawValue = CommonCrypto.CCPBKDFAlgorithm
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCrypto.CCPBKDFAlgorithm(kCCPBKDF2): self = .pbkdf2
        default: return nil
        }
    }
    
    public var rawValue: CommonCrypto.CCPBKDFAlgorithm { return CommonCrypto.CCPBKDFAlgorithm(kCCPBKDF2) }
}

public enum CCPseudoRandomAlgorithm: RawRepresentable {
    case prfHmacSHA1
    case prfHmacSHA224
    case prfHmacSHA256
    case prfHmacSHA384
    case prfHmacSHA512
    
    public typealias RawValue = CommonCrypto.CCPseudoRandomAlgorithm
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCrypto.CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1):    self = .prfHmacSHA1
        case CommonCrypto.CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224):  self = .prfHmacSHA224
        case CommonCrypto.CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256):  self = .prfHmacSHA256
        case CommonCrypto.CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384):  self = .prfHmacSHA384
        case CommonCrypto.CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512):  self = .prfHmacSHA512
        default: return nil
        }
    }
    
    public var rawValue: CommonCrypto.CCPseudoRandomAlgorithm {
        switch self {
        case .prfHmacSHA1:      return CommonCrypto.CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        case .prfHmacSHA224:    return CommonCrypto.CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
        case .prfHmacSHA256:    return CommonCrypto.CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .prfHmacSHA384:    return CommonCrypto.CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
        case .prfHmacSHA512:    return CommonCrypto.CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        }
    }
}

/// Derive a key from a text password/passphrase.
/// - Parameters:
///   - algorithm: Currently only PBKDF2 is available.
///   - password: The text password used as input to the derivation function.
///   - salt: The slat bytes.
///   - prf: The Pseudo Random Algorithm to use for the derivation iterations.
///   - rounds: The number of rounds of the Pseudo Random Algorithm.
///   - derivedSize: The expected length of the derived key in bytes. It cannot be zero.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The resulting derived key produced by the function.
public func CCKeyDerivationPBKDF(algorithm: CCPBKDFAlgorithm, password: String, salt: Data, prf: CCPseudoRandomAlgorithm, rounds: UInt32, derivedSize: Int) throws -> Data {
    var derived = [UInt8](repeating: 0, count: derivedSize)
    let status = CCCryptorStatus(CommonCrypto.CCKeyDerivationPBKDF(algorithm.rawValue, password, password.count, Array(salt), salt.count, prf.rawValue, rounds, &derived, derivedSize))
    guard status == .success else { throw CryptoError(status) }
    return Data(derived)
}

/// Creates a CCKDFParameters object that will hold parameters for key derivation with PBKDF2 with an HMAC PRF.
/// - Parameters:
///   - parameters: A KDFParameters pointer.
///   - rounds: Number of iterations.
///   - salt: Salt.
/// - Throws: A `CryptoError` describing the issue.
@available(iOS 13.0, macOS 10.15, *)
public func CCKDFParametersCreatePbkdf2(_ parameters: inout CCKDFParametersRef?, rounds: UInt32, salt: Data) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCKDFParametersCreatePbkdf2(&parameters, rounds, Array(salt), salt.count))
    guard status == .success else { throw CryptoError(status) }
}

/// Creates a CCKDFParameters object that will hold parameters
/// for key derivation with NIST SP800-108 KDF in Counter Mode with an HMAC PRF.
/// - Parameters:
///   - parameters: A KDFParameters pointer.
///   - label: Label to identify purpose of derived key.
///   - context: Data shared between entities.
/// - Throws: A `CryptoError` describing the issue.
@available(iOS 13.0, macOS 10.15, *)
public func CCKDFParametersCreateCtrHmac(_ parameters: inout CCKDFParametersRef?, label: Data, context: Data) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCKDFParametersCreateCtrHmac(&parameters, Array(label), label.count, Array(context), context.count))
    guard status == .success else { throw CryptoError(status) }
}

/// Creates a CCKDFParameters object that will hold parameters
/// for key derivation with NIST SP800-108 KDF in Counter Mode with an HMAC PRF.
/// - Parameters:
///   - parameters: A KDFParameters pointer.
///   - context: Data shared between entities.
/// - Throws: A `CryptoError` describing the issue.
@available(iOS 13.0, macOS 10.15, *)
public func CCKDFParametersCreateCtrHmacFixed(_ parameters: inout CCKDFParametersRef?, context: Data) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCKDFParametersCreateCtrHmacFixed(&parameters, Array(context), context.count))
    guard status == .success else { throw CryptoError(status) }
}

/// Creates a CCKDFParameters object that will hold parameters
/// for key derivation with HKDF as defined by RFC 5869.
/// - Parameters:
///   - parameters: A KDFParameters pointer.
///   - salt: Salt.
///   - context: Data shared between entities.
/// - Throws: A `CryptoError` describing the issue.
@available(iOS 13.0, macOS 10.15, *)
public func CCKDFParametersCreateHkdf(_ parameters: inout CCKDFParametersRef?, salt: Data, context: Data) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCKDFParametersCreateHkdf(&parameters, Array(salt), salt.count, Array(context), context.count))
    guard status == .success else { throw CryptoError(status) }
}

/// Creates a CCKDFParameters object that will hold parameters
/// for key derivation with ANSI x9.63 KDF.
/// - Parameters:
///   - parameters: A KDFParameters pointer.
///   - sharedInfo: Data shared between entities.
/// - Throws: A `CryptoError` describing the issue.
@available(iOS 13.0, macOS 10.15, *)
public func CCKDFParametersCreateAnsiX963(_ parameters: inout CCKDFParametersRef?, sharedInfo: Data) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCKDFParametersCreateAnsiX963(&parameters, Array(sharedInfo), sharedInfo.count))
    guard status == .success else { throw CryptoError(status) }
}

/// Clear and release a KDFParametersRef.
/// - Parameter reference: A KDFParametersRef instance.
@available(iOS 13.0, macOS 10.15, *)
public func CCKDFParametersDestroy(_ reference: CCKDFParametersRef) {
    CommonCryptoSPI.CCKDFParametersDestroy(reference)
}

/// Generic key derivation function supporting multiple key derivation algorithms.
/// - Parameters:
///   - parameters: A KDFParameters pointer.
///   - digest: The digest algorithm to use.
///   - key: The input key material to derive from.
///   - derivedSize: Desired length of the derived key.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The derived key.
@available(iOS 13.0, macOS 10.15, *)
public func CCDeriveKey(_ parameters: CCKDFParametersRef?, digest: CCDigestAlgorithm, key: Data, derivedSize: Int) throws -> Data {
    var derived = [UInt8](repeating: 0, count: derivedSize)
    let status = key.withUnsafeBytes { keyPtr in
        CCCryptorStatus(CommonCryptoSPI.CCDeriveKey(parameters, digest.rawValue, keyPtr.baseAddress, keyPtr.count, &derived, derivedSize))
    }
    guard status == .success else { throw CryptoError(status) }
    return Data(derived)
}
