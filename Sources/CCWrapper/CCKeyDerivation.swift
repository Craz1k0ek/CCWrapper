import CommonCryptoSPI
import Foundation

public typealias KDFParametersRef = CCKDFParametersRef

/// Key Derivation algorithms implemented by this module.
public enum KDFAlgorithm: RawRepresentable {
    case pbkdf2Hmac
    case ctrHmac
    case ctrHmacFixed
    case hkdf
    case ansiX963
    
    public typealias RawValue = CCKDFAlgorithm
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CCKDFAlgorithm(kCCKDFAlgorithmPBKDF2_HMAC):    self = .pbkdf2Hmac
        case CCKDFAlgorithm(kCCKDFAlgorithmCTR_HMAC):       self = .ctrHmac
        case CCKDFAlgorithm(kCCKDFAlgorithmCTR_HMAC_FIXED): self = .ctrHmacFixed
        case CCKDFAlgorithm(kCCKDFAlgorithmHKDF):           self = .hkdf
        case CCKDFAlgorithm(kCCKDFAlgorithmAnsiX963):       self = .ansiX963
        default: return nil
        }
    }
    
    public var rawValue: CCKDFAlgorithm {
        switch self {
        case .pbkdf2Hmac:   return CCKDFAlgorithm(kCCKDFAlgorithmPBKDF2_HMAC)
        case .ctrHmac:      return CCKDFAlgorithm(kCCKDFAlgorithmCTR_HMAC)
        case .ctrHmacFixed: return CCKDFAlgorithm(kCCKDFAlgorithmCTR_HMAC_FIXED)
        case .hkdf:         return CCKDFAlgorithm(kCCKDFAlgorithmHKDF)
        case .ansiX963:     return CCKDFAlgorithm(kCCKDFAlgorithmAnsiX963)
        }
    }
}

public enum PBKDFAlgorithm: RawRepresentable {
    case pbkdf2
    
    public typealias RawValue = CCPBKDFAlgorithm
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CCPBKDFAlgorithm(kCCPBKDF2): self = .pbkdf2
        default: return nil
        }
    }
    
    public var rawValue: CCPBKDFAlgorithm { return CCPBKDFAlgorithm(kCCPBKDF2) }
}

public enum PseudoRandomAlgorithm: RawRepresentable {
    case prfHmacSHA1
    case prfHmacSHA224
    case prfHmacSHA256
    case prfHmacSHA384
    case prfHmacSHA512
    
    public typealias RawValue = CCPseudoRandomAlgorithm
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1):    self = .prfHmacSHA1
        case CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224):  self = .prfHmacSHA224
        case CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256):  self = .prfHmacSHA256
        case CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384):  self = .prfHmacSHA384
        case CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512):  self = .prfHmacSHA512
        default: return nil
        }
    }
    
    public var rawValue: CCPseudoRandomAlgorithm {
        switch self {
        case .prfHmacSHA1:      return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        case .prfHmacSHA224:    return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
        case .prfHmacSHA256:    return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .prfHmacSHA384:    return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
        case .prfHmacSHA512:    return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
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
public func KeyDerivationPBKDF(algorithm: PBKDFAlgorithm, password: String, salt: Data, prf: PseudoRandomAlgorithm, rounds: UInt32, derivedSize: Int) throws -> Data {
    var derived = [UInt8](repeating: 0, count: derivedSize)
    let status = CryptorStatus(CCKeyDerivationPBKDF(algorithm.rawValue, password, password.count, Array(salt), salt.count, prf.rawValue, rounds, &derived, derivedSize))
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
public func KDFParametersCreatePbkdf2(_ parameters: inout KDFParametersRef?, rounds: UInt32, salt: Data) throws {
    let status = CryptorStatus(CCKDFParametersCreatePbkdf2(&parameters, rounds, Array(salt), salt.count))
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
public func KDFParametersCreateCtrHmac(_ parameters: inout KDFParametersRef?, label: Data, context: Data) throws {
    let status = CryptorStatus(CCKDFParametersCreateCtrHmac(&parameters, Array(label), label.count, Array(context), context.count))
    guard status == .success else { throw CryptoError(status) }
}

/// Creates a CCKDFParameters object that will hold parameters
/// for key derivation with NIST SP800-108 KDF in Counter Mode with an HMAC PRF.
/// - Parameters:
///   - parameters: A KDFParameters pointer.
///   - context: Data shared between entities.
/// - Throws: A `CryptoError` describing the issue.
@available(iOS 13.0, macOS 10.15, *)
public func KDFParametersCreateCtrHmacFixed(_ parameters: inout KDFParametersRef?, context: Data) throws {
    let status = CryptorStatus(CCKDFParametersCreateCtrHmacFixed(&parameters, Array(context), context.count))
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
public func KDFParametersCreateHkdf(_ parameters: inout KDFParametersRef?, salt: Data, context: Data) throws {
    let status = CryptorStatus(CCKDFParametersCreateHkdf(&parameters, Array(salt), salt.count, Array(context), context.count))
    guard status == .success else { throw CryptoError(status) }
}

/// Creates a CCKDFParameters object that will hold parameters
/// for key derivation with ANSI x9.63 KDF.
/// - Parameters:
///   - parameters: A KDFParameters pointer.
///   - sharedInfo: Data shared between entities.
/// - Throws: A `CryptoError` describing the issue.
@available(iOS 13.0, macOS 10.15, *)
public func KDFParametersCreateAnsiX963(_ parameters: inout KDFParametersRef?, sharedInfo: Data) throws {
    let status = CryptorStatus(CCKDFParametersCreateAnsiX963(&parameters, Array(sharedInfo), sharedInfo.count))
    guard status == .success else { throw CryptoError(status) }
}

/// Clear and release a KDFParametersRef.
/// - Parameter reference: A KDFParametersRef instance.
@available(iOS 13.0, macOS 10.15, *)
public func KDFParametersDestroy(_ reference: KDFParametersRef) {
    CCKDFParametersDestroy(reference)
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
public func DeriveKey(_ parameters: KDFParametersRef?, digest: DigestAlgorithm, key: Data, derivedSize: Int) throws -> Data {
    var derived = [UInt8](repeating: 0, count: derivedSize)
    let status = key.withUnsafeBytes { keyPtr in
        CryptorStatus(CCDeriveKey(parameters, digest.rawValue, keyPtr.baseAddress, keyPtr.count, &derived, derivedSize))
    }
    guard status == .success else { throw CryptoError(status) }
    return Data(derived)
}
