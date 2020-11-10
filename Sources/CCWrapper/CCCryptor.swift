import CommonCryptoSPI
import Foundation

/// Opaque reference type to a CCCryptor object.
public typealias CryptorRef = CommonCrypto.CCCryptorRef

/// Operations that a cryptor can perform.
public enum Operation: RawRepresentable {
    /// The encrypt operation.
    case encrypt
    /// The decrypt operation.
    case decrypt
    /// Bidirectional operation used by XTS.
    case both
    
    public typealias RawValue = CommonCrypto.CCOperation
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCrypto.CCOperation(kCCEncrypt): 	self = .encrypt
        case CommonCrypto.CCOperation(kCCDecrypt):  self = .decrypt
        case CommonCrypto.CCOperation(kCCBoth):     self = .both
        default: return nil
        }
    }
    
    public var rawValue: CommonCrypto.CCOperation {
        switch self {
        case .encrypt:  return CommonCrypto.CCOperation(kCCEncrypt)
        case .decrypt:  return CommonCrypto.CCOperation(kCCDecrypt)
        case .both:     return CommonCrypto.CCOperation(kCCBoth)
        }
    }
}

/// Encryption algorithms implemented by this module.
public enum Algorithm: RawRepresentable {
    /// Advanced Encryption Standard, 128-bit block.
    case aes
    /// Data Encryption Standard.
    case des
    /// Triple-DES, three key, EDE configuration.
    case tripleDES
    /// CAST.
    case cast
    /// RC4 stream cipher.
    case rc4
    /// RC2 block cipher.
    case rc2
    /// Blowfish block cipher.
    case blowfish
    
    public typealias RawValue = CommonCrypto.CCAlgorithm
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCrypto.CCAlgorithm(kCCAlgorithmAES), CommonCrypto.CCAlgorithm(kCCAlgorithmAES128): self = .aes
        case CommonCrypto.CCAlgorithm(kCCAlgorithmDES):      self = .des
        case CommonCrypto.CCAlgorithm(kCCAlgorithm3DES):     self = .tripleDES
        case CommonCrypto.CCAlgorithm(kCCAlgorithmCAST):     self = .cast
        case CommonCrypto.CCAlgorithm(kCCAlgorithmRC4):      self = .rc4
        case CommonCrypto.CCAlgorithm(kCCAlgorithmRC2):      self = .rc2
        case CommonCrypto.CCAlgorithm(kCCAlgorithmBlowfish): self = .blowfish
        default: return nil
        }
    }
    
    public var rawValue: CommonCrypto.CCAlgorithm {
        switch self {
        case .aes:          return CommonCrypto.CCAlgorithm(kCCAlgorithmAES)
        case .des:          return CommonCrypto.CCAlgorithm(kCCAlgorithmDES)
        case .tripleDES:    return CommonCrypto.CCAlgorithm(kCCAlgorithm3DES)
        case .cast:         return CommonCrypto.CCAlgorithm(kCCAlgorithmCAST)
        case .rc4:          return CommonCrypto.CCAlgorithm(kCCAlgorithmRC4)
        case .rc2:          return CommonCrypto.CCAlgorithm(kCCAlgorithmRC2)
        case .blowfish:     return CommonCrypto.CCAlgorithm(kCCAlgorithmBlowfish)
        }
    }
}

/// Key sizes, in bytes, for supported algorithms.
public enum KeySize {
    /// 128 bit AES key size.
    case aes128
    /// 192 bit AES key size.
    case aes192
    /// 256 bit AES key size.
    case aes256
    /// DES key size.
    case des
    /// Triple DES key size.
    case tripleDES
    /// CAST minimum key size.
    case minCAST
    /// CAST maximum key size.
    case maxCAST
    /// RC4 minimum key size.
    case minRC4
    /// RC4 maximum key size.
    case maxRC4
    /// RC2 minimum key size.
    case minRC2
    /// RC2 maximum key size.
    case maxRC2
    /// Blowfish minimum key size.
    case minBlowfish
    /// Blowfish maximum key size.
    case maxBlowfish
    
    public var rawValue: Int {
        switch self {
        case .aes128:       return kCCKeySizeAES128
        case .aes192:       return kCCKeySizeAES192
        case .aes256:       return kCCKeySizeAES256
        case .des:          return kCCKeySizeDES
        case .tripleDES:    return kCCKeySize3DES
        case .minCAST:      return kCCKeySizeMinCAST
        case .maxCAST:      return kCCKeySizeMaxCAST
        case .minRC4:       return kCCKeySizeMinRC4
        case .maxRC4:       return kCCKeySizeMaxRC4
        case .minRC2:       return kCCKeySizeMinRC2
        case .maxRC2:       return kCCKeySizeMaxRC2
        case .minBlowfish:  return kCCKeySizeMinBlowfish
        case .maxBlowfish:  return kCCKeySizeMaxBlowfish
        }
    }
}

/// Block sizes, in bytes, for supported algorithms.
public enum BlockSize {
    /// AES block size (currently, only 128-bit blocks are supported).
    case aes
    /// DES block size.
    case des
    /// Triple DES block size.
    case tripleDES
    /// CAST block size.
    case cast
    /// RC2 block size.
    case rc2
    /// Blowfish block size.
    case blowfish
    
    public var rawValue: Int {
        switch self {
        case .aes:          return kCCBlockSizeAES128
        case .des:          return kCCBlockSizeDES
        case .tripleDES:    return kCCBlockSize3DES
        case .cast:         return kCCBlockSizeCAST
        case .rc2:          return kCCBlockSizeRC2
        case .blowfish:     return kCCBlockSizeBlowfish
        }
    }
}

/// These are the selections available for modes of operation for use with block ciphers.
/// If RC4 is selected as the cipher (a stream cipher) the only correct mode is `.rc4`.
public enum Mode: RawRepresentable {
    /// Electronic Code Book Mode.
    case ecb
    /// Cipher Block Chaining Mode.
    case cbc
    /// Cipher Feedback Mode.
    case cfb
    /// Counter Mode.
    case ctr
    /// Output Feedback Mode.
    case ofb
    /// RC4 as a streaming cipher is handled internally as a mode.
    case rc4
    /// Cipher Feedback Mode producing 8 bits per round.
    case cfb8
    case xts
    case gcm
    case ccm
    
    public typealias RawValue = CommonCrypto.CCMode
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCrypto.CCMode(kCCModeECB):   self = .ecb
        case CommonCrypto.CCMode(kCCModeCBC):   self = .cbc
        case CommonCrypto.CCMode(kCCModeCFB):   self = .cfb
        case CommonCrypto.CCMode(kCCModeCTR):   self = .ctr
        case CommonCrypto.CCMode(kCCModeOFB):   self = .ofb
        case CommonCrypto.CCMode(kCCModeRC4):   self = .rc4
        case CommonCrypto.CCMode(kCCModeCFB8):  self = .cfb8
        case CommonCrypto.CCMode(kCCModeXTS):   self = .xts
        case CommonCrypto.CCMode(kCCModeGCM):   self = .gcm
        case CommonCrypto.CCMode(kCCModeCCM):   self = .ccm
        default: return nil
        }
    }
    
    public var rawValue: CommonCrypto.CCMode {
        switch self {
        case .ecb:  return CommonCrypto.CCMode(kCCModeECB)
        case .cbc:  return CommonCrypto.CCMode(kCCModeCBC)
        case .cfb:  return CommonCrypto.CCMode(kCCModeCFB)
        case .ctr:  return CommonCrypto.CCMode(kCCModeCTR)
        case .ofb:  return CommonCrypto.CCMode(kCCModeOFB)
        case .rc4:  return CommonCrypto.CCMode(kCCModeRC4)
        case .cfb8: return CommonCrypto.CCMode(kCCModeCFB8)
        case .xts:  return CommonCrypto.CCMode(kCCModeXTS)
        case .gcm:  return CommonCrypto.CCMode(kCCModeGCM)
        case .ccm:  return CommonCrypto.CCMode(kCCModeCCM)
        }
    }
}

/// These are the padding options available for block modes.
public enum Padding: RawRepresentable {
    /// No padding.
    case none
    /// PKCS7 Padding.
    case pkcs7Padding
    
    public typealias RawValue = CommonCrypto.CCPadding
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCrypto.CCPadding(ccNoPadding):    self = .none
        case CommonCrypto.CCPadding(ccPKCS7Padding): self = .pkcs7Padding
        default: return nil
        }
    }
    
    public var rawValue: CommonCrypto.CCPadding {
        switch self {
        case .none:         return CommonCrypto.CCPadding(ccNoPadding)
        case .pkcs7Padding: return CommonCrypto.CCPadding(ccPKCS7Padding)
        }
    }
}

public enum Parameter: RawRepresentable {
    /// Initialization vector - cryptor input parameter, typically needs to have the same length as block size,
    /// but in some cases (GCM) it can be arbitrarily long and even might be called multiple times.
    case iv
    /// Authentication data - cryptor input parameter, input for authenticating encryption modes like GCM.
    /// If supported, can be called multiple times before encryption starts.
    case authenticationData
    /// Mac Size - cryptor input parameter, input for authenticating encryption modes like CCM.
    /// Specifies the size of the AuthTag the algorithm is expected to produce.
    case macSize
    /// Data Size - cryptor input parameter, input for authenticating encryption modes like CCM.
    /// Specifies the amount of data the algorithm is expected to process.
    case dataSize
    /// Authentication tag - cryptor output parameter, output from authenticating encryption modes like CCM.
    /// If supported, should be retrieved after the encryption finishes.
    case authenticationTag
    
    public typealias RawValue = CCParameter
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CCParameter(kCCParameterIV):       self = .iv
        case CCParameter(kCCParameterAuthData): self = .authenticationData
        case CCParameter(kCCMacSize):           self = .macSize
        case CCParameter(kCCDataSize):          self = .dataSize
        case CCParameter(kCCParameterAuthTag): 	self = .authenticationTag
        default: return nil
        }
    }
    
    public var rawValue: CCParameter {
        switch self {
        case .iv:                   return  CCParameter(kCCParameterIV)
        case .authenticationData:   return  CCParameter(kCCParameterAuthData)
        case .macSize:              return  CCParameter(kCCMacSize)
        case .dataSize:             return  CCParameter(kCCDataSize)
        case .authenticationTag:    return  CCParameter(kCCParameterAuthTag)
        }
    }
}

/// Free a cryptor reference.
/// - Parameter reference: The reference to free.
/// - Throws: A `CryptoError` describing the issue.
public func CryptorRelease(_ reference: CryptorRef?) throws {
    let status = CryptorStatus(CommonCrypto.CCCryptorRelease(reference))
    guard status == .success else { throw CryptoError(status) }
}

/// Determine output buffer size required to process a given input size.
/// - Parameters:å
///   - reference: The cryptor reference.
///   - inputLength: The length of data to process.
///   - final: Whether or not this is the final operation.
/// - Returns: The required size in the output buffer to process input size bytes.
public func CryptorGetOutputLength(_ reference: CCCryptorRef?, inputLength: Int, final: Bool) -> Int {
    CommonCrypto.CCCryptorGetOutputLength(reference, inputLength, final)
}

/// Process (encrypt/decrypt) some data. The result, if any, is returned.
/// - Parameters:
///   - reference: The cryptor reference.
///   - data: The data to process.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The processed data.
public func CryptorUpdate(_ reference: CryptorRef?, data: Data) throws -> Data {
    var output = [UInt8](repeating: 0, count: CryptorGetOutputLength(reference, inputLength: data.count, final: false))
    let status = data.withUnsafeBytes { dataPointer -> CryptorStatus in
        CryptorStatus(CommonCrypto.CCCryptorUpdate(reference, dataPointer.baseAddress, data.count, &output, output.count, nil))
    }
    guard status == .success else { throw CryptoError(status) }
    return Data(output)
}

/// Finish an encrypt or decrypt operation, and obtain the (possible) final data output.
/// - Parameter reference: The cryptor reference.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The processed final data.
public func CryptorFinalize(_ reference: CryptorRef?) throws -> Data {
    var output = [UInt8](repeating: 0, count: CryptorGetOutputLength(reference, inputLength: 0, final: true))
    var moved = 0
    let status = CryptorStatus(CommonCrypto.CCCryptorFinal(reference, &output, output.count, &moved))
    guard status == .success else { throw CryptoError(status) }
    output.removeSubrange(moved...)
    return Data(output)
}

/// Create a cryptographic context.
/// - Parameters:
///   - op: Defines the basic operation.
///   - mode: Specifies the cipher mode to use for operations.
///   - alg: Defines the algorithm.
///   - padding: Specififies the padding to use.
///   - iv: Initialization vector, optional.
///   - key: Raw key material.
///   - tweak: Raw key material.
///   - reference: The cryptor reference.
/// - Throws: A `CryptoError` describing the issue.
public func CryptorCreateWithMode(op: Operation, mode: Mode, alg: Algorithm, padding: Padding, iv: Data?, key: Data, tweak: Data?, reference: inout CryptorRef?) throws {
    let iv: [UInt8]?    = iv == nil ? nil : Array(iv!)
    let tweak: [UInt8]? = tweak == nil ? nil : Array(tweak!)
    
    let status = key.withUnsafeBytes { keyPtr -> CryptorStatus in
        CryptorStatus(CCCryptorCreateWithMode(op.rawValue, mode.rawValue, alg.rawValue, padding.rawValue, iv, keyPtr.baseAddress, key.count, tweak, tweak?.count ?? 0, 0, 0, &reference))
    }
    guard status == .success else { throw CryptoError(status) }
}

public func CryptorEncryptDataBlock(_ reference: CryptorRef?, iv: Data, data: Data) throws -> Data {
    var output = [UInt8](repeating: 0, count: data.count)
    let status = iv.withUnsafeBytes { ivPtr -> CryptorStatus in
        data.withUnsafeBytes { dataPtr -> CryptorStatus in
            CryptorStatus(CCCryptorEncryptDataBlock(reference, ivPtr.baseAddress, dataPtr.baseAddress, data.count, &output))
        }
    }
    guard status == .success else { throw CryptoError(status) }
    return Data(output)
}

public func CryptorDecryptDataBlock(_ reference: CryptorRef?, iv: Data, data: Data) throws -> Data {
    var output = [UInt8](repeating: 0, count: data.count)
    let status = iv.withUnsafeBytes { ivPtr -> CryptorStatus in
        data.withUnsafeBytes { dataPtr -> CryptorStatus in
            CryptorStatus(CCCryptorDecryptDataBlock(reference, ivPtr.baseAddress, dataPtr.baseAddress, data.count, &output))
        }
    }
    guard status == .success else { throw CryptoError(status) }
    return Data(output)
}

/// This finalizes the GCM state.
/// - Note: On encryption, the computed tag is returned in the tag field.
/// On decryption, the provided tag is securely compared to the expected tag and an error is thrown if the tags do not match.
/// - Throws: A `CryptoError` describing the issue.
public func CryptorGCMFinalize(_ reference: CryptorRef?, tag: inout Data) throws {
    let status = tag.withUnsafeMutableBytes { tagPtr -> CryptorStatus in
        CryptorStatus(CCCryptorGCMFinalize(reference, tagPtr.baseAddress, tagPtr.count))
    }
    guard status == .success else { throw CryptoError(status) }
}

/// Reset the GCM state to the initial state.
/// - Note: After that, the initialization vector and authentication data will have to be added again.
/// - Throws: A `CryptoError` describing the issue.
public func CryptorGCMReset(_ reference: CryptorRef?) throws {
    let status = CryptorStatus(CCCryptorGCMReset(reference))
    guard status == .success else { throw CryptoError(status) }
}

/// Sets or adds some other cryptor input parameter.  According to the
/// cryptor type and state, parameter can be either accepted or
/// refused with kCCUnimplemented (when given parameter is not
/// supported for this type of cryptor at all) or kCCParamError (bad
/// data length or format) or kCCCallSequenceError (bad sequence of
/// calls when using GCM or CCM).


/// Add the initialization vector or authentication data.
/// - Parameters:
///   - reference: The cryptor reference.
///   - parameter: The parameter to set.
///   - data: The data to set the parameter to.
/// - Throws: A `CryptoError` describing the issue.
public func CryptorAddParameter(_ reference: CryptorRef?, parameter: Parameter, data: Data) throws {
    let status = data.withUnsafeBytes { dataPtr -> CryptorStatus in
        CryptorStatus(CCCryptorAddParameter(reference, parameter.rawValue, dataPtr.baseAddress, dataPtr.count))
    }
    guard status == .success else { throw CryptoError(status) }
}

/// Add the MAC size or data size.
/// - Parameters:
///   - reference: The cryptor reference.
///   - parameter: The parameter to set.
///   - size: The size to set.
/// - Throws: A `CryptoError` describing the issue.
public func CryptorAddParameter(_ reference: CryptorRef?, parameter: Parameter, size: Int) throws {
    let status = CryptorStatus(CCCryptorAddParameter(reference, parameter.rawValue, nil, size))
    guard status == .success else { throw CryptoError(status) }
}

/// Get the authentication tag when performing CCM.
/// - Parameters:
///   - reference: The cryptor reference.
///   - parameter: The parameter to retrieve.
///   - size: The expected output size.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The retrieved data of the parameter.
public func CryptorGetParameter(_ reference: CryptorRef?, parameter: Parameter, size: Int) throws -> Data {
    var size = size
    var output = [UInt8](repeating: 0, count: size)
    let status = CryptorStatus(CCCryptorGetParameter(reference, parameter.rawValue, &output, &size))
    guard status == .success else { throw CryptoError(status) }
    output.removeSubrange(size...)
    return Data(output)
}
