import CommonCryptoSPI
import Foundation

/// Opaque reference to a CCRSACryptor object.
public typealias CCRSACryptorRef = CommonCryptoSPI.CCRSACryptorRef

/// RSA Key Types.
public enum CCRSAKeyType: RawRepresentable {
    case `public`, `private`, badKey
    
    public typealias RawValue = CommonCryptoSPI.CCRSAKeyType
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCryptoSPI.CCRSAKeyType(ccRSAKeyPublic):  self = .public
        case CommonCryptoSPI.CCRSAKeyType(ccRSAKeyPrivate): self = .private
        case CommonCryptoSPI.CCRSAKeyType(ccRSABadKey):     self = .badKey
        default: return nil
        }
    }
    
    public var rawValue: CommonCryptoSPI.CCRSAKeyType {
        switch self {
        case .public:   return CommonCryptoSPI.CCRSAKeyType(ccRSAKeyPublic)
        case .private:  return CommonCryptoSPI.CCRSAKeyType(ccRSAKeyPrivate)
        case .badKey:   return CommonCryptoSPI.CCRSAKeyType(ccRSABadKey)
        }
    }
}

/// Padding for Asymmetric ciphers.
public enum CCAsymmetricPadding: RawRepresentable {
    case none, pkcs1, oaep, pss
    
    public typealias RawValue = CommonCryptoSPI.CCAsymmetricPadding
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCryptoSPI.CCAsymmetricPadding(ccPaddingNone):    self = .none
        case CommonCryptoSPI.CCAsymmetricPadding(ccPKCS1Padding):   self = .pkcs1
        case CommonCryptoSPI.CCAsymmetricPadding(ccOAEPPadding):    self = .oaep
        case CommonCryptoSPI.CCAsymmetricPadding(ccRSAPSSPadding):  self = .pss
        default: return nil
        }
    }
    
    public var rawValue: CommonCryptoSPI.CCAsymmetricPadding {
        switch self {
        case .none:     return CommonCryptoSPI.CCAsymmetricPadding(ccPaddingNone)
        case .pkcs1:    return CommonCryptoSPI.CCAsymmetricPadding(ccPKCS1Padding)
        case .oaep:     return CommonCryptoSPI.CCAsymmetricPadding(ccOAEPPadding)
        case .pss:      return CommonCryptoSPI.CCAsymmetricPadding(ccRSAPSSPadding)
        }
    }
}

/// Generate an RSA public and private key.
/// - Parameters:
///   - keySize: The Key size in bits. RSA keys smaller than 2048 bits are insecure and should not be used.
///   - e: The "e" value (public key). Must be odd; 65537 or larger
///   - publicKey: A (required) pointer for the returned public `CCRSACryptorRef`.
///   - privateKey: A (required) pointer for the returned private `CCRSACryptorRef`.
/// - Throws: A `CryptoError` describing the issue.
public func CCRSACryptorGeneratePair(keySize: Int, e: UInt32, publicKey: inout CCRSACryptorRef?, privateKey: inout CCRSACryptorRef?) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCRSACryptorGeneratePair(keySize, e, &publicKey, &privateKey))
    guard status == .success else { throw CryptoError(status) }
}

/// Create an RSA public key from a full private key.
/// - Parameter privateKey: A pointer to a private CCRSACryptorRef.
/// - Returns: Returns either a valid public key `CCRSACryptorRef` or `nil`.
@available(iOS 13.0, macOS 10.15, *)
public func CCRSACryptorCreatePublicKeyFromPrivateKey(privateKey: CCRSACryptorRef?) -> CCRSACryptorRef? {
    CommonCryptoSPI.CCRSACryptorCreatePublicKeyFromPrivateKey(privateKey)
}

/// Deprecated. Use CCRSACryptorCreatePublicKeyFromPrivateKey() instead.
/// - Parameter privateKey: A pointer to a private CCRSACryptorRef.
/// - Returns: Returns either a valid public key `CCRSACryptorRef` or `nil`.
@available(iOS, deprecated: 13.0, renamed: "CCRSACryptorCreatePublicKeyFromPrivateKey")
@available(macOS, deprecated: 10.15, renamed: "CCRSACryptorCreatePublicKeyFromPrivateKey")
public func CCRSACryptorGetPublicKeyFromPrivateKey(privateKey: CCRSACryptorRef?) -> CCRSACryptorRef {
    CommonCryptoSPI.CCRSACryptorGetPublicKeyFromPrivateKey(privateKey)
}

/// Import an RSA key from data. This imports public or private keys in PKCS#1 format.
/// - Parameters:
///   - keyPackage: The data package containing the encoded key.
///   - key: A `CCRSACryptorRef` of the decoded key.
/// - Throws: A `CryptoError` describing the issue.
public func CCRSACryptorImport(keyPackage: Data, key: inout CCRSACryptorRef?) throws {
    let status = keyPackage.withUnsafeBytes { keyPackagePtr -> CCCryptorStatus in
        CCCryptorStatus(CommonCryptoSPI.CCRSACryptorImport(keyPackagePtr.baseAddress, keyPackagePtr.count, &key))
    }
    guard status == .success else { throw CryptoError(status) }
}

/// Export an RSA key to data. This exports public or private keys in PKCS#1 format.
/// - Parameter key: The CCRSACryptorRef of the key to encode.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The data package with the encoded key.
public func CCRSACryptorExport(key: CCCryptorRef?) throws -> Data {
    var keySize = CCWrapper.CCRSAGetKeySize(key)
    var keyOut = [UInt8](repeating: 0, count: keySize)
    let status = CCCryptorStatus(CommonCryptoSPI.CCRSACryptorExport(key, &keyOut, &keySize))
    guard status == .success else { throw CryptoError(status) }
    keyOut.removeSubrange(keySize...)
    return Data(keyOut)
}

/// Determine whether a `CCRSACryptorRef` is public or private
/// - Parameter key: The `CCRSACryptorRef`.
/// - Returns: Return values are `.public`, `.private`, or `.badKey`.
public func CCRSAGetKeyType(_ key: CCCryptorRef?) -> CCRSAKeyType {
    CCRSAKeyType(rawValue: CommonCryptoSPI.CCRSAGetKeyType(key))!
}

/// Return the key size
/// - Parameter key: The `CCRSACryptorRef`.
/// - Returns: The key size in bits.
public func CCRSAGetKeySize(_ key: CCCryptorRef?) -> Int {
    Int(CommonCryptoSPI.CCRSAGetKeySize(key))
}

/// Clear and release a CCRSACryptorRef.
/// - Parameter key: The `CCRSACryptorRef` to release.
public func CCRSACryptorRelease(_ key: CCCryptorRef?) {
    CommonCryptoSPI.CCRSACryptorRelease(key)
}

/// Compute a signature for data with an RSA private key.
/// - Parameters:
///   - privateKey: A pointer to a private `CCRSACryptorRef`.
///   - padding: A selector for the padding to be used.
///   - data: The bytes of the value to be signed.
///   - digest: The digest algorithm to use.
///   - saltSize: Length of salt to use for the signature.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The signature bytes.
public func CCRSACryptorSign(privateKey: CCCryptorRef?, padding: CCAsymmetricPadding, data: Data, digest: CCDigestAlgorithm, saltSize: Int) throws -> Data {
    let rawData = try padding == .pss ? CCDigest(algorithm: digest, data: data) : data
    
    var signatureSize = CCRSAGetKeySize(privateKey) / 8
    var signatureBytes = [UInt8](repeating: 0, count: signatureSize)
    
    let status = rawData.withUnsafeBytes { rawDataPtr -> CCCryptorStatus in
        CCCryptorStatus(CommonCryptoSPI.CCRSACryptorSign(privateKey, padding.rawValue, rawDataPtr.baseAddress, rawDataPtr.count, digest.rawValue, saltSize, &signatureBytes, &signatureSize))
    }
    guard status == .success else { throw CryptoError(status) }
    signatureBytes.removeSubrange(signatureSize...)
    return Data(signatureBytes)
}

/// Verify a signature for data with an RSA public key.
/// - Parameters:
///   - publicKey: A pointer to a public `CCRSACryptorRef`.
///   - padding: A selector for the padding to be used.
///   - data: The bytes of the value that was signed.
///   - signature: The bytes of the signature to be verified.
///   - digest: The digest algorithm to use.
///   - saltSize: Length of salt to use for the signature.
/// - Throws: A `CryptoError` describing the issue.
public func CCRSACryptorVerify(publicKey: CCCryptorRef?, padding: CCAsymmetricPadding, data: Data, signature: Data, digest: CCDigestAlgorithm, saltSize: Int) throws {
    let rawData = try padding == .pss ? CCDigest(algorithm: digest, data: data) : data
    
    let status = rawData.withUnsafeBytes { rawDataPtr -> CCCryptorStatus in
        signature.withUnsafeBytes { signaturePtr -> CCCryptorStatus in
            CCCryptorStatus(CommonCryptoSPI.CCRSACryptorVerify(publicKey, padding.rawValue, rawDataPtr.baseAddress, rawDataPtr.count, digest.rawValue, saltSize, signaturePtr.baseAddress, signaturePtr.count))
        }
    }
    guard status == .success else { throw CryptoError(status) }
}

/// Encrypt data with an RSA public key. It currently supports RSA-OAEP and PKCS1.5
/// - Parameters:
///   - publicKey: A pointer to a public `CCRSACryptorRef`.
///   - padding: A selector for the padding to be used.
///   - plainText: The data to be encrypted.
///   - tag: Tag to be included in the encryption.
///   - digest: The digest algorithm to use.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The encrypted byte result.
public func CCRSACryptorEncrypt(publicKey: CCRSACryptorRef?, padding: CCAsymmetricPadding, plainText: Data, tag: Data?, digest: CCDigestAlgorithm) throws -> Data {
    var tag = tag ?? Data()
    
    var cipherTextSize = CCRSAGetKeySize(publicKey) / 8
    var cipherText = [UInt8](repeating: 0, count: cipherTextSize)
    
    let status = plainText.withUnsafeBytes { plainTextPtr -> CCCryptorStatus in
        CCCryptorStatus(CommonCryptoSPI.CCRSACryptorEncrypt(publicKey, padding.rawValue, plainTextPtr.baseAddress, plainTextPtr.count, &cipherText, &cipherTextSize, &tag, tag.count, digest.rawValue))
    }
    guard status == .success else { throw CryptoError(status) }
    cipherText.removeSubrange(cipherTextSize...)
    return Data(cipherText)
}

/// Decrypt data with an RSA private key.
/// - Parameters:
///   - privateKey: A pointer to a private `CCRSACryptorRef`.
///   - padding: A selector for the padding to be used.
///   - cipherText: The encrypted bytes.
///   - tag: Tag to be included in the encryption.
///   - digest: The digest algorithm to use.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The decrypted data bytes.
public func CCRSACryptorDecrypt(privateKey: CCRSACryptorRef?, padding: CCAsymmetricPadding, cipherText: Data, tag: Data?, digest: CCDigestAlgorithm) throws -> Data {
    var tag = tag ?? Data()
    
    var plainTextSize = CCWrapper.CCRSAGetKeySize(privateKey)
    var plainText = [UInt8](repeating: 0, count: plainTextSize)
    
    let status = cipherText.withUnsafeBytes { cipherTextPtr -> CCCryptorStatus in
        CCCryptorStatus(CommonCryptoSPI.CCRSACryptorDecrypt(privateKey, padding.rawValue, cipherTextPtr.baseAddress, cipherTextPtr.count, &plainText, &plainTextSize, &tag, tag.count, digest.rawValue))
    }
    guard status == .success else { throw CryptoError(status) }
    plainText.removeSubrange(plainTextSize...)
    return Data(plainText)
}

public typealias RSAKeyComponents = (modulus: Data, exponent: Data, p: Data?, q: Data?)

/// Extracts the modulus, p, q, and private exponent if key is a private key, and modulus and public exponent if key is a public key.
/// - Parameter key: A pointer to a `CCRSACryptorRef`.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A tuple containing the moduls, exponent and, depending on type, the p and q value.
public func CCRSAGetKeyComponents(key: CCRSACryptorRef?) throws -> RSAKeyComponents {
    let size = CCWrapper.CCRSAGetKeySize(key) / 8
    let type = CCWrapper.CCRSAGetKeyType(key)
    
    var modulusSize: Int = size
    var modulus = [UInt8](repeating: 0, count: modulusSize)
    
    var exponentSize: Int = size
    var exponent = [UInt8](repeating: 0, count: exponentSize)
    
    var pSize: Int = type == .private ? size : 0
    var p = [UInt8](repeating: 0, count: pSize)
    
    var qSize: Int = type == .private ? size : 0
    var q = [UInt8](repeating: 0, count: qSize)
    let status = CCCryptorStatus(CommonCryptoSPI.CCRSAGetKeyComponents(key, &modulus, &modulusSize, &exponent, &exponentSize, &p, &pSize, &q, &qSize))
    guard status == .success else { throw CryptoError(status) }
    
    modulus.removeSubrange(modulusSize...)
    exponent.removeSubrange(exponentSize...)
    p.removeSubrange(pSize...)
    q.removeSubrange(qSize...)
    
    return type == .private ? (Data(modulus), Data(exponent), Data(p), Data(q)) : (Data(modulus), Data(exponent), nil, nil)
}

/// Create an RSA key from its components.
/// - Parameters:
///   - type: The type of key to create, either `.public` or `.private`.
///   - modulus: The modulus data in MSB format.
///   - exponent: The exponent data.
///   - p: The modulus factor P data.
///   - q: The modulus factor Q data.
///   - reference: A pointer to a `CCRSACryptorRef`.
/// - Throws: A `CryptoError` describing the issue.
public func CCRSACryptorCreateFromData(type: CCRSAKeyType, modulus: Data, exponent: Data, p: Data?, q: Data?, reference: inout CCCryptorRef?) throws {
    let p: [UInt8]? = p == nil ? nil : Array(p!)
    let q: [UInt8]? = q == nil ? nil : Array(q!)
    
    let status = CCCryptorStatus(CommonCryptoSPI.CCRSACryptorCreateFromData(type.rawValue, Array(modulus), modulus.count, Array(exponent), exponent.count, p, p?.count ?? 0, q, q?.count ?? 0, &reference))
    guard status == .success else { throw CryptoError(status) }
}
