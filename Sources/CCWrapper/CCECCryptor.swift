import CommonCryptoSPI
import Foundation

/// Opaque reference to a CCECCryptor object.
public typealias CCECCryptorRef = CommonCryptoSPI.CCECCryptorRef

/// EC Key Types.
public enum CCECKeyType: RawRepresentable {
    case `public`,`private`, badKey
    
    public typealias RawValue = CommonCryptoSPI.CCECKeyType
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCryptoSPI.CCECKeyType(ccECKeyPublic):   self = .public
        case CommonCryptoSPI.CCECKeyType(ccECKeyPrivate):  self = .private
        case CommonCryptoSPI.CCECKeyType(ccECBadKey):      self = .badKey
        default: return nil
        }
    }
    
    public var rawValue: CommonCryptoSPI.CCECKeyType {
        switch self {
        case .public:   return CommonCryptoSPI.CCECKeyType(ccECKeyPublic)
        case .private:  return CommonCryptoSPI.CCECKeyType(ccECKeyPrivate)
        case .badKey:   return CommonCryptoSPI.CCECKeyType(ccECBadKey)
        }
    }
}

/// EC Key Import/Export Formats.
public enum CCECKeyExternalFormat: RawRepresentable {
    case binary, compact
    
    public typealias RawValue = CommonCryptoSPI.CCECKeyExternalFormat
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCryptoSPI.CCECKeyExternalFormat(kCCImportKeyBinary):     self = .binary
        case CommonCryptoSPI.CCECKeyExternalFormat(kCCImportKeyCompact): 	self = .compact
        default: return nil
        }
    }
    
    public var rawValue: CommonCryptoSPI.CCECKeyExternalFormat {
        switch self {
        case .binary:   return CommonCryptoSPI.CCECKeyExternalFormat(kCCImportKeyBinary)
        case .compact:  return CommonCryptoSPI.CCECKeyExternalFormat(kCCImportKeyCompact)
        }
    }
}

/// Generate an EC public and private key.
/// - Parameters:
///   - keySize: The key size. Must be between 192 and 521 (inclusive).
///   - publicKey: A (required) pointer for the returned public `CCECCryptorRef`.
///   - privateKey: A (required) pointer for the returned private `CCECCryptorRef`.
/// - Throws: A `CryptoError` describing the issue.
public func CCECCryptorGeneratePair(keySize: Int, publicKey: inout CCECCryptorRef?, privateKey: inout CCECCryptorRef?) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCECCryptorGeneratePair(keySize, &publicKey, &privateKey))
    guard status == .success else { throw CryptoError(status) }
}

/// Grab the parts from a private key to make a public key.
/// - Parameter privateKey: A pointer to a private `CCECCryptorRef`.
/// - Returns: Returns either a valid public key `CCECCryptorRef` or `nil`.
public func CCECCryptorGetPublicKeyFromPrivateKey(privateKey: CCECCryptorRef?) -> CCECCryptorRef? {
    CommonCryptoSPI.CCECCryptorGetPublicKeyFromPrivateKey(privateKey)
}

/// Import an Elliptic Curve public key from data. This imports public keys in ANSI X.9.63 format.
/// - Parameters:
///   - keyPackage: The data package containing the encoded key.
///   - key: A `CCECCryptorRef` of the decoded key.
/// - Throws: A `CryptoError` describing the issue.
public func CCECCryptorImportPublicKey(keyPackage: Data, key: inout CCECCryptorRef?) throws {
    let status = keyPackage.withUnsafeBytes {
        CCCryptorStatus(CommonCryptoSPI.CCECCryptorImportPublicKey($0.baseAddress, $0.count, &key))
    }
    guard status == .success else { throw CryptoError(status) }
}

/// Import an Elliptic Curve public key from data.
/// - Parameters:
///   - format: The format in which the key is encoded.
///   - keyPackage: The data package containing the encoded key.
///   - keyType: The type of key to be imported (public or private).
///   - key: A `CCECCryptorRef` of the decoded key.
/// - Throws: A `CryptoError` describing the issue.
public func CCECCryptorImportKey(format: CCECKeyExternalFormat, keyPackage: Data, keyType: CCECKeyType, key: inout CCECCryptorRef?) throws {
    let status = keyPackage.withUnsafeBytes {
        CCCryptorStatus(CommonCryptoSPI.CCECCryptorImportKey(format.rawValue, $0.baseAddress, $0.count, keyType.rawValue, &key))
    }
    guard status == .success else { throw CryptoError(status) }
}

public func CCECCryptorExportKey(format: CCECKeyExternalFormat, key: CCECCryptorRef?) throws -> Data {
    let keyType = CCWrapper.CCECGetKeyType(key)
    var outputSize = CCWrapper.CCECGetKeySize(key)
    var output = [UInt8](repeating: 0, count: outputSize)
    let status = CCCryptorStatus(CommonCryptoSPI.CCECCryptorExportKey(format.rawValue, &output, &outputSize, keyType.rawValue, key))
    guard status == .success else { throw CryptoError(status) }
    output.removeSubrange(outputSize...)
    return Data(output)
}

/// Determine whether a CCECCryptorRef is public or private
/// - Parameter key: The `CCECCryptorRef`.
/// - Returns: Return values are `.public`, `.private`, or `.badKey`.
public func CCECGetKeyType(_ key: CCCryptorRef?) -> CCECKeyType {
    CCECKeyType(rawValue: CommonCryptoSPI.CCECGetKeyType(key))!
}

/// Returns the key size.
/// - Parameter key: The `CCECCryptorRef`.
/// - Returns: The key size in bits.
public func CCECGetKeySize(_ key: CCCryptorRef?) -> Int {
    Int(CommonCryptoSPI.CCECGetKeySize(key))
}

/// Clear and release a CCECCryptorRef.
/// - Parameter key: The `CCECCryptorRef` of the key to release.
public func CCECCryptorRelease(_ key: CCCryptorRef?) {
    CommonCryptoSPI.CCECCryptorRelease(key)
}

/// Compute a signature for a hash with an EC private key.
/// - Parameters:
///   - privateKey: A pointer to a private `CCECCryptorRef`.
///   - hash: The bytes of the value to be signed.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The signature bytes.
public func CCECCryptorSignHash(privateKey: CCECCryptorRef?, hash: Data) throws -> Data {
    var signatureSize = hash.count * 8
    var signatureBytes = [UInt8](repeating: 0, count: signatureSize)
    let status = hash.withUnsafeBytes {
        CCCryptorStatus(CommonCryptoSPI.CCECCryptorSignHash(privateKey, $0.baseAddress, $0.count, &signatureBytes, &signatureSize))
    }
    guard status == .success else { throw CryptoError(status) }
    signatureBytes.removeSubrange(signatureSize...)
    return Data(signatureBytes)
}

/// Verify a signature for data with an EC private key.
/// - Parameters:
///   - publicKey: A pointer to a public `CCECCryptorRef`.
///   - hash: The bytes of the hash of the data.
///   - signature: The bytes of the signature to be verified.
/// - Throws: A `CryptoError` describing the issue.
public func CCECCryptorVerifyHash(publicKey: CCECCryptorRef?, hash: Data, signature: Data) throws {
    var valid: UInt32 = 0
    let status = hash.withUnsafeBytes { hashPtr -> CCCryptorStatus in
        signature.withUnsafeBytes { signaturePtr -> CCCryptorStatus in
            CCCryptorStatus(CommonCryptoSPI.CCECCryptorVerifyHash(publicKey, hashPtr.baseAddress, hashPtr.count, signaturePtr.baseAddress, signaturePtr.count, &valid))
        }
    }
    guard status == .success else { throw CryptoError(status) }
    guard valid == 1 else { throw CryptoError.notVerified }
}

/// Construct a Diffie-Hellman shared secret with a private and public ECC key.
/// - Parameters:
///   - privateKey: A pointer to a private `CCECCryptorRef`.
///   - publicKey: A pointer to a public `CCECCryptorRef` (usually obtained from the other party in the session.)
///   - size: The output size.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The shared secret.
public func CCECCryptorComputeSharedSecret(privateKey: CCECCryptorRef?, publicKey: CCECCryptorRef?, size: Int) throws -> Data {
    var sharedSize = size
    var shared = [UInt8](repeating: 0, count: sharedSize)
    let status = CCCryptorStatus(CommonCryptoSPI.CCECCryptorComputeSharedSecret(privateKey, publicKey, &shared, &sharedSize))
    guard status == .success else { throw CryptoError(status) }
    shared.removeSubrange(sharedSize...)
    return Data(shared)
}

/// Diversifies a given EC key by deriving two scalars u,v from the given entropy.
/// - Parameters:
///   - keyType: The type of key to be diversified (public or private).
///   - inKey: A `CCECCryptorRef` of type "keyType".
///   - entropy: The entropy data.
///   - outKey: A pointer to a `CCECCryptorRef` of type "keyType".
/// - Throws: A `CryptoError` describing the issue.
@available(iOS 13.0, macOS 10.15, *)
public func CCECCryptorTwinDiversifyKey(inKey: CCECCryptorRef?, entropy: Data, outKey: inout CCECCryptorRef?) throws {
    var entropy = entropy
    let status = CCCryptorStatus(CommonCryptoSPI.CCECCryptorTwinDiversifyKey(CCECGetKeyType(inKey).rawValue, inKey, &entropy, entropy.count, &outKey))
    guard status == .success else { throw CryptoError(status) }
}

/// Returns the length of the entropy required by `CCECCryptorTwinDiversifyKey()`.
/// - Parameter key: A `CCECCryptorRef`.
/// - Returns: The entropy size.
@available(iOS 13.0, macOS 10.15, *)
public func CCECCryptorTwinDiversifyEntropySize(_ key: CCECCryptorRef?) -> Int {
    CommonCryptoSPI.CCECCryptorTwinDiversifyEntropySize(key)
}

public typealias ECKeyComponents = (x: Data, y: Data, d: Data?)

/// Get EC Public Key Parameters
/// - Parameter key: The EC Key to deconstruct
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A tuple containing the X, Y and, depending on type, the D value.
public func CCECCryptorGetKeyComponents(key: CCECCryptorRef?) throws -> ECKeyComponents {
    var size = CCECGetKeySize(key) / 8
    let type = CCWrapper.CCECGetKeyType(key)
    
    var xSize = size
    var x = [UInt8](repeating: 0, count: xSize)
    
    var ySize = size
    var y = [UInt8](repeating: 0, count: ySize)
    
    var dSize = size
    var d = [UInt8](repeating: 0, count: dSize)
    
    let status = CCCryptorStatus(CCECCryptorGetKeyComponents(key, &size, &x, &xSize, &y, &ySize, &d, &dSize))
    guard status == .success else { throw CryptoError(status) }
    
    x.removeSubrange(xSize...)
    y.removeSubrange(ySize...)
    d.removeSubrange(dSize...)
    
    return type == .private ? (Data(x), Data(y), Data(d)) : (Data(x), Data(y), nil)
}
