import CommonCryptoSPI

public enum CryptorStatus: RawRepresentable {
    /// Illegal parameter value.
    case paramError
    /// Insufficent buffer provided for specified operation.
    case bufferTooSmall
    /// Memory allocation failure.
    case memoryFailure
    /// Input size was not aligned properly.
    case alignmentError
    /// Input data did not decode or decrypt properly.
    case decodeError
    /// Function not implemented for the current algorithm.
    case unimplemented
    case overflow
    case rngFailure
    case unspecifiedError
    case callSequenceError
    case keySizeError
    /// Key is not valid.
    case invalidKey
    /// Signature verification failed.
    case notVerified
    case unknown(CCCryptorStatus)
    
    public typealias RawValue = CCCryptorStatus
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CCCryptorStatus(kCCParamError):        self = .paramError
        case CCCryptorStatus(kCCBufferTooSmall):    self = .bufferTooSmall
        case CCCryptorStatus(kCCMemoryFailure):     self = .memoryFailure
        case CCCryptorStatus(kCCAlignmentError):    self = .alignmentError
        case CCCryptorStatus(kCCDecodeError):       self = .decodeError
        case CCCryptorStatus(kCCUnimplemented):     self = .unimplemented
        case CCCryptorStatus(kCCOverflow):          self = .overflow
        case CCCryptorStatus(kCCRNGFailure):        self = .rngFailure
        case CCCryptorStatus(kCCUnspecifiedError):  self = .unspecifiedError
        case CCCryptorStatus(kCCCallSequenceError): self = .callSequenceError
        case CCCryptorStatus(kCCKeySizeError):      self = .keySizeError
        case CCCryptorStatus(kCCInvalidKey):        self = .invalidKey
        case CCCryptorStatus(kCCNotVerified):       self = .notVerified
        default:                                    self = .unknown(rawValue)
        }
    }
    
    public var rawValue: CCCryptorStatus {
        switch self {
        case .paramError:           return CCCryptorStatus(kCCParamError)
        case .bufferTooSmall:       return CCCryptorStatus(kCCBufferTooSmall)
        case .memoryFailure: 		return CCCryptorStatus(kCCMemoryFailure)
        case .alignmentError: 	    return CCCryptorStatus(kCCAlignmentError)
        case .decodeError: 	        return CCCryptorStatus(kCCDecodeError)
        case .unimplemented: 	    return CCCryptorStatus(kCCUnimplemented)
        case .overflow:             return CCCryptorStatus(kCCOverflow)
        case .rngFailure:       	return CCCryptorStatus(kCCRNGFailure)
        case .unspecifiedError:     return CCCryptorStatus(kCCUnspecifiedError)
        case .callSequenceError:    return CCCryptorStatus(kCCCallSequenceError)
        case .keySizeError:         return CCCryptorStatus(kCCKeySizeError)
        case .invalidKey:           return CCCryptorStatus(kCCInvalidKey)
        case .notVerified:          return CCCryptorStatus(kCCNotVerified)
        case .unknown(let status):  return status
        }
    }
}

/// Return values from CommonCryptor operations.
/// Interpreted into errors.
/// - Note: `kCCSuccess` is not considered an error.
public enum CryptoError: Swift.Error {
    /// Illegal parameter value.
    case paramError
    /// Insufficent buffer provided for specified operation.
    case bufferTooSmall
    /// Memory allocation failure.
    case memoryFailure
    /// Input size was not aligned properly.
    case alignmentError
    /// Input data did not decode or decrypt properly.
    case decodeError
    /// Function not implemented for the current algorithm.
    case unimplemented
    case overflow
    case rngFailure
    case unspecifiedError
    case callSequenceError
    case keySizeError
    /// Key is not valid.
    case invalidKey
    /// Signature verification failed.
    case notVerified
    case unknown(CryptorStatus)
    
    init(_ status: CryptorStatus) {
        switch status {
        case .paramError:           self = .paramError
        case .bufferTooSmall:       self = .bufferTooSmall
        case .memoryFailure:        self = .memoryFailure
        case .alignmentError:       self = .alignmentError
        case .decodeError:          self = .decodeError
        case .unimplemented:        self = .unimplemented
        case .overflow:             self = .overflow
        case .rngFailure:           self = .rngFailure
        case .unspecifiedError:     self = .unspecifiedError
        case .callSequenceError:    self = .callSequenceError
        case .keySizeError:         self = .keySizeError
        case .invalidKey:           self = .invalidKey
        case .notVerified:          self = .notVerified
        default:                    self = .unknown(status)
        }
    }
}

