import CommonCryptoSPI

public enum CCCryptorStatus: RawRepresentable {
    case success
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
    case unknown(CommonCrypto.CCCryptorStatus)
    
    public typealias RawValue = CommonCrypto.CCCryptorStatus
    
    public init?(rawValue: RawValue) {
        switch rawValue {
        case CommonCrypto.CCCryptorStatus(kCCSuccess):           self = .success
        case CommonCrypto.CCCryptorStatus(kCCParamError):        self = .paramError
        case CommonCrypto.CCCryptorStatus(kCCBufferTooSmall):    self = .bufferTooSmall
        case CommonCrypto.CCCryptorStatus(kCCMemoryFailure):     self = .memoryFailure
        case CommonCrypto.CCCryptorStatus(kCCAlignmentError):    self = .alignmentError
        case CommonCrypto.CCCryptorStatus(kCCDecodeError):       self = .decodeError
        case CommonCrypto.CCCryptorStatus(kCCUnimplemented):     self = .unimplemented
        case CommonCrypto.CCCryptorStatus(kCCOverflow):          self = .overflow
        case CommonCrypto.CCCryptorStatus(kCCRNGFailure):        self = .rngFailure
        case CommonCrypto.CCCryptorStatus(kCCUnspecifiedError):  self = .unspecifiedError
        case CommonCrypto.CCCryptorStatus(kCCCallSequenceError): self = .callSequenceError
        case CommonCrypto.CCCryptorStatus(kCCKeySizeError):      self = .keySizeError
        case CommonCrypto.CCCryptorStatus(kCCInvalidKey):        self = .invalidKey
        case CommonCrypto.CCCryptorStatus(kCCNotVerified):       self = .notVerified
        default:                                    self = .unknown(rawValue)
        }
    }
    
    internal init(_ status: RawValue) {
        switch status {
        case CommonCrypto.CCCryptorStatus(kCCParamError):        self = .paramError
        case CommonCrypto.CCCryptorStatus(kCCBufferTooSmall):    self = .bufferTooSmall
        case CommonCrypto.CCCryptorStatus(kCCMemoryFailure):     self = .memoryFailure
        case CommonCrypto.CCCryptorStatus(kCCAlignmentError):    self = .alignmentError
        case CommonCrypto.CCCryptorStatus(kCCDecodeError):       self = .decodeError
        case CommonCrypto.CCCryptorStatus(kCCUnimplemented):     self = .unimplemented
        case CommonCrypto.CCCryptorStatus(kCCOverflow):          self = .overflow
        case CommonCrypto.CCCryptorStatus(kCCRNGFailure):        self = .rngFailure
        case CommonCrypto.CCCryptorStatus(kCCUnspecifiedError):  self = .unspecifiedError
        case CommonCrypto.CCCryptorStatus(kCCCallSequenceError): self = .callSequenceError
        case CommonCrypto.CCCryptorStatus(kCCKeySizeError):      self = .keySizeError
        case CommonCrypto.CCCryptorStatus(kCCInvalidKey):        self = .invalidKey
        case CommonCrypto.CCCryptorStatus(kCCNotVerified):       self = .notVerified
        default:                                    self = .unknown(status)
        }
    }
    
    public var rawValue: CommonCrypto.CCCryptorStatus {
        switch self {
        case .success:              return CommonCrypto.CCCryptorStatus(kCCSuccess)
        case .paramError:           return CommonCrypto.CCCryptorStatus(kCCParamError)
        case .bufferTooSmall:       return CommonCrypto.CCCryptorStatus(kCCBufferTooSmall)
        case .memoryFailure: 		return CommonCrypto.CCCryptorStatus(kCCMemoryFailure)
        case .alignmentError: 	    return CommonCrypto.CCCryptorStatus(kCCAlignmentError)
        case .decodeError: 	        return CommonCrypto.CCCryptorStatus(kCCDecodeError)
        case .unimplemented: 	    return CommonCrypto.CCCryptorStatus(kCCUnimplemented)
        case .overflow:             return CommonCrypto.CCCryptorStatus(kCCOverflow)
        case .rngFailure:       	return CommonCrypto.CCCryptorStatus(kCCRNGFailure)
        case .unspecifiedError:     return CommonCrypto.CCCryptorStatus(kCCUnspecifiedError)
        case .callSequenceError:    return CommonCrypto.CCCryptorStatus(kCCCallSequenceError)
        case .keySizeError:         return CommonCrypto.CCCryptorStatus(kCCKeySizeError)
        case .invalidKey:           return CommonCrypto.CCCryptorStatus(kCCInvalidKey)
        case .notVerified:          return CommonCrypto.CCCryptorStatus(kCCNotVerified)
        case .unknown(let status):  return status
        }
    }
}

/// Return values from CommonCryptor operations interpreted into errors.
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
    case unknown(CCCryptorStatus)
    
    init(_ status: CCCryptorStatus) {
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

