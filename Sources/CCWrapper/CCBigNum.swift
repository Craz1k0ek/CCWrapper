import CommonCryptoSPI
import Foundation

public typealias CCBigNumRef = CommonCryptoSPI.CCBigNumRef

/// Creates a BigNum
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A newly allocated BigNum.
public func CCCreateBigNum() throws -> CCBigNumRef {
    var status = CCStatus(kCCSuccess)
    let reference = CommonCryptoSPI.CCCreateBigNum(&status)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return reference!
}

/// Zeroes (clears) a BigNum.
/// - Parameter bn: The BigNum to clear.
/// - Throws: A `CryptoError` describing the issue.
public func CCBigNumClear(_ bn: CCBigNumRef?) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumClear(bn))
    guard status == .success else { throw CryptoError(status) }
}

/// Frees and clears a BigNum.
/// - Parameter bn: The BigNum to free.
public func CCBigNumFree(_ bn: CCBigNumRef?) {
    CommonCryptoSPI.CCBigNumFree(bn)
}

/// Copies a BigNum.
/// - Parameter bn: The BigNum to copy.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A newly allocated BigNum.
public func CCBigNumCopy(_ bn: CCBigNumRef) throws -> CCBigNumRef {
    var status = CCStatus(kCCSuccess)
    let copy = CommonCryptoSPI.CCBigNumCopy(&status, bn)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return copy!
}

/// Returns the number of significant bits in a BigNum.
/// - Parameter bn: The BigNum.
/// - Returns: The number of bits.
public func CCBigNumBitCount(_ bn: CCBigNumRef) -> UInt32 {
    CommonCryptoSPI.CCBigNumBitCount(bn)
}

/// Returns the number of zero bits before the least significant 1 bit.
/// - Parameter bn: The BigNum.
/// - Returns: The number of bits.
public func CCBigNumZeroLSBCount(_ bn: CCBigNumRef) -> UInt32 {
    CommonCryptoSPI.CCBigNumZeroLSBCount(bn)
}

/// Returns the number of bytes when converted to binary data.
/// - Parameter bn: The BigNum.
/// - Returns: The number of bytes.
public func CCBigNumByteCount(_ bn: CCBigNumRef) -> UInt32 {
    CommonCryptoSPI.CCBigNumByteCount(bn)
}

/// Creates a BigNum from binary data.
/// - Parameter data: The data in big endian format.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A newly allocated BigNum.
public func CCBigNumFromData(_ data: Data) throws -> CCBigNumRef {
    var status = CCStatus(kCCSuccess)
    let reference = data.withUnsafeBytes {
        CommonCryptoSPI.CCBigNumFromData(&status, $0.baseAddress, $0.count)
    }
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return reference!
}

/// Dumps a BigNum into binary data.
/// - Parameter bn: The BigNum.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The binary data.
public func CCBigNumToData(_ bn: CCBigNumRef) throws -> Data {
    var status = CCStatus(kCCSuccess)
    var data = [UInt8](repeating: 0, count: Int(CCBigNumByteCount(bn)))
    CommonCryptoSPI.CCBigNumToData(&status, bn, &data)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return Data(data)
}

/// Creates a BigNum from a hexadecimal string.
/// - Parameter hexString: A null terminated hexadecimal string.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A newly allocated BigNum.
public func CCBigNumFromHexString(_ hexString: String) throws -> CCBigNumRef {
    var status = CCStatus(kCCSuccess)
    let reference = CommonCryptoSPI.CCBigNumFromHexString(&status, hexString)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return reference!
}

/// Dumps a BigNum into hexadecimal string.
/// - Parameter bn: The BigNum.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A hexadecimal string representation of the BigNum.
public func CCBigNumToHexString(_ bn: CCBigNumRef) throws -> String {
    var status = CCStatus(kCCSuccess)
    let hexData = CommonCryptoSPI.CCBigNumToHexString(&status, bn)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return String(cString: hexData!)
}

/// Creates a BigNum from a decimal string.
/// - Parameter decimalString: A null terminated decimal string.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A newly allocated BigNum.
public func CCBigNumFromDecimalString(_ decimalString: String) throws -> CCBigNumRef {
    var status = CCStatus(kCCSuccess)
    let reference = CommonCryptoSPI.CCBigNumFromDecimalString(&status, decimalString)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return reference!
}

/// Dumps a BigNum into a decimal string.
/// - Parameter bn: The BigNum.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A decimal string representation of the BigNum.
public func CCBigNumToDecimalString(_ bn: CCBigNumRef) throws -> String {
    var status = CCStatus(kCCSuccess)
    let decimalData = CommonCryptoSPI.CCBigNumToDecimalString(&status, bn)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return String(cString: decimalData!)
}

/// Compares two BigNums.
/// - Parameters:
///   - bn1: A BigNum.
///   - bn2: A BigNum.
/// - Returns: Returns -1 if bn1 is less than bn2.
/// Returns 0 if bn1 and bn2 are equal.
/// Returns 1 if bn1 is greater than bn2.
public func CCBigNumCompare(_ bn1: CCBigNumRef, _ bn2: CCBigNumRef) -> Int {
    Int(CommonCryptoSPI.CCBigNumCompare(bn1, bn2))
}

/// Compares a BigNum and a 32 bit integer.
/// - Parameters:
///   - bn: A BigNum.
///   - num: An integer.
/// - Returns: Returns -1 if bn1 is less than bn2.
/// Returns 0 if bn1 and bn2 are equal.
/// Returns 1 if bn1 is greater than bn2.
public func CCBigNumCompareI(_ bn: CCBigNumRef, _ num: UInt32) -> Int {
    Int(CommonCryptoSPI.CCBigNumCompareI(bn, num))
}

/// Sets a BigNum to negative.
/// - Parameter bn: A BigNum.
/// - Throws: A `CryptoError` describing the issue.
public func CCBigNumSetNegative(_ bn: CCBigNumRef) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumSetNegative(bn))
    guard status == .success else { throw CryptoError(status) }
}

/// Sets a BigNum value using an unsigned integer.
/// - Parameters:
///   - bn: The BigNum.
///   - num: The value to set.
/// - Throws: A `CryptoError` describing the issue.
public func CCBigNumSetI(_ bn: CCBigNumRef, num: UInt64) throws {
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumSetI(bn, num))
    guard status == .success else { throw CryptoError(status) }
}

/// Get an unsigned integer representation of the BigNum.
/// This assumes the BigNum can actually fit within the unsigned integer representation.
/// - Parameter bn: The BigNum.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The unsigned integer value.
public func CCBigNumGetI(_ bn: CCBigNumRef) throws -> UInt32 {
    var status = CCStatus(kCCSuccess)
    let num = CommonCryptoSPI.CCBigNumGetI(&status, bn)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return num
}

/// Adds two BigNums.
/// - Parameters:
///   - a: The first BigNum to add.
///   - b: The second BigNum to add.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The sum of the two numbers.
public func CCBigNumAdd(_ a: CCBigNumRef, _ b: CCBigNumRef) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumAdd(result, a, b))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Adds a BigNum and an unsigned integer.
/// - Parameters:
///   - bn: The first BigNum to add.
///   - num: The unsigned integer to add.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The sum of the two numbers.
public func CCBigNumAddI(_ bn: CCBigNumRef, _ num: UInt32) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumAddI(result, bn, num))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Subtracts a BigNum from a BigNum.
/// - Parameters:
///   - a: The BigNum.
///   - b: The BigNum to subtract.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The result.
public func CCBigNumSub(_ a: CCBigNumRef, _ b: CCBigNumRef) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumSub(result, a, b))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Subtracts an unsigned integer from a BigNum.
/// - Parameters:
///   - bn: The BigNum.
///   - num: The unsigned integer to subtract.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The result.
public func CCBigNumSubI(_ bn: CCBigNumRef, _ num: UInt32) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumSubI(result, bn, num))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Multiplies two BigNums.
/// - Parameters:
///   - a: The first BigNum to multiply.
///   - b: The second BigNum to multiply.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The result.
public func CCBigNumMul(_ a: CCBigNumRef, _ b: CCBigNumRef) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumMul(result, a, b))
    guard status == .success else { throw CryptoError(status) }
    return result
}
/// Multiplies a BigNum and an unsigned integer.
/// - Parameters:
///   - bn: The first BigNum to multiply.
///   - num: The unsigned integer to multiply.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The result.
public func CCBigNumMulI(_ bn: CCBigNumRef, _ num: UInt32) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumMulI(result, bn, num))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Divides a BigNum by another BigNum.
/// - Parameters:
///   - a: The BigNum to divide.
///   - b: The BigNum used to divide a.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A tuple containing the quotient and remainder.
public func CCBigNumDiv(_ a: CCBigNumRef, _ b: CCBigNumRef) throws -> (quotient: CCBigNumRef, remainder: CCBigNumRef) {
    let quotient = try CCCreateBigNum()
    let remainder = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumDiv(quotient, remainder, a, b))
    guard status == .success else { throw CryptoError(status) }
    return (quotient, remainder)
}

/// Find the remainder of a BigNum for a given modulus.
/// - Parameters:
///   - dividend: The BigNum to divide.
///   - modulus: The BigNum used to divide a and produce the mod value.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The result.
public func CCBigNumMod(_ dividend: CCBigNumRef, _ modulus: CCBigNumRef) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumMod(result, dividend, modulus))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Find the remainder of a BigNum for a given modulus (unsigned integer version).
/// - Parameters:
///   - dividend: The BigNum to divide.
///   - modulus: The integer used to divide a and produce the mod value.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The result.
public func CCBigNumModI(_ dividend: CCBigNumRef, _ modulus: UInt32) throws -> UInt32 {
    var result: UInt32 = 0
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumModI(&result, dividend, modulus))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Perform Modular Multiplication.
/// - Parameters:
///   - a: A BigNum.
///   - b: A BigNum.
///   - mod: The modulus.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The result.
public func CCBigNumMulMod(_ a: CCBigNumRef, _ b: CCBigNumRef, _ mod: CCBigNumRef) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumMulMod(result, a, b, mod))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Perform Modular Exponentiation.
/// - Parameters:
///   - bn: The base integer.
///   - power: The power integer.
///   - mod: The modulus.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The result.
public func CCBigNumModExp(_ bn: CCBigNumRef, power: CCBigNumRef, mod: CCBigNumRef) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumModExp(result, bn, power, mod))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Shift a BigNum left.
/// - Parameters:
///   - bn: The BigNum.
///   - digits: How many bit places to shift left.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The result.
public func CCBigNumLeftShift(_ bn: CCBigNumRef, digits: UInt32) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumLeftShift(result, bn, digits))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Shift a BigNum right.
/// - Parameters:
///   - bn: The BigNum.
///   - digits: How many bit places to shift right.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: The result.
public func CCBigNumRightShift(_ bn: CCBigNumRef, digits: UInt32) throws -> CCBigNumRef {
    let result = try CCCreateBigNum()
    let status = CCCryptorStatus(CommonCryptoSPI.CCBigNumRightShift(result, bn, digits))
    guard status == .success else { throw CryptoError(status) }
    return result
}

/// Creates a BigNum with a random value.
/// - Parameter bits: The bits in the BigNum.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: A newly allocated BigNum.
public func CCBigNumCreateRandom(bits: Int32) throws -> CCBigNumRef {
    var status = CCStatus(kCCSuccess)
    let random = CommonCryptoSPI.CCBigNumCreateRandom(&status, 0, bits, 0)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return random!
}

/// Determines if a BigNum is prime.
/// - Parameter bn: A BigNum.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: True or false.
public func CCBigNumIsPrime(_ bn: CCBigNumRef) throws -> Bool {
    var status = CCStatus(kCCSuccess)
    let isPrime = CommonCryptoSPI.CCBigNumIsPrime(&status, bn)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return isPrime
}

/// Determines if a BigNum is negative.
/// - Parameter bn: A BigNum.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: True or false.
public func CCBigNumIsZero(_ bn: CCBigNumRef) throws -> Bool {
    var status = CCStatus(kCCSuccess)
    let isZero = CommonCryptoSPI.CCBigNumIsZero(&status, bn)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return isZero
}

/// Determines if a BigNum is negative.
/// - Parameter bn: A BigNum.
/// - Throws: A `CryptoError` describing the issue.
/// - Returns: True or false.
public func CCBigNumIsNegative(_ bn: CCBigNumRef) throws -> Bool {
    var status = CCStatus(kCCSuccess)
    let isNegative = CommonCryptoSPI.CCBigNumIsNegative(&status, bn)
    guard CCCryptorStatus(status) == .success else { throw CryptoError(CCCryptorStatus(status)) }
    return isNegative
}
