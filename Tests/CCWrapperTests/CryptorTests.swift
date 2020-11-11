import XCTest
import CCWrapper

final class SomeTest: XCTestCase {
    func testRSA() throws {
        var privateKey: CCRSACryptorRef?
        var publicKey: CCRSACryptorRef?
        
        defer {
            CCRSACryptorRelease(privateKey)
            CCRSACryptorRelease(publicKey)
        }
        
        try CCRSACryptorGeneratePair(keySize: 2048, e: 65537, publicKey: &publicKey, privateKey: &privateKey)
        
        print(privateKey, publicKey)
        
        let message = Data("Hello World".utf8)
        
        let signature = try CCRSACryptorSign(privateKey: privateKey, padding: .pss, data: message, digest: .sha256, saltSize: 0)
        try CCRSACryptorVerify(publicKey: publicKey, padding: .pss, data: message, signature: signature, digest: .sha256, saltSize: 0)
        
        print(signature as NSData)
        
        let ct = try CCRSACryptorEncrypt(publicKey: publicKey, padding: .oaep, plainText: message, tag: nil, digest: .sha256)
        let pt = try CCRSACryptorDecrypt(privateKey: privateKey, padding: .oaep, cipherText: ct, tag: nil, digest: .sha256)
        
        print(String(data: pt, encoding: .utf8)!)
        
        print(try CCRSAGetKeyComponents(key: privateKey))
        print(try CCRSAGetKeyComponents(key: publicKey))
        
        print(try CCRSACryptorExport(key: privateKey) as NSData)
        print(try CCRSACryptorExport(key: publicKey) as NSData)
    }
    
    @available(iOS 13.0, macOS 10.15, *)
    func testKDF() throws {
        print(try CCKeyDerivationPBKDF(algorithm: .pbkdf2, password: "Password", salt: Data(), prf: .prfHmacSHA256, rounds: 10000, derivedSize: 32) as NSData)
        
        var reference: CCKDFParametersRef?
        
        try CCKDFParametersCreatePbkdf2(&reference, rounds: 10000, salt: Data())
        print(try CCDeriveKey(reference, digest: .sha256, key: Data("Password".utf8), derivedSize: 32) as NSData)
    }
    
    func testCmac() throws {
        let message = Data([0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a])
        let key = Data([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        
        let reference = CCAESCmacCreate(key: key)
        CCAESCmacUpdate(reference, data: message)
        let mac = CCAESCmacFinalize(reference)
        CCAESCmacDestroy(reference)
        print(mac as NSData)
    }
    
    func testHmac() throws {
        let key = Data(repeating: 0x0b, count: 20)
        let message = Data([0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65])
        let reference = CCHmacCreate(algorithm: .sha256, key: key)
        CCHmacUpdate(reference, data: message)
        let mac = CCHmacFinalize(reference)
        CCHmacDestroy(reference)
        print(CCHmacClone(reference))
        print(mac as NSData)
    }
    
    func testDigest() throws {
        let message = Data("abc".utf8)
        
        let reference: CCDigestRef = CCDigestCreate(algorithm: .sha256)
        try CCDigestInit(algorithm: .sha256, reference: reference)
        try CCDigestUpdate(reference, data: message)
        var hash = try CCDigestFinalize(reference)
        CCDigestReset(reference)
        try CCDigestUpdate(reference, data: message + message)
        hash = try CCDigestFinalize(reference)
        CCDigestDestroy(reference)
        print(hash as NSData)
    }
    
    func testSomething() throws {
        let msg = Data("Hello World".utf8)
        let key = Data(repeating: 0x1f, count: 16)
        let iv = Data(repeating: 0xae, count: 13)
        let aad = Data("Some authentication data".utf8)
        
        var ref: CCCryptorRef?
        
        try CCCryptorCreateWithMode(op: .encrypt, mode: .ccm, alg: .aes, padding: .none, iv: nil, key: key, tweak: nil, reference: &ref)
        try CCCryptorAddParameter(ref, parameter: .iv, data: iv)
        try CCCryptorAddParameter(ref, parameter: .macSize, size: 16)
        try CCCryptorAddParameter(ref, parameter: .dataSize, size: msg.count)
        try CCCryptorAddParameter(ref, parameter: .authenticationData, data: aad)
        
        let ct = try CCCryptorUpdate(ref, data: msg)
        try CCCryptorFinalize(ref)
        let tag = try CCCryptorGetParameter(ref, parameter: .authenticationTag, size: 16)
        print(tag as NSData)
        try CCCryptorRelease(ref)
        
        try CCCryptorCreateWithMode(op: .decrypt, mode: .ccm, alg: .aes, padding: .none, iv: nil, key: key, tweak: nil, reference: &ref)
        try CCCryptorAddParameter(ref, parameter: .iv, data: iv)
        try CCCryptorAddParameter(ref, parameter: .macSize, size: 16)
        try CCCryptorAddParameter(ref, parameter: .dataSize, size: msg.count)
        try CCCryptorAddParameter(ref, parameter: .authenticationData, data: aad)
        
        let pt = try CCCryptorUpdate(ref, data: ct)
        try CCCryptorFinalize(ref)
        let ver = try CCCryptorGetParameter(ref, parameter: .authenticationTag, size: 16)
        print(ver as NSData)
        print(String(data: pt, encoding: .utf8)!)
    }
    
}
