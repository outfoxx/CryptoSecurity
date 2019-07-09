//
//  SecKeyTests.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import CryptoSecurity
import XCTest


class SecKeyTests: XCTestCase {

  var publicKey: SecKey!
  var privateKey: SecKey!

  override func setUp() {
    super.setUp()

    let pair = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()

    publicKey = pair.publicKey
    privateKey = pair.privateKey
  }


  func testEncryptDecrypt() throws {

    let plainText = try Random.generateBytes(ofSize: 171)

    let cipherText = try publicKey.encrypt(plainText: plainText, padding: .OAEP)

    let plainText2 = try privateKey.decrypt(cipherText: cipherText, padding: .OAEP)

    XCTAssertEqual(plainText, plainText2)
  }

  func testFailedEncryptError() {

    do {
      _ = try publicKey.encrypt(plainText: try Random.generateBytes(ofSize: 312), padding: .OAEP)
      XCTFail("Encrypt should have thrown an error")
    }
    catch _ {}
  }

  func testFailedDecryptError() {

    do {
      _ = try privateKey.decrypt(cipherText: try Random.generateBytes(ofSize: 312), padding: .OAEP)
      XCTFail("Decrypt should have thrown an error")
    }
    catch _ {}
  }

  func testSignVerifySHA1() throws {

    let data = try Random.generateBytes(ofSize: 217)

    let signature = try privateKey.sign(data: data, digestAlgorithm: .SHA1)

    XCTAssertTrue(try publicKey.verify(data: data, againstSignature: signature, digestAlgorithm: .SHA1))
  }

  func testSignVerifySHA224() throws {

    let data = try Random.generateBytes(ofSize: 217)

    let signature = try privateKey.sign(data: data, digestAlgorithm: .SHA224)

    XCTAssertTrue(try publicKey.verify(data: data, againstSignature: signature, digestAlgorithm: .SHA224))
  }

  func testSignVerifySHA256() throws {

    let data = try Random.generateBytes(ofSize: 217)

    let signature = try privateKey.sign(data: data, digestAlgorithm: .SHA256)

    XCTAssertTrue(try publicKey.verify(data: data, againstSignature: signature, digestAlgorithm: .SHA256))
  }

  func testSignVerifySHA384() throws {

    let data = try Random.generateBytes(ofSize: 217)

    let signature = try privateKey.sign(data: data, digestAlgorithm: .SHA384)

    XCTAssertTrue(try publicKey.verify(data: data, againstSignature: signature, digestAlgorithm: .SHA384))
  }

  func testSignVerifySHA512() throws {

    let data = try Random.generateBytes(ofSize: 217)

    let signature = try privateKey.sign(data: data, digestAlgorithm: .SHA512)

    XCTAssertTrue(try publicKey.verify(data: data, againstSignature: signature, digestAlgorithm: .SHA512))
  }

  func testSignVerifyFailed() throws {

    let invalidSignature = try privateKey.sign(data: try Random.generateBytes(ofSize: 217), digestAlgorithm: .SHA1)

    XCTAssertFalse(try publicKey.verify(data: try Random.generateBytes(ofSize: 217), againstSignature: invalidSignature, digestAlgorithm: .SHA1))
  }

  func testEncodeDecode() throws {

    let plainText = try Random.generateBytes(ofSize: 143)

    let cipherText1 = try publicKey.encrypt(plainText: plainText, padding: .OAEP)

    let encodedPublicKey = try publicKey.encode(class: kSecAttrKeyClassPublic)
    let decodedPublicKey = try SecKey.decode(fromData: encodedPublicKey, type: kSecAttrKeyTypeRSA, class: kSecAttrKeyClassPublic)

    let cipherText2 = try decodedPublicKey.encrypt(plainText: plainText, padding: .OAEP)

    let encodedPrivateKey = try privateKey.encode(class: kSecAttrKeyClassPrivate)
    let decodedPrivateKey = try SecKey.decode(fromData: encodedPrivateKey, type: kSecAttrKeyTypeRSA, class: kSecAttrKeyClassPrivate)

    XCTAssertEqual(plainText, try decodedPrivateKey.decrypt(cipherText: cipherText1, padding: .OAEP))
    XCTAssertEqual(plainText, try decodedPrivateKey.decrypt(cipherText: cipherText2, padding: .OAEP))
  }

}
