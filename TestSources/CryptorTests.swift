//
//  CryptorTests.swift
//  CryptoSecurity
//
//  Created by Kevin Wooten on 7/28/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

import XCTest
@testable import CryptoSecurity


class CryptorTests: XCTestCase {


  let plainText = try! Random.generateBytes(ofSize: 368)


  func exec(_ cryptor: Cryptor, source data: Data) throws -> Data {

    let buffer = NSMutableData(length: 33 + cryptor.blockSize)!
    var out = Data()

    let totalBytes = data.count
    var totalBytesRead = 0

    while totalBytesRead < totalBytes {

      let bytesToRead = min(33, totalBytes - totalBytesRead)

      var processedBytes = 0
      try cryptor.update(data: data,
                         atOffset: totalBytesRead,
                         length: bytesToRead,
                         intoData: buffer,
                         returningLength: &processedBytes)

      out.append(buffer.subdata(with: NSMakeRange(0, processedBytes)))
      totalBytesRead += bytesToRead
    }

    var processedBytes = 0
    try cryptor.final(intoData: buffer, returningLength: &processedBytes)

    out.append(buffer.subdata(with: NSMakeRange(0, processedBytes)))

    return out
  }

  func testCryptorAES_128() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .AES))
    let key = try Random.generateBytes(ofSize: 16)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .AES, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .AES, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .AES, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .AES, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorAES_128_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .AES))
    var key = try Random.generateBytes(ofSize: 16)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .AES, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .AES, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorAES_192() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .AES))
    let key = try Random.generateBytes(ofSize: 24)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .AES, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .AES, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .AES, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .AES, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorAES_192_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .AES))
    var key = try Random.generateBytes(ofSize: 24)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .AES, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .AES, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorAES_256() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .AES))
    let key = try Random.generateBytes(ofSize: 32)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .AES, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .AES, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .AES, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .AES, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorAES_256_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .AES))
    var key = try Random.generateBytes(ofSize: 32)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .AES, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .AES, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorDES() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .DES))
    let key = try Random.generateBytes(ofSize: 8)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .DES, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .DES, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .DES, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .DES, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorDES_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .DES))
    var key = try Random.generateBytes(ofSize: 8)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .DES, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .DES, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptor3DES() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .tripleDES))
    let key = try Random.generateBytes(ofSize: 24)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .tripleDES, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .tripleDES, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .tripleDES, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .tripleDES, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptor3DES_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .tripleDES))
    var key = try Random.generateBytes(ofSize: 24)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .tripleDES, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .tripleDES, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorCAST_40() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .CAST))
    let key = try Random.generateBytes(ofSize: 5)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .CAST, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .CAST, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .CAST, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .CAST, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorCAST_40_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .CAST))
    var key = try Random.generateBytes(ofSize: 5)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .CAST, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .CAST, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorCAST_88() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .CAST))
    let key = try Random.generateBytes(ofSize: 11)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .CAST, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .CAST, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .CAST, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .CAST, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorCAST_88_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .CAST))
    var key = try Random.generateBytes(ofSize: 11)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .CAST, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .CAST, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorCAST_128() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .CAST))
    let key = try Random.generateBytes(ofSize: 16)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .CAST, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .CAST, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .CAST, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .CAST, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorCAST_128_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .CAST))
    var key = try Random.generateBytes(ofSize: 16)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .CAST, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .CAST, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorRC4_8() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC4))
    let key = try Random.generateBytes(ofSize: 1)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC4, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .RC4, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC4, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .RC4, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorRC4_8_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC4))
    var key = try Random.generateBytes(ofSize: 1)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC4, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.withUnsafeMutableBytes { ptr in
      ptr.pointee += 1
    }

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC4, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorRC4_256() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC4))
    let key = try Random.generateBytes(ofSize: 32)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC4, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .RC4, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC4, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .RC4, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorRC4_256_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC4))
    var key = try Random.generateBytes(ofSize: 32)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC4, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC4, options: [.pkcs7Padding], key: key, iv: iv))
  }


  func testCryptorRC4_512() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC4))
    let key = try Random.generateBytes(ofSize: 64)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC4, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .RC4, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC4, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .RC4, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorRC4_512_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC4))
    var key = try Random.generateBytes(ofSize: 64)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC4, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC4, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorRC2_8() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC2))
    let key = try Random.generateBytes(ofSize: 1)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC2, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .RC2, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC2, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .RC2, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorRC2_8_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC2))
    var key = try Random.generateBytes(ofSize: 3)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC2, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.withUnsafeMutableBytes { ptr in
      ptr.pointee += 1
    }

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC2, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorRC2_64() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC2))
    let key = try Random.generateBytes(ofSize: 8)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC2, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .RC2, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC2, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .RC2, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorRC2_64_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC2))
    var key = try Random.generateBytes(ofSize: 8)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC2, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC2, options: [.pkcs7Padding], key: key, iv: iv))
  }


  func testCryptorRC2_128() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC2))
    let key = try Random.generateBytes(ofSize: 16)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC2, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(operation: .decrypt, algorithm: .RC2, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC2, options: [.pkcs7Padding], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .RC2, options: [.pkcs7Padding], key: key, iv: iv))
  }

  func testCryptorRC2_128_Fail() throws {

    let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .RC2))
    var key = try Random.generateBytes(ofSize: 16)

    let encryptor = try Cryptor(operation: .encrypt, algorithm: .RC2, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText)

    key.resetBytes(in: 0 ..< 3)

    XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .RC2, options: [.pkcs7Padding], key: key, iv: iv))
  }

  #if BLOWFISH

    func testCryptorBlowfish_8() throws {

      let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .blowfish))
      let key = try Random.generateBytes(ofSize: 1)

      let encryptor = try Cryptor(operation: .encrypt, algorithm: .blowfish, options: [.pkcs7Padding], key: key, iv: iv)
      let decryptor = try Cryptor(operation: .decrypt, algorithm: .blowfish, options: [.pkcs7Padding], key: key, iv: iv)

      let cipherText = try exec(encryptor, source: plainText)

      XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .blowfish, options: [.pkcs7Padding], key: key, iv: iv))
      XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
      XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .blowfish, options: [.pkcs7Padding], key: key, iv: iv))
    }

    func testCryptorBlowfish_8_Fail() throws {

      let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .blowfish))
      var key = try Random.generateBytes(ofSize: 1)

      let encryptor = try Cryptor(operation: .encrypt, algorithm: .blowfish, options: [.pkcs7Padding], key: key, iv: iv)

      let cipherText = try exec(encryptor, source: plainText)

      key.resetBytes(in: 0 ..< 3)

      XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .blowfish, options: [.pkcs7Padding], key: key, iv: iv))
    }

    func testCryptorBlowfish_32() throws {

      let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .blowfish))
      let key = try Random.generateBytes(ofSize: 4)

      let encryptor = try Cryptor(operation: .encrypt, algorithm: .blowfish, options: [.pkcs7Padding], key: key, iv: iv)
      let decryptor = try Cryptor(operation: .decrypt, algorithm: .blowfish, options: [.pkcs7Padding], key: key, iv: iv)

      let cipherText = try exec(encryptor, source: plainText)

      XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .blowfish, options: [.pkcs7Padding], key: key, iv: iv))
      XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
      XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .blowfish, options: [.pkcs7Padding], key: key, iv: iv))
    }

    func testCryptorBlowfish_32_Fail() throws {

      let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .blowfish))
      var key = try Random.generateBytes(ofSize: 4)

      let encryptor = try Cryptor(operation: .encrypt, algorithm: .blowfish, options: [.pkcs7Padding], key: key, iv: iv)

      let cipherText = try exec(encryptor, source: plainText)

      key.resetBytes(in: 0 ..< 3)

      XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .blowfish, options: [.pkcs7Padding], key: key, iv: iv))
    }


    func testCryptorBlowfish_56() throws {

      let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .blowfish))
      let key = try Random.generateBytes(ofSize: 7)

      let encryptor = try Cryptor(operation: .encrypt, algorithm: .blowfish, options: [.pkcs7Padding], key: key, iv: iv)
      let decryptor = try Cryptor(operation: .decrypt, algorithm: .blowfish, options: [.pkcs7Padding], key: key, iv: iv)

      let cipherText = try exec(encryptor, source: plainText)

      XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .blowfish, options: [.pkcs7Padding], key: key, iv: iv))
      XCTAssertEqual(plainText, try exec(decryptor, source: cipherText))
      XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: .blowfish, options: [.pkcs7Padding], key: key, iv: iv))
    }

    func testCryptorBlowfish_56_Fail() throws {

      let iv = try Random.generateBytes(ofSize: Cryptor.blockSize(algorithm: .blowfish))
      var key = try Random.generateBytes(ofSize: 7)

      let encryptor = try Cryptor(operation: .encrypt, algorithm: .blowfish, options: [.pkcs7Padding], key: key, iv: iv)

      let cipherText = try exec(encryptor, source: plainText)

      key.resetBytes(in: 0 ..< 3)

      XCTAssertNotEqual(cipherText, try Cryptor.encrypt(data: plainText, using: .blowfish, options: [.pkcs7Padding], key: key, iv: iv))
    }

  #endif

}
