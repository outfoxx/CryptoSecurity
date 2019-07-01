//
//  SecCertificateTests.swift
//  CryptoSecurity
//
//  Created by Kevin Wooten on 8/10/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

import XCTest
@testable import CryptoSecurity


class SecCertificateTests: XCTestCase {

  func testCertificateProperties() throws {

    let keyPairWithKeychain = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()

    let certFactory = SecCertificateFactory()
    certFactory.subject = [X501NameEntry("CN", "Unit Testing")]
    certFactory.issuer = certFactory.subject
    certFactory.publicKey = try keyPairWithKeychain.encodedPublicKey()
    certFactory.keyUsage = [.keyEncipherment]

    let certData = try certFactory.build(signingKey: keyPairWithKeychain.privateKey, signingAlgorithm: .SHA256)

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    let name = X501.build(from: [X501NameEntry("CN", "Unit Testing")])
    XCTAssertTrue(name == cert.issuerName!)
    XCTAssertTrue(name == cert.subjectName!)
  }

  func testInvalidCertificate() throws {

    let keyPairWithKeychain = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()

    let certFactory = SecCertificateFactory()
    certFactory.subject = [X501NameEntry("CN", "Unit Testing")]
    certFactory.issuer = certFactory.subject
    certFactory.publicKey = try keyPairWithKeychain.encodedPublicKey()
    certFactory.keyUsage = [.keyEncipherment]

    let certData = try certFactory.build(signingKey: keyPairWithKeychain.privateKey, signingAlgorithm: .SHA256)

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    do {
      _ = try cert.publicKeyValidated(trustedCertificates: [])
      XCTFail("Should have thrown an error")
    }
    catch let error {
      print(error)
    }
  }
}
