//
//  SecCertificateRequestFactoryTests.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import CryptoSecurity
import XCTest


class SecCertificateRequestFactoryTests: XCTestCase {

  func testBuild() throws {

    let keyPair = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()

    let factory = SecCertificateRequestFactory()
    factory.subject = [X501NameEntry("CN", "Outfox Signing")]
    factory.publicKey = try keyPair.encodedPublicKey()
    factory.keyUsage = [.keyEncipherment]

    let csrData = try factory.build(signingKey: keyPair.privateKey, signingAlgorithm: .SHA256)
    //    let csrDataEncoded = csrData.base64EncodedString()

    let certFactory = SecCertificateFactory(certificateSigningRequest: csrData)
    certFactory.issuer = factory.subject

    let certData = try certFactory.build(signingKey: keyPair.privateKey, signingAlgorithm: .SHA256)
    let certDataEncoded = certData.base64EncodedString()

    print(certDataEncoded)
  }

}
