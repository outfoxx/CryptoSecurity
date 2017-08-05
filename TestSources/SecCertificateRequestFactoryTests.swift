//
//  SecCertificateRequestFactoryTests.swift
//  CryptoSecurity
//
//  Created by Kevin Wooten on 8/9/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

import XCTest
@testable import CryptoSecurity


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
