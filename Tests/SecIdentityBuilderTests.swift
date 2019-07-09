//
//  SecIdentityBuilderTests.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import CryptoSecurity
import XCTest


class SecIdentityBuilderTests: XCTestCase {

  func testBuildAndFetch() throws {

    let subject = [
      X501NameEntry("CN", "Test Guy"),
      X501NameEntry("O", "Some Corp"),
      X501NameEntry("C", "USA"),
    ]

    let builder = try SecIdentityBuilder.generate(subject: subject,
                                                  keySize: 2048,
                                                  usage: .nonRepudiation)

    // Build a self-signed certificate for importing
    let certFactory = SecCertificateFactory()
    certFactory.subject = subject
    certFactory.issuer = certFactory.subject
    certFactory.publicKey = try builder.keyPair.encodedPublicKey()
    certFactory.keyUsage = [.nonRepudiation]

    let certData = try certFactory.build(signingKey: builder.keyPair.privateKey, signingAlgorithm: .SHA256)
    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    // Save the certificate to finish out the identity
    try builder.save(withCertificate: cert)

    // Ensure all went well
    let ident = try SecIdentity.load(certificate: cert)

    XCTAssertNotNil(ident)
    XCTAssertNotNil(try ident.certificate())
    XCTAssertNotNil(try ident.privateKey())
  }

}
