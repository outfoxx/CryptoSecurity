//
//  DigestTests.swift
//  CryptoSecurity
//
//  Created by Kevin Wooten on 7/28/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

import XCTest
@testable import CryptoSecurity


class DigestTests: XCTestCase {


  let data = try! Random.generateBytes(ofSize: 3619)


  func exec(_ digester: Digester) throws -> Data {

    var data = self.data

    while data.count > 0 {

      let amt = min(data.count, 33)

      try digester.update(data: data.subdata(in: 0 ..< amt))

      data = data.subdata(in: amt ..< data.count)
    }

    return try digester.final()
  }

  func testDigestBlocksSHA1() throws {

    let blocksDigest = try exec(Digester(algorithm: .SHA1))

    XCTAssertEqual(blocksDigest, try Digester.digest(algorithm: .SHA1, data: data))
  }

  func testDigestBlocksSHA224() throws {

    let blocksDigest = try exec(Digester(algorithm: .SHA224))

    XCTAssertEqual(blocksDigest, try Digester.digest(algorithm: .SHA224, data: data))
  }

  func testDigestBlocksSHA256() throws {

    let blocksDigest = try exec(Digester(algorithm: .SHA256))

    XCTAssertEqual(blocksDigest, try Digester.digest(algorithm: .SHA256, data: data))
  }

  func testDigestBlocksSHA384() throws {

    let blocksDigest = try exec(Digester(algorithm: .SHA384))

    XCTAssertEqual(blocksDigest, try Digester.digest(algorithm: .SHA384, data: data))
  }

  func testDigestBlocksSHA512() throws {

    let blocksDigest = try exec(Digester(algorithm: .SHA512))

    XCTAssertEqual(blocksDigest, try Digester.digest(algorithm: .SHA512, data: data))
  }

}
