//
//  HmacTests.swift
//  CryptoSecurity
//
//  Created by Kevin Wooten on 7/28/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

import XCTest
@testable import CryptoSecurity


class HmacTests: XCTestCase {

  let key = "secret".data(using: .utf8)!
  let data = try! Random.generateBytes(ofSize: 3619)

  func exec(_ hmac: Hmac) -> Data {

    var data = self.data

    while data.count > 0 {

      let amt = min(data.count, 33)

      hmac.update(data: data.subdata(in: 0 ..< amt))

      data = data.subdata(in: amt ..< data.count)
    }

    return hmac.final()
  }

  func testHmacBlocksSHA1() throws {

    let blocksMac = exec(Hmac(algorithm: .SHA1, key: key))

    XCTAssertEqual(blocksMac, Hmac.hmac(algorithm: .SHA1, key: key, data: data))
  }

  func testDigestBlocksSHA224() throws {

    let blocksMac = exec(Hmac(algorithm: .SHA224, key: key))

    XCTAssertEqual(blocksMac, Hmac.hmac(algorithm: .SHA224, key: key, data: data))
  }

  func testDigestBlocksSHA256() throws {

    let blocksMac = exec(Hmac(algorithm: .SHA256, key: key))

    XCTAssertEqual(blocksMac, Hmac.hmac(algorithm: .SHA256, key: key, data: data))
  }

  func testDigestBlocksSHA384() throws {

    let blocksMac = exec(Hmac(algorithm: .SHA384, key: key))

    XCTAssertEqual(blocksMac, Hmac.hmac(algorithm: .SHA384, key: key, data: data))
  }

  func testDigestBlocksSHA512() throws {

    let blocksMac = exec(Hmac(algorithm: .SHA512, key: key))

    XCTAssertEqual(blocksMac, Hmac.hmac(algorithm: .SHA512, key: key, data: data))
  }

}
