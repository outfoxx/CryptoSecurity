//
//  ASN1Tests.swift
//  CryptoSecurity
//
// Created by Kevin Wooten on 2/28/17.
// Copyright (c) 2017 Outfox, Inc. All rights reserved.
//

import Foundation
import Security
import XCTest
@testable import CryptoSecurity


class ASN1Tests: XCTestCase {

  func testOIDCodec() {

    let oids = [
      OID.commonName,
      OID.countryName,
      OID.organizationName,
      OID.organizationUnitName,
      OID.userId,
    ]

    let newOids = ASN1.DER.decode(data: ASN1.DER.encode(items: ASN1Sequence(value: oids))) as! ASN1Sequence

    for newOid in newOids.value as! [ASN1ObjectIdentifier] {
      _ = OID.RDNIdFromOID(oid: newOid)
    }
  }

  func testBitStringEncodeDecode() {

    for idx in 0 ..< 64 {
      let srcValue = UInt64(1) << UInt64(idx)
      let bits = ASN1.DER.encode(items: ASN1.bitString(of: BitSet(value: srcValue)))
      let bitString = ASN1.DER.decode(data: bits) as! ASN1BitString
      let dstValue = bitString.host() as UInt64
      XCTAssertEqual(srcValue, dstValue)
    }

  }

}
