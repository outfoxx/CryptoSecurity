//
//  ASN1Tests.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import CryptoSecurity
import Foundation
import Security
import XCTest


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
