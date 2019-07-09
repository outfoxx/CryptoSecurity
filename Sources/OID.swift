//
//  OID.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation


public struct OID {

  /// See: http://oid-info.com/get/{oid}

  public static let commonName = ASN1.oid(of: 2, 5, 4, 3)
  public static let serialNumber = ASN1.oid(of: 2, 5, 4, 5)
  public static let countryName = ASN1.oid(of: 2, 5, 4, 6)
  public static let localityName = ASN1.oid(of: 2, 5, 4, 7)
  public static let stateOrProvinceName = ASN1.oid(of: 2, 5, 4, 8)
  public static let organizationName = ASN1.oid(of: 2, 5, 4, 10)
  public static let organizationUnitName = ASN1.oid(of: 2, 5, 4, 11)
  public static let userId = ASN1.oid(of: 0, 9, 2342, 19200300, 100, 1, 1)

  public static let rsaEncryption = ASN1.oid(of: 1, 2, 840, 113549, 1, 1, 1)
  public static let sha1WithRSAEncryption = ASN1.oid(of: 1, 2, 840, 113549, 1, 1, 5)
  public static let sha256WithRSAEncryption = ASN1.oid(of: 1, 2, 840, 113549, 1, 1, 11)
  public static let sha384WithRSAEncryption = ASN1.oid(of: 1, 2, 840, 113549, 1, 1, 12)
  public static let sha512WithRSAEncryption = ASN1.oid(of: 1, 2, 840, 113549, 1, 1, 13)
  public static let sha224WithRSAEncryption = ASN1.oid(of: 1, 2, 840, 113549, 1, 1, 14)
  public static let extensionRequest = ASN1.oid(of: 1, 2, 840, 113549, 1, 9, 14)
  public static let extensionKeyUsage = ASN1.oid(of: 2, 5, 29, 15)

  public static func OIDFromRDNId(id: String) -> ASN1ObjectIdentifier {
    switch id {
    case "CN":
      return OID.commonName
    case "C":
      return OID.countryName
    case "O":
      return OID.organizationName
    case "OU":
      return OID.organizationUnitName
    case "UID":
      return OID.userId
    case "SN":
      return OID.serialNumber
    default:
      fatalError("Unsupported RDN ID")
    }
  }

  public static func RDNIdFromOID(oid: ASN1ObjectIdentifier) -> String {

    if oid.value == commonName.value {
      return "CN"
    }

    if oid.value == countryName.value {
      return "C"
    }

    if oid.value == localityName.value {
      return "L"
    }

    if oid.value == stateOrProvinceName.value {
      return "ST"
    }

    if oid.value == organizationName.value {
      return "O"
    }

    if oid.value == organizationUnitName.value {
      return "OU"
    }

    if oid.value == userId.value {
      return "UID"
    }

    if oid.value == serialNumber.value {
      return "SN"
    }

    fatalError("Unsupported RDN ID")
  }

}
