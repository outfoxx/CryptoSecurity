//
//  X501.swift
//  CryptoSecurity
//
//  Created by Kevin Wooten on 8/9/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

import Foundation


public typealias X501Name = [(ASN1ObjectIdentifier, ASN1String)]

public func ==(lhs: X501Name, rhs: X501Name) -> Bool {
  for (lhs, rhs) in zip(lhs, rhs) {
    if lhs.0 != rhs.0 || lhs.1.value != rhs.1.value {
      return false
    }
  }
  return true
}

public func !=(lhs: X501Name, rhs: X501Name) -> Bool {
  return !(lhs == rhs)
}


public struct X501 {

  public static func encode(name: X501Name) -> ASN1Sequence {
    return rdnSequence(of: name)
  }

  public static func decode(sequence: ASN1Sequence) -> X501Name {

    var items = [(ASN1ObjectIdentifier, ASN1String)]()

    for rdn in sequence.value {
      let set = rdn as! ASN1Set
      let seq = set.value[0] as! ASN1Sequence
      let oid = seq.value[0] as! ASN1ObjectIdentifier
      guard let val = seq.value[1] as? ASN1String else {
        fatalError("Unsupported value type for X501 name pair")
      }
      let entry = (oid, val)
      items.append(entry)
    }

    return items
  }

  public static func rdnSequence(of rdns: [(ASN1ObjectIdentifier, ASN1String)]) -> ASN1Sequence {

    var items = [ASN1Item]()

    for rdn in rdns {
      items.append(relativeDistinguishedName(of: rdn))
    }

    return ASN1.sequence(of: items)
  }

  public static func relativeDistinguishedName(of rdn: (oid: ASN1ObjectIdentifier, value: ASN1String)) -> ASN1Item {
    return ASN1.set(of:
      ASN1.sequence(of:
        rdn.oid,
                    rdn.value))
  }

  public static func parse(name: X501Name) -> [X501NameEntry] {

    var entries = [X501NameEntry]()

    for item in name {
      entries.append(X501NameEntry(OID.RDNIdFromOID(oid: item.0), item.1.value))
    }

    return entries
  }

  public static func build(from entries: [X501NameEntry]) -> X501Name {

    var items = X501Name()

    for entry in entries {
      items.append(entry.toRDN())
    }

    return items
  }

}


public struct X501NameEntry {

  public let name: String
  public let value: String

  public init(_ name: String, _ value: String) {
    self.name = name
    self.value = value
  }

  fileprivate func toRDN() -> (ASN1ObjectIdentifier, ASN1String) {
    return (OID.OIDFromRDNId(id: name), ASN1UTF8String(value: value))
  }

}
