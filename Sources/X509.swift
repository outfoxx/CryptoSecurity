//
//  X509.swift
//  CryptoSecurity
//
//  Created by Kevin Wooten on 8/10/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

import Foundation


public struct X509 {

  public static func certificateInfo(serialNumber: Data,
                                     issuer: X501Name,
                                     issuerUniqueId: BitSet?,
                                     subject: X501Name,
                                     subjectUniqueId: BitSet?,
                                     notBefore: Date,
                                     notAfter: Date,
                                     publicKey: ASN1Sequence,
                                     keyUsage: UInt32?) -> ASN1Sequence {

    var items = [
      ASN1.object(tag: ASN1.Tag.privateStructured(tag: 0), data: ASN1.DER.encode(items: ASN1.integer(of: 2))),
      ASN1.integer(of: serialNumber),
      ASN1.sequence(of: OID.sha256WithRSAEncryption, ASN1.null()),
      X501.encode(name: issuer),
      ASN1.sequence(of:
        ASN1.utcTime(of: notBefore),
                    ASN1.utcTime(of: notAfter)),
      X501.encode(name: subject),
      subjectPublicKeyInfo(encryptionOID: OID.rsaEncryption, publicKey: publicKey)
    ]

    if let issuerUniqueId = issuerUniqueId {
      items.append(ASN1.object(tag: ASN1.Tag.privateStructured(tag: 1),
                               data: ASN1.DER.encode(items:
                                 ASN1.bitString(of: issuerUniqueId))))
    }

    if let subjectUniqueId = subjectUniqueId {
      items.append(ASN1.object(tag: ASN1.Tag.privateStructured(tag: 2),
                               data: ASN1.DER.encode(items:
                                 ASN1.bitString(of: subjectUniqueId))))
    }

    items.append(ASN1.object(tag: ASN1.Tag.privateStructured(tag: 3),
                             data: ASN1.DER.encode(items:
                               extensions(forKeyUsage: keyUsage))))

    return ASN1.sequence(of: items)
  }

  public static func subjectPublicKeyInfo(encryptionOID oid: ASN1ObjectIdentifier, publicKey: ASN1Sequence) -> ASN1Item {
    return ASN1.sequence(of:
      ASN1.sequence(of: oid, ASN1.null()),
                         ASN1.bitString(of: ASN1.DER.encode(items: publicKey)))
  }

  public static func extensions(forKeyUsage keyUsage: UInt32?) -> ASN1Item {

    var extensions = [ASN1Item]()

    if let keyUsage = keyUsage {
      extensions.append(keyUsageExtension(keyUsage: keyUsage))
    }

    return ASN1.sequence(of: extensions)
  }

  public static func keyUsageExtension(keyUsage: UInt32) -> ASN1Sequence {

    return ASN1.sequence(of:
      OID.extensionKeyUsage,
                         ASN1.boolean(of: true),
                         ASN1.octetString(of:
        ASN1.DER.encode(items:
          ASN1.bitString(of: BitSet(value: keyUsage)))))
  }

}
