//
//  PKCS10.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation


public struct PKCS10 {

  public static func certificationRequestInfo(subject: X501Name, publicKey: ASN1Sequence, keyUsage: UInt32) -> ASN1Item {

    return ASN1.sequence(of: [
      ASN1.integer(of: 0), // Version
      X501.encode(name: subject), // Subject
      X509.subjectPublicKeyInfo(encryptionOID: OID.rsaEncryption, publicKey: publicKey), // Public Key
      attributes(keyUsage: keyUsage), // Attributes
    ])
  }

  public static func attributes(keyUsage: UInt32?) -> ASN1Item {

    let extensions = extensionRequest(keyUsage: keyUsage)

    return ASN1.object(tag: ASN1.Tag.privateStructured(tag: 0),
                       data: ASN1.DER.encode(items: extensions))
  }

  public static func extensionRequest(keyUsage: UInt32?) -> ASN1Item {

    var extensions = [ASN1Item]()

    if let keyUsage = keyUsage {
      extensions.append(ASN1.sequence(of: X509.keyUsageExtension(keyUsage: keyUsage)))
    }

    return ASN1.sequence(of: [
      OID.extensionRequest,
      ASN1.set(of: extensions),
    ])
  }

}
