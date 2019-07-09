//
//  SecKeyPair.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import Security


public enum SecKeyPairError: Error {
  case generateFailed
  case noMatchingKey
  case itemAddFailed
  case itemDeleteFailed

  public static func build(error: SecKeyPairError, message: String, status: OSStatus) -> NSError {
    let error = error as NSError
    return NSError(domain: error.domain, code: error.code, userInfo: [
      NSLocalizedDescriptionKey: message,
      "status": Int(status) as NSNumber,
    ])
  }
}


public enum SecKeyType: Int {

  case RSA
  case EC

  var systemValue: CFString {
    switch self {
    case .RSA:
      return kSecAttrKeyTypeRSA
    case .EC:
      return kSecAttrKeyTypeEC
    }
  }
}


private let keyExportKeySize = 32


public class SecKeyPairFactory {

  public let type: SecKeyType
  public let keySize: Int

  public init(type: SecKeyType, keySize: Int) {
    self.type = type
    self.keySize = keySize
  }

  public func generate() throws -> SecKeyPair {

    let attrs: [String: Any] = [
      kSecAttrKeyType as String: type.systemValue,
      kSecAttrKeySizeInBits as String: keySize,
    ]

    var publicKey: SecKey?, privateKey: SecKey?
    let status = SecKeyGeneratePair(attrs as CFDictionary, &publicKey, &privateKey)
    if status != errSecSuccess {
      throw SecKeyPairError.build(error: .generateFailed, message: "Generate failed", status: status)
    }

    #if os(iOS) || os(watchOS) || os(tvOS)

      try publicKey!.save(class: kSecAttrKeyClassPublic)
      try privateKey!.save(class: kSecAttrKeyClassPrivate)

    #endif

    return SecKeyPair(privateKey: privateKey!, publicKey: publicKey!)
  }

}


public class SecKeyPair: Codable {

  public let privateKey: SecKey
  public let publicKey: SecKey

  public init(privateKey: SecKey, publicKey: SecKey) {
    self.privateKey = privateKey
    self.publicKey = publicKey
  }

  public convenience init(privateKeyRef: Data, publicKeyRef: Data) throws {

    let privateKey = try SecKey.load(persistentReference: privateKeyRef)
    let publicKey = try SecKey.load(persistentReference: publicKeyRef)

    self.init(privateKey: privateKey, publicKey: publicKey)
  }

  public func save() throws {

    try privateKey.save(class: kSecAttrKeyClassPrivate)
    try publicKey.save(class: kSecAttrKeyClassPublic)
  }

  public func delete() throws {

    try publicKey.delete()
    try privateKey.delete()
  }

  public func persistentReferences() throws -> (Data, Data) {
    return (try privateKey.persistentReference(), try publicKey.persistentReference())
  }

  public func encodedPublicKey() throws -> Data {
    return try publicKey.encode(class: kSecAttrKeyClassPublic) as Data
  }

  public func encodedPrivateKey() throws -> Data {
    return try privateKey.encode(class: kSecAttrKeyClassPrivate) as Data
  }

  public func export(password: String) throws -> Data {

    let passwordData = password.data(using: String.Encoding.utf8)!

    let salt = try Random.generateBytes(ofSize: keyExportKeySize)
    let rounds = PBKDF2.calibrate(passwordLength: passwordData.count,
                                  saltLength: salt.count,
                                  keySize: keyExportKeySize,
                                  algorithm: .SHA512,
                                  taking: 300)
    let key = try PBKDF2.deriveKey(ofSize: keyExportKeySize,
                                   withPassword: passwordData,
                                   andSalt: salt,
                                   usingRounds: rounds,
                                   ofAlgorithm: .SHA512)

    let keyMaterial = try encodedPrivateKey()
    let encryptedKeyData = try Cryptor.encrypt(data: keyMaterial, using: .AES, options: .pkcs7Padding, key: key, iv: salt)

    let keyType: SecKeyType

    let attrs = try privateKey.attributes(class: kSecAttrKeyClassPrivate)

    // iOS 10 SecKeyCopyAttributes returns string values, SecItemCopyMatching returns number values
    let type =
      (attrs[kSecAttrKeyType as String] as? NSNumber)?.stringValue ??
      attrs[kSecAttrKeyType as String] as! String

    if type == kSecAttrKeyTypeRSA as String {
      keyType = .RSA
    }
    else if type == kSecAttrKeyTypeEC as String {
      keyType = .EC
    }
    else {
      fatalError("Unsupported key type")
    }

    return ASN1.DER.encode(items:
      ASN1.sequence(of:
        ASN1.integer(of: UInt64(keyType.rawValue)),
                    ASN1.integer(of: UInt64(keyExportKeySize)),
                    ASN1.octetString(of: salt),
                    ASN1.integer(of: UInt64(rounds)),
                    ASN1.octetString(of: encryptedKeyData)))
  }

  public static func importKeys(fromData data: Data, withPassword password: String) throws -> SecKeyPair {

    let items = ASN1.DER.decode(data: data) as! ASN1Sequence

    let keyTypeVal = (items.value[0] as! ASN1Integer).intValue
    let keySize = (items.value[1] as! ASN1Integer).intValue
    let salt = (items.value[2] as! ASN1OctetString).value
    let rounds = (items.value[3] as! ASN1Integer).intValue
    let encryptedKeyData = (items.value[4] as! ASN1OctetString).value

    let keyType = SecKeyType(rawValue: Int(keyTypeVal))!

    let key = try PBKDF2.deriveKey(ofSize: Int(keySize),
                                   withPassword: password.data(using: String.Encoding.utf8)!,
                                   andSalt: salt,
                                   usingRounds: Int(rounds),
                                   ofAlgorithm: .SHA512)

    let keyMaterial = try Cryptor.decrypt(data: encryptedKeyData, using: .AES, options: .pkcs7Padding, key: key, iv: salt)

    let privateKey = try SecKey.decode(fromData: keyMaterial,
                                       type: keyType.systemValue,
                                       class: kSecAttrKeyClassPrivate)

    // Assemble PEM-DER public key from private key material
    let keySequence = ASN1.DER.decode(data: keyMaterial) as! ASN1Sequence
    let pubKeySequence = ASN1.sequence(of: keySequence.value[1], keySequence.value[2])
    let pubKeyMaterial = ASN1.DER.encode(items: pubKeySequence)

    let publicKey = try SecKey.decode(fromData: pubKeyMaterial,
                                      type: keyType.systemValue,
                                      class: kSecAttrKeyClassPublic)

    return SecKeyPair(privateKey: privateKey, publicKey: publicKey)
  }

  public func matchesCertificate(certificate: SecCertificate, trustedCertificates: [SecCertificate]) throws -> Bool {

    let keyData = try certificate.publicKeyValidated(trustedCertificates: trustedCertificates).encode(class: kSecAttrKeyClassPublic)

    return try encodedPublicKey() == keyData
  }

  enum CodingKeys: CodingKey {
    case `public`
    case `private`
  }

  public required init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: Self.CodingKeys.self)
    privateKey = try SecKey.load(persistentReference: container.decode(Data.self, forKey: .private))
    publicKey = try SecKey.load(persistentReference: container.decode(Data.self, forKey: .public))
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: Self.CodingKeys.self)
    try container.encode(privateKey.persistentReference(), forKey: .private)
    try container.encode(publicKey.persistentReference(), forKey: .public)
  }

}
