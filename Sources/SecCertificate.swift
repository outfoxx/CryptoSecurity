//
//  SecCertificate.swift
//  CryptoSecurity
//
//  Created by Kevin Wooten on 7/6/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

import Foundation
import Security


public enum SecCertificateError: Int, Error {
  case loadFailed               = 0
  case saveFailed               = 1
  case queryFailed              = 2
  case trustCreationFailed      = 3
  case trustValidationFailed    = 4
  case trustValidationError     = 5
  case publicKeyRetrievalFailed = 6
  case parsingFailed            = 7
}


public extension SecCertificate {

  public static func from(data: Data) throws -> SecCertificate {
    guard let cert = SecCertificateCreateWithData(nil, data as CFData) else {
      throw SecCertificateError.parsingFailed
    }
    return cert
  }

  private var certificateInfo: ASN1Sequence {
    return (ASN1.DER.decode(data: derEncoded) as! ASN1Sequence).value[0] as! ASN1Sequence
  }

  public var issuerName: X501Name? {
    let issuerSeq: ASN1Sequence
    if #available(iOS 10.3, OSX 10.12.4, tvOS 10.3, watchOS 3.3, *) {
      guard
        let seqData = SecCertificateCopyNormalizedIssuerSequence(self),
        let seq = ASN1.DER.decode(data: seqData as Data) as? ASN1Sequence
      else {
        fatalError("invalid certificate encoding")
      }
      issuerSeq = seq
    }
    else {
      issuerSeq = certificateInfo.value[3] as! ASN1Sequence
    }
    return X501.decode(sequence: issuerSeq)
  }

  public var subjectName: X501Name? {
    let subjectSeq: ASN1Sequence
    if #available(iOS 10.3, OSX 10.12.4, tvOS 10.3, watchOS 3.3, *) {
      guard
        let seqData = SecCertificateCopyNormalizedSubjectSequence(self),
        let seq = ASN1.DER.decode(data: seqData as Data) as? ASN1Sequence
      else {
        fatalError("invalid certificate encoding")
      }
      subjectSeq = seq
    }
    else {
      subjectSeq = certificateInfo.value[5] as! ASN1Sequence
    }
    return X501.decode(sequence: subjectSeq)
  }

  public func publicKeyValidated(trustedCertificates: [SecCertificate]) throws -> SecKey {

    let policy = SecPolicyCreateBasicX509()

    var trustResult: SecTrust?
    var status = SecTrustCreateWithCertificates(self, policy, &trustResult)
    guard let trust = trustResult, status == errSecSuccess else {
      throw SecCertificateError.trustCreationFailed
    }

    status = SecTrustSetAnchorCertificates(trust, trustedCertificates as CFArray)
    if status != errSecSuccess {
      throw SecCertificateError.trustCreationFailed
    }

    var result = SecTrustResultType.deny

    status = SecTrustEvaluate(trust, &result)
    if status != errSecSuccess {
      throw SecCertificateError.trustValidationError
    }

    if
      result != SecTrustResultType.proceed &&
      result != SecTrustResultType.unspecified {
      throw SecCertificateError.trustValidationFailed
    }

    guard let key = SecTrustCopyPublicKey(trust) else {
      throw SecCertificateError.publicKeyRetrievalFailed
    }

    return key
  }

  public var derEncoded: Data {
    return SecCertificateCopyData(self) as Data
  }

  public func attributes() throws -> [String: Any] {

    #if os(iOS) || os(watchOS) || os(tvOS)

      let query = [
        kSecReturnAttributes as String: kCFBooleanTrue,
        kSecValueRef as String: self
      ] as CFDictionary

      var data: CFTypeRef?

      let status = SecItemCopyMatching(query as CFDictionary, &data)
      if status != errSecSuccess {
        throw SecCertificateError.queryFailed
      }

    #elseif os(macOS)

      let query: [String: Any] = [
        kSecReturnAttributes as String: kCFBooleanTrue,
        kSecUseItemList as String: [self] as CFArray
      ]

      var data: AnyObject?

      let status = SecItemCopyMatching(query as CFDictionary, &data)
      if status != errSecSuccess {
        throw SecCertificateError.queryFailed
      }

    #endif

    return data as! [String: Any]
  }

  public func save() throws {

    let query = [
      kSecClass as String: kSecClassCertificate,
      kSecValueRef as String: self
    ] as CFDictionary

    var data: CFTypeRef?

    let status = SecItemAdd(query, &data)

    if status != errSecSuccess {
      throw SecCertificateError.saveFailed
    }
  }

}


#if os(iOS) || os(watchOS) || os(tvOS)
  // Add key usage options matching Apple provided macOS version
  //
  public struct SecKeyUsage: OptionSet {

    public let rawValue: UInt32

    public init(rawValue: UInt32) {
      self.rawValue = rawValue
    }

    // See: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
    public static let unspecified        = SecKeyUsage(rawValue: 0)
    public static let digitalSignature   = SecKeyUsage(rawValue: 1 << 0)
    public static let nonRepudiation     = SecKeyUsage(rawValue: 1 << 1)
    public static let keyEncipherment    = SecKeyUsage(rawValue: 1 << 2)
    public static let dataEncipherment   = SecKeyUsage(rawValue: 1 << 3)
    public static let keyAgreement       = SecKeyUsage(rawValue: 1 << 4)
    public static let keyCertSign        = SecKeyUsage(rawValue: 1 << 5)
    public static let crlSign            = SecKeyUsage(rawValue: 1 << 6)
    public static let encipherOnly       = SecKeyUsage(rawValue: 1 << 7)
    public static let decipherOnly       = SecKeyUsage(rawValue: 1 << 8)
    public static let critical           = SecKeyUsage(rawValue: 1 << 31)
    public static let all                = SecKeyUsage(rawValue: 0x7fff_ffff)
  }
#endif


public class SecCertificateRequestFactory {

  public var subject: [X501NameEntry]?
  public var publicKey: Data?
  public var keyUsage: SecKeyUsage?

  public init(subject: [X501NameEntry]? = nil, publicKey: Data? = nil, keyUsage: SecKeyUsage? = nil) {
    self.subject = subject
    self.publicKey = publicKey
    self.keyUsage = keyUsage
  }

  public func build(signingKey: SecKey, signingAlgorithm: DigestAlgorithm) throws -> Data {

    let subject = X501.build(from: self.subject!)
    let publicKey = ASN1.DER.decode(data: self.publicKey!) as! ASN1Sequence

    let certificateRequestInfo = PKCS10.certificationRequestInfo(subject: subject,
                                                                 publicKey: publicKey,
                                                                 keyUsage: keyUsage?.rawValue ?? 0)

    let certificateRequestInfoDERData = ASN1.DER.encode(items: certificateRequestInfo)

    let signature = try signingKey.sign(data: certificateRequestInfoDERData, digestAlgorithm: signingAlgorithm)

    let signingOid: ASN1ObjectIdentifier
    switch signingAlgorithm {
    case .SHA1:
      signingOid = OID.sha1WithRSAEncryption
    case .SHA224:
      signingOid = OID.sha224WithRSAEncryption
    case .SHA256:
      signingOid = OID.sha256WithRSAEncryption
    case .SHA384:
      signingOid = OID.sha384WithRSAEncryption
    case .SHA512:
      signingOid = OID.sha512WithRSAEncryption
    }

    return ASN1.DER.encode(items:
      ASN1.sequence(of:
        certificateRequestInfo,
                    ASN1.sequence(of: signingOid, ASN1.null()),
                    ASN1.bitString(of: signature)))
  }

}




public class SecCertificateFactory {

  public var serialNumber = try! Random.generateBytes(ofSize: 32)
  public var subject: [X501NameEntry]!
  public var subjectUniqueId: UInt64?
  public var issuer: [X501NameEntry]!
  public var issuerUniqueId: UInt64?
  public var notBefore = Date()
  public var notAfter = Date().addingTimeInterval(86400 * 365)
  public var publicKey: Data!
  public var keyUsage: SecKeyUsage?

  public init() {
  }

  public init(certificateSigningRequest csrData: Data) {

    let certificateSigningRequest = ASN1.DER.decode(data: csrData) as! ASN1Sequence
    let csrInfo = (certificateSigningRequest.value[0] as! ASN1Sequence)

    subject = X501.parse(name: X501.decode(sequence: csrInfo.value[1] as! ASN1Sequence))
    publicKey = ((csrInfo.value[2] as! ASN1Sequence).value[1] as! ASN1BitString).value
    let keyUsageValue = (ASN1.DER.decode(data: (((((ASN1.DER.decode(data: (csrInfo.value[3] as! ASN1Object).data) as! ASN1Sequence).value[1] as! ASN1Set).value[0] as! ASN1Sequence).value[0] as! ASN1Sequence).value[2] as! ASN1OctetString).value) as! ASN1BitString)
      .host() as UInt32
    keyUsage = SecKeyUsage(rawValue: keyUsageValue)
  }

  public func build(signingKey: SecKey, signingAlgorithm: DigestAlgorithm) throws -> Data {

    let subjectName = X501.build(from: subject!)
    let subjectUniqueId: BitSet? = self.subjectUniqueId != nil ? BitSet(value: self.subjectUniqueId!) : nil

    let issuerName = X501.build(from: issuer!)
    let issuerUniqueId: BitSet? = self.issuerUniqueId != nil ? BitSet(value: self.issuerUniqueId!) : nil

    let publicKey = ASN1.DER.decode(data: self.publicKey!) as! ASN1Sequence

    let certificateInfo = X509.certificateInfo(serialNumber: serialNumber,
                                               issuer: issuerName,
                                               issuerUniqueId: issuerUniqueId,
                                               subject: subjectName,
                                               subjectUniqueId: subjectUniqueId,
                                               notBefore: notBefore,
                                               notAfter: notAfter,
                                               publicKey: publicKey,
                                               keyUsage: keyUsage?.rawValue)

    let certificateInfoDERData = ASN1.DER.encode(items: certificateInfo)

    let signature = try signingKey.sign(data: certificateInfoDERData, digestAlgorithm: signingAlgorithm)

    let signingOid: ASN1ObjectIdentifier
    switch signingAlgorithm {
    case .SHA1:
      signingOid = OID.sha1WithRSAEncryption
    case .SHA224:
      signingOid = OID.sha224WithRSAEncryption
    case .SHA256:
      signingOid = OID.sha256WithRSAEncryption
    case .SHA384:
      signingOid = OID.sha384WithRSAEncryption
    case .SHA512:
      signingOid = OID.sha512WithRSAEncryption
    }

    return ASN1.DER.encode(items:
      ASN1.sequence(of: [
        certificateInfo,
        ASN1.sequence(of: [signingOid, ASN1.null()]),
        ASN1.bitString(of: signature)
      ])
    )
  }

}
