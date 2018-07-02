//
//  ASN1.swift
//  CryptoSecurity
//
//  Created by Kevin Wooten on 7/29/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

import Foundation


public protocol ASN1Encoder {

  func encode(boolean value: Bool)
  func encode(integer value: Data)
  func encode(bitString value: Data, bitLength: Int)
  func encode(octetString value: Data)
  func encode(null value: Void)
  func encode(objectIdentifier value: [UInt64])
  func encode(utf8String value: String)
  func encode(printableString value: String)
  func encode(ia5String value: String)
  func encode(sequence value: [ASN1Item])
  func encode(set value: [ASN1Item])
  func encode(utcTime value: Date)
  func encode(tag: UInt8, data: Data)

}

public protocol ASN1Item {

  func encode(encoder: ASN1Encoder)

}


public struct ASN1Boolean: ASN1Item, Equatable {

  public let value: Bool

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(boolean: value)
  }

  public static func == (lhs: ASN1Boolean, rhs: ASN1Boolean) -> Bool {
    return lhs.value == rhs.value
  }

}


public struct ASN1Integer: ASN1Item, Equatable {

  public let value: Data

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(integer: value)
  }

  var intValue: Int64 {

    return value.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> Int64 in

      switch value.count {
      case 0:
        return 0
      case 1:
        let byte0 = ((Int64(ptr[0]) & 0xff) << 00)
        return byte0
      case 2:
        let byte1 = ((Int64(ptr[0]) & 0xff) << 08)
        let byte0 = ((Int64(ptr[1]) & 0xff) << 00)
        return byte1 | byte0
      case 3:
        let byte2 = ((Int64(ptr[0]) & 0xff) << 16)
        let byte1 = ((Int64(ptr[1]) & 0xff) << 08)
        let byte0 = ((Int64(ptr[2]) & 0xff) << 00)
        return byte2 | byte1 | byte0
      case 4:
        let byte3 = ((Int64(ptr[0]) & 0xff) << 24)
        let byte2 = ((Int64(ptr[1]) & 0xff) << 16)
        let byte1 = ((Int64(ptr[2]) & 0xff) << 08)
        let byte0 = ((Int64(ptr[3]) & 0xff) << 00)
        return byte3 | byte2 | byte1 | byte0
      case 5:
        let byte4 = ((Int64(ptr[0]) & 0xff) << 32)
        let byte3 = ((Int64(ptr[1]) & 0xff) << 24)
        let byte2 = ((Int64(ptr[2]) & 0xff) << 16)
        let byte1 = ((Int64(ptr[3]) & 0xff) << 08)
        let byte0 = ((Int64(ptr[4]) & 0xff) << 00)
        return byte4 | byte3 | byte2 | byte1 | byte0
      case 6:
        let byte5 = ((Int64(ptr[0]) & 0xff) << 40)
        let byte4 = ((Int64(ptr[1]) & 0xff) << 32)
        let byte3 = ((Int64(ptr[2]) & 0xff) << 24)
        let byte2 = ((Int64(ptr[3]) & 0xff) << 16)
        let byte1 = ((Int64(ptr[4]) & 0xff) << 08)
        let byte0 = ((Int64(ptr[5]) & 0xff) << 00)
        return byte5 | byte4 | byte3 | byte2 | byte1 | byte0
      case 7:
        let byte6 = ((Int64(ptr[0]) & 0xff) << 48)
        let byte5 = ((Int64(ptr[1]) & 0xff) << 40)
        let byte4 = ((Int64(ptr[2]) & 0xff) << 32)
        let byte3 = ((Int64(ptr[3]) & 0xff) << 24)
        let byte2 = ((Int64(ptr[4]) & 0xff) << 16)
        let byte1 = ((Int64(ptr[5]) & 0xff) << 08)
        let byte0 = ((Int64(ptr[6]) & 0xff) << 00)
        return byte6 | byte5 | byte4 | byte3 | byte2 | byte1 | byte0
      case 8:
        let byte7 = ((Int64(ptr[0]) & 0xff) << 56)
        let byte6 = ((Int64(ptr[1]) & 0xff) << 48)
        let byte5 = ((Int64(ptr[2]) & 0xff) << 40)
        let byte4 = ((Int64(ptr[3]) & 0xff) << 32)
        let byte3 = ((Int64(ptr[4]) & 0xff) << 24)
        let byte2 = ((Int64(ptr[5]) & 0xff) << 16)
        let byte1 = ((Int64(ptr[6]) & 0xff) << 08)
        let byte0 = ((Int64(ptr[7]) & 0xff) << 00)
        return byte7 | byte6 | byte5 | byte4 | byte3 | byte2 | byte1 | byte0
      default:
        fatalError("Invalid intger length")
      }

    }
  }

  public static func == (lhs: ASN1Integer, rhs: ASN1Integer) -> Bool {
    return lhs.value == rhs.value
  }

}


public struct ASN1BitString: ASN1Item, Equatable {

  public let value: Data
  public let length: Int

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(bitString: value, bitLength: length)
  }

  public static func == (lhs: ASN1BitString, rhs: ASN1BitString) -> Bool {
    return lhs.value == rhs.value && lhs.length == rhs.length
  }

  private func big<Container: UnsignedInteger>() -> Container {
    let size = MemoryLayout<Container>.size
    let prefix = Array<UInt8>(repeating: 0, count: size)
    let bytes = Array((prefix + self.value.reversed().map {
      reverse(byte: $0)
    }).suffix(size))
    return bytes.withUnsafeBytes { ptr -> Container in
      ptr.baseAddress!.assumingMemoryBound(to: Container.self).pointee
    }
  }

  public func host() -> UInt8 {
    return big() as UInt8
  }

  public func host() -> UInt16 {
    var value = big() as UInt16
    if NSHostByteOrder() != NS_BigEndian {
      value = value.byteSwapped
    }
    return value
  }

  public func host() -> UInt32 {
    var value = big() as UInt32
    if NSHostByteOrder() != NS_BigEndian {
      value = value.byteSwapped
    }
    return value
  }

  public func host() -> UInt64 {
    var value = big() as UInt64
    if NSHostByteOrder() != NS_BigEndian {
      value = value.byteSwapped
    }
    return value
  }

}


public struct ASN1OctetString: ASN1Item, Equatable {

  public let value: Data

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(octetString: value)
  }

  public static func == (lhs: ASN1OctetString, rhs: ASN1OctetString) -> Bool {
    return lhs.value == rhs.value
  }

}


public struct ASN1Null: ASN1Item, Equatable {

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(null: Void())
  }

  public static func == (lhs: ASN1Null, rhs: ASN1Null) -> Bool {
    return true
  }

}


public struct ASN1ObjectIdentifier: ASN1Item, Equatable {

  public let value: [UInt64]

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(objectIdentifier: value)
  }

  public static func == (lhs: ASN1ObjectIdentifier, rhs: ASN1ObjectIdentifier) -> Bool {
    return lhs.value == rhs.value
  }

}

public protocol ASN1String: ASN1Item {

  var value: String { get }

}

public struct ASN1UTF8String: ASN1Item, ASN1String, Equatable {

  public let value: String

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(utf8String: value)
  }

  public static func == (lhs: ASN1UTF8String, rhs: ASN1UTF8String) -> Bool {
    return lhs.value == rhs.value
  }

}


public struct ASN1PrintableString: ASN1Item, ASN1String, Equatable {

  public let value: String

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(printableString: value)
  }

  public static func == (lhs: ASN1PrintableString, rhs: ASN1PrintableString) -> Bool {
    return lhs.value == rhs.value
  }

}

public struct ASN1IA5String: ASN1Item, ASN1String, Equatable {

  public let value: String

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(ia5String: value)
  }

  public static func == (lhs: ASN1IA5String, rhs: ASN1IA5String) -> Bool {
    return lhs.value == rhs.value
  }

}


public struct ASN1Sequence: ASN1Item, Equatable {

  public let value: Array<ASN1Item>

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(sequence: value)
  }

  public static func == (lhs: ASN1Sequence, rhs: ASN1Sequence) -> Bool {
    for (lhs, rhs) in zip(lhs.value, rhs.value) {
      if lhs != rhs { return false }
    }
    return true
  }

}


public struct ASN1Set: ASN1Item, Equatable {

  public let value: Array<ASN1Item>

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(set: value)
  }

  public static func == (lhs: ASN1Set, rhs: ASN1Set) -> Bool {
    for (lhs, rhs) in zip(lhs.value, rhs.value) {
      if lhs != rhs { return false }
    }
    return true
  }

}


public struct ASN1UTCTime: ASN1Item, Equatable {

  public let timestamp: Date

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(utcTime: timestamp)
  }

  public static func == (lhs: ASN1UTCTime, rhs: ASN1UTCTime) -> Bool {
    return lhs.timestamp == rhs.timestamp
  }

}


public struct ASN1Object: ASN1Item, Equatable {

  public let tag: UInt8
  public let data: Data

  public func encode(encoder: ASN1Encoder) {
    encoder.encode(tag: tag, data: data)
  }

  public static func == (lhs: ASN1Object, rhs: ASN1Object) -> Bool {
    return lhs.tag == rhs.tag && lhs.data == rhs.data
  }

}


func ==(lhs: ASN1Item, rhs: ASN1Item) -> Bool {
  if let lhs = lhs as? ASN1Boolean, let rhs = rhs as? ASN1Boolean {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1Integer, let rhs = rhs as? ASN1Integer {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1BitString, let rhs = rhs as? ASN1BitString {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1OctetString, let rhs = rhs as? ASN1OctetString {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1Null, let rhs = rhs as? ASN1Null {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1ObjectIdentifier, let rhs = rhs as? ASN1ObjectIdentifier {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1UTF8String, let rhs = rhs as? ASN1UTF8String {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1PrintableString, let rhs = rhs as? ASN1PrintableString {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1Sequence, let rhs = rhs as? ASN1Sequence {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1Set, let rhs = rhs as? ASN1Set {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1UTCTime, let rhs = rhs as? ASN1UTCTime {
    return lhs == rhs
  }
  if let lhs = lhs as? ASN1Object, let rhs = rhs as? ASN1Object {
    return lhs == rhs
  }
  return false
}


func !=(lhs: ASN1Item, rhs: ASN1Item) -> Bool {
  return !(lhs == rhs)
}


public struct ASN1 {

  /**
   Item factory methods
   **/

  public static func object(tag: UInt8, data: Data) -> ASN1Object {
    return ASN1Object(tag: tag, data: data)
  }

  public static func null() -> ASN1Null {
    return ASN1Null()
  }

  public static func boolean(of value: Bool) -> ASN1Boolean {
    return ASN1Boolean(value: value)
  }

  public static func integer(of value: UInt64) -> ASN1Integer {
    return integer(of: toData(value.bigEndian))
  }

  public static func integer(of value: Data) -> ASN1Integer {

    return value.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> ASN1Integer in

      var nonZero = ptr
      while nonZero.pointee == 0 && ptr.distance(to: nonZero) < value.count - 1 {
        nonZero = nonZero.successor()
      }

      let off = ptr.distance(to: nonZero)

      return ASN1Integer(value: value.subdata(in: off ..< value.count))
    }
  }

  public static func bitString(of value: BitSet) -> ASN1BitString {

    var lastUsedIdx = 0
    var bytes = [UInt8]()
    for byteIdx in 0 ..< value.bytes.count {

      var byte = UInt8(0)
      var offsetBitTarget = UInt8(0x80)

      for offsetBitIdx in 0 ..< 8 {

        let bitIdx = byteIdx * 8 + offsetBitIdx

        if value[bitIdx] {
          byte = byte | offsetBitTarget
          lastUsedIdx = bitIdx
        }

        offsetBitTarget >>= 1
      }

      bytes.append(byte)
    }

    bytes = Array(bytes.prefix(through: lastUsedIdx / 8))

    return ASN1BitString(value: Data(bytes: &bytes, count: bytes.count), length: lastUsedIdx + 1)
  }

  public static func bitString(of value: Data) -> ASN1BitString {
    return bitString(of: value, bitLength: value.count * 8)
  }

  public static func bitString(of value: Data, bitLength: Int) -> ASN1BitString {
    return ASN1BitString(value: value, length: bitLength)
  }

  public static func octetString(of value: Data) -> ASN1OctetString {
    return ASN1OctetString(value: value)
  }

  public static func octetString<T>(of value: T) -> ASN1OctetString {
    return ASN1OctetString(value: toData(value))
  }

  public static func utf8String(of value: String) -> ASN1UTF8String {
    return ASN1UTF8String(value: value)
  }

  public static func printableString(of value: String) -> ASN1PrintableString {
    return ASN1PrintableString(value: value)
  }

  public static func sequence(of values: ASN1Item...) -> ASN1Sequence {
    return ASN1Sequence(value: values)
  }

  public static func sequence(of values: [ASN1Item]) -> ASN1Sequence {
    return ASN1Sequence(value: values)
  }

  public static func set(of values: ASN1Item...) -> ASN1Set {
    return ASN1Set(value: values)
  }

  public static func set(of values: [ASN1Item]) -> ASN1Set {
    return ASN1Set(value: values)
  }

  public static func utcTime(of value: Date) -> ASN1UTCTime {
    return ASN1UTCTime(timestamp: value)
  }

  public static func oid(of values: UInt64...) -> ASN1ObjectIdentifier {
    return ASN1ObjectIdentifier(value: values)
  }


  public struct Tag {

    public static let BOOLEAN: UInt8             = 0x01
    public static let INTEGER: UInt8             = 0x02
    public static let BITSTRING: UInt8           = 0x03
    public static let OCTETSTRING: UInt8         = 0x04
    public static let NULL: UInt8                = 0x05
    public static let OBJECT_IDENTIFIER: UInt8   = 0x06
    public static let REAL: UInt8                = 0x09
    public static let UTF8STRING: UInt8          = 0x0c
    public static let PRINTABLESTRING: UInt8     = 0x13
    public static let IA5STRING: UInt8           = 0x16
    public static let UTCTIME: UInt8             = 0x17
    public static let SEQUENCE: UInt8            = 0x30
    public static let SET: UInt8                 = 0x31

    public static func privatePrimitive(tag: UInt8) -> UInt8 {
      return tag | 0x80
    }

    public static func privateStructured(tag: UInt8) -> UInt8 {
      return tag | 0xa0
    }

  }


  /**
   DER Encoding
   **/

  public struct DER {

    public static func encode(items: ASN1Item...) -> Data {
      return encode(items: items)
    }

    public static func encode(items: [ASN1Item]) -> Data {
      let encoder = DER.Encoder()
      for item in items {
        item.encode(encoder: encoder)
      }
      return encoder.data
    }

    public static func decode(data: Data) -> ASN1Item {
      return data.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) in
        var ptr = ptr
        return parse(item: &ptr)
      }
    }

    public class Encoder: ASN1Encoder {

      var data = Data(capacity: 512)

      public func append(byte: UInt8) {
        var byte = byte
        withUnsafePointer(to: &byte) {
          data.append(UnsafePointer($0), count: 1)
        }
      }

      public func append(length value: Int) {

        switch value {
        case 0x0000 ..< 0x0080:
          append(byte: UInt8(value & 0x007f))

        case 0x0080 ..< 0x0100:
          append(byte: 0x81)
        append(byte: UInt8(value & 0x00ff))

        case 0x0100 ..< 0x8000:
          append(byte: 0x82)
        append(byte: UInt8((value & 0xff00) >> 8))
        append(byte: UInt8(value & 0xff))

        default:
          fatalError("Invalid DER length")
        }
      }

      public func append(data: Data) {
        self.data.append(data)
      }

      public func append(tag: UInt8, length: Int) {
        append(byte: tag)
        append(length: length)
      }

      public func encode(boolean value: Bool) {
        append(tag: Tag.BOOLEAN, length: 1)
        append(byte: value ? 0xff : 0x00)
      }

      public func encode(integer value: UInt64) {
        encode(integer: toData(value.bigEndian))
      }

      public func encode(integer value: Data) {
        append(tag: ASN1.Tag.INTEGER, length: value.count)
        append(data: value)
      }

      public func encode(bitString value: Data, bitLength: Int) {

        let usedBits = UInt8(bitLength % 8)
        let unusedBits = usedBits == 0 ? 0 : 8 - usedBits

        append(tag: ASN1.Tag.BITSTRING, length: value.count + 1)
        append(byte: unusedBits)
        append(data: value)
      }

      public func encode(octetString value: Data) {
        append(tag: ASN1.Tag.OCTETSTRING, length: value.count)
        append(data: value)
      }

      public func encode(ia5String value: Data) {
        append(tag: ASN1.Tag.OCTETSTRING, length: value.count)
        append(data: value)
      }

      public func encode(null value: Void) {
        append(tag: ASN1.Tag.NULL, length: 0)
      }

      public func encode(objectIdentifier value: [UInt64]) {

        func field(val: UInt64) -> Data {
          var val = val
          var result = Data(count: 9)
          var pos = 8
          result[pos] = UInt8(val & 0x7f)
          while val >= (UInt64(1) << 7) {
            val >>= 7
            pos -= 1
            result[pos] = UInt8((val & 0x7f) | 0x80)
          }
          return Data(result.dropFirst(pos))
        }

        var iter = value.makeIterator()

        let first = iter.next()!
        let second = iter.next()!

        var bytes = field(val: first * 40 + second)

        while let val = iter.next() {
          bytes.append(field(val: val))
        }

        append(tag: ASN1.Tag.OBJECT_IDENTIFIER, length: bytes.count)
        append(data: bytes)
      }

      public func encode(utf8String value: String) {

        let itemData = value.data(using: String.Encoding.utf8)!

        append(tag: ASN1.Tag.UTF8STRING, length: itemData.count)
        append(data: itemData)
      }

      public func encode(printableString value: String) {

        let itemData = value.data(using: String.Encoding.ascii)!

        append(tag: ASN1.Tag.PRINTABLESTRING, length: itemData.count)
        append(data: itemData)
      }

      public func encode(ia5String value: String) {

        let itemData = value.data(using: String.Encoding.ascii)!

        append(tag: ASN1.Tag.IA5STRING, length: itemData.count)
        append(data: itemData)
      }

      public func encode(sequence value: [ASN1Item]) {

        let itemData = ASN1.DER.encode(items: value)

        append(tag: ASN1.Tag.SEQUENCE, length: itemData.count)
        append(data: itemData)
      }

      public func encode(set value: [ASN1Item]) {

        let itemData = ASN1.DER.encode(items: value)

        append(tag: ASN1.Tag.SET, length: itemData.count)
        append(data: itemData)
      }

      let utcDateFormatter: DateFormatter = {
        let fmt = DateFormatter()
        fmt.timeZone = TimeZone(abbreviation: "UTC")
        fmt.dateFormat = "yyMMddHHmmss'Z'"
        return fmt
      }()

      public func encode(utcTime value: Date) {

        let itemData = utcDateFormatter.string(from: value).data(using: String.Encoding.ascii)!

        append(tag: ASN1.Tag.UTCTIME, length: itemData.count)
        append(data: itemData)
      }

      public func encode(tag: UInt8, data: Data) {

        append(tag: tag, length: data.count)
        append(data: data)
      }

    }

    public static func parse(items ptr: inout UnsafePointer<UInt8>, length: Int) -> [ASN1Item] {

      let start = ptr

      var items = [ASN1Item]()
      repeat {

        items.append(parse(item: &ptr))

      } while start.distance(to: ptr) < length

      return items
    }

    public static func parse(item ptr: inout UnsafePointer<UInt8>) -> ASN1Item {

      let tag = ptr[0]
      ptr = ptr.successor()

      let length = parse(length: &ptr)

      switch tag {
      case Tag.BOOLEAN:
        let bool = ASN1Boolean(value: ptr.pointee != 0)
        ptr = ptr.advanced(by: length)
        return bool

      case Tag.INTEGER:
        let int = ASN1Integer(value: Data(bytes: ptr, count: length))
        ptr = ptr.advanced(by: length)
        return int

      case Tag.BITSTRING:
        let data = Data(bytes: ptr.successor(), count: length - 1)
        let bits = ASN1BitString(value: data, length: data.count * 8)
        ptr = ptr.advanced(by: length)
        return bits

      case Tag.OCTETSTRING:
        let octs = ASN1OctetString(value: Data(bytes: ptr, count: length))
        ptr = ptr.advanced(by: length)
        return octs

      case Tag.NULL:
        return ASN1Null()

      case Tag.OBJECT_IDENTIFIER:
        return ASN1ObjectIdentifier(value: parse(oid: &ptr, length: length))

      case Tag.UTF8STRING:
        let str = ASN1UTF8String(value: String(data: Data(bytes: ptr, count: length), encoding: String.Encoding.utf8)!)
        ptr = ptr.advanced(by: length)
        return str

      case Tag.PRINTABLESTRING:
        let str = ASN1PrintableString(value: String(data: Data(bytes: ptr, count: length), encoding: String.Encoding.ascii)!)
        ptr = ptr.advanced(by: length)
        return str

      case Tag.IA5STRING:
        let str = ASN1IA5String(value: String(data: Data(bytes: ptr, count: length), encoding: String.Encoding.ascii)!)
        ptr = ptr.advanced(by: length)
        return str

      case Tag.SEQUENCE:
        return ASN1Sequence(value: parse(items: &ptr, length: length))

      case Tag.SET:
        return ASN1Set(value: parse(items: &ptr, length: length))

      default:
        let obj = ASN1Object(tag: tag, data: Data(bytes: ptr, count: length))
        ptr = ptr.advanced(by: length)
        return obj
      }
    }

    private static func parse(oid ptr: inout UnsafePointer<UInt8>, length: Int) -> [UInt64] {

      let start = ptr

      var ids = [UInt64]()
      repeat {

        var val = parse(base128: &ptr)
        if ids.isEmpty {
          if val < 40 {
            ids.append(0)
          }
          else if val < 80 {
            ids.append(1)
            val = val - 40
          }
          else {
            ids.append(2)
            val = val - 80
          }

        }

        ids.append(val)

      } while start.distance(to: ptr) < length

      return ids
    }

    private static func parse(base128 ptr: inout UnsafePointer<UInt8>) -> UInt64 {

      var val = UInt64(0)

      repeat {
        val = val << 7
        val = val + UInt64(ptr.pointee & 0x7f)
        ptr = ptr.successor()
      }
      while ptr.predecessor().pointee & 0x80 != 0

      return val
    }

    private static func parse(length ptr: inout UnsafePointer<UInt8>) -> Int {

      var length: Int = 0

      let numBytes: Int

      if ptr.pointee > 0x80 {
        numBytes = Int(ptr.pointee) - 0x80
      }
      else {
        length = Int(ptr.pointee)
        numBytes = 0
      }

      ptr = ptr.successor()

      for _ in 0 ..< numBytes {
        length = (length * 0x100) + Int(ptr.pointee)
        ptr = ptr.successor()
      }

      return length
    }

  }

}


func reverse(byte: UInt8) -> UInt8 {
  var b = byte
  b = (b & 0xf0) >> 4 | (b & 0x0f) << 4
  b = (b & 0xcc) >> 2 | (b & 0x33) << 2
  b = (b & 0xaa) >> 1 | (b & 0x55) << 1
  return b
}


func toData<T>(_ value: T) -> Data {
  var value = value
  return withUnsafePointer(to: &value) {
    return Data(bytes: $0, count: MemoryLayout<T>.size)
  }
}
