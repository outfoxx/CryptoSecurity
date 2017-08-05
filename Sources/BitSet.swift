//
//  BitSet.swift
//  CryptoSecurity
//
//  Created by Kevin Wooten on 8/8/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

import Foundation


/*
 A fixed-size sequence of n bits. Bits have indices 0 to n-1.
 */
public struct BitSet {
  /* How many bits this object can hold. */
  private(set) public var size: Int

  /*
   We store the bits in a list of unsigned 8-bit integers.
   The first entry, `bytes[0]`, is the least significant byte.
   */
  private let N = 8
  public typealias Byte = UInt8
  fileprivate(set) public var bytes: [UInt8]

  private let allOnes = ~Byte()

  /* Creates a bit set that can hold `size` bits. All bits are initially 0. */
  public init(size: Int) {
    precondition(size > 0)
    self.size = size

    // Round up the count to the next multiple of 8.
    let n = (size + (N - 1)) / N
    bytes = Array(repeating: 0, count: n)
  }

  public init(value: UInt8) {
    self.init(size: 8)

    var value = value
    for idx in 0 ..< 8 {
      self[idx] = value & 0x1 != 0
      value = value >> 1
    }

  }

  public init(value: UInt16) {
    self.init(size: 16)

    var value = value
    for idx in 0 ..< 16 {
      self[idx] = value & 0x1 != 0
      value = value >> 1
    }

  }

  public init(value: UInt32) {
    self.init(size: 32)

    var value = value
    for idx in 0 ..< 32 {
      self[idx] = value & 0x1 != 0
      value = value >> 1
    }

  }

  public init(value: UInt64) {
    self.init(size: 64)

    var value = value
    for idx in 0 ..< 64 {
      self[idx] = value & 0x1 != 0
      value = value >> 1
    }

  }

  /* Converts a bit index into an array index and a mask inside the byte. */
  private func indexOf(_ i: Int) -> (Int, Byte) {
    precondition(i >= 0)
    precondition(i < size)
    let o = i / N
    let m = Byte(i - o * N)
    return (o, 1 << m)
  }

  /* Returns a mask that has 1s for all bits that are in the last byte. */
  private func lastByteMask() -> Byte {
    let diff = bytes.count * N - size
    if diff > 0 {
      // Set the highest bit that's still valid.
      let mask = 1 << Byte(63 - diff)
      // Subtract 1 to turn it into a mask, and add the high bit back in.
      return BitSet.Byte(mask | (mask - 1))
    } else {
      return allOnes
    }
  }

  /*
   If the size is not a multiple of N, then we have to clear out the bits
   that we're not using, or bitwise operations between two differently sized
   BitSets will go wrong.
   */
  fileprivate mutating func clearUnusedBits() {
    bytes[bytes.count - 1] &= lastByteMask()
  }

  /* So you can write bitset[99] = ... */
  public subscript(i: Int) -> Bool {
    get { return isSet(i) }
    set { if newValue { set(i) } else { clear(i) } }
  }

  /* Sets the bit at the specified index to 1. */
  public mutating func set(_ i: Int) {
    let (j, m) = indexOf(i)
    bytes[j] |= m
  }

  /* Sets all the bits to 1. */
  public mutating func setAll() {
    for i in 0 ..< bytes.count {
      bytes[i] = allOnes
    }
    clearUnusedBits()
  }

  /* Sets the bit at the specified index to 0. */
  public mutating func clear(_ i: Int) {
    let (j, m) = indexOf(i)
    bytes[j] &= ~m
  }

  /* Sets all the bits to 0. */
  public mutating func clearAll() {
    for i in 0 ..< bytes.count {
      bytes[i] = 0
    }
  }

  /* Changes 0 into 1 and 1 into 0. Returns the new value of the bit. */
  public mutating func flip(i: Int) -> Bool {
    let (j, m) = indexOf(i)
    bytes[j] ^= m
    return (bytes[j] & m) != 0
  }

  /* Determines whether the bit at the specific index is 1 (true) or 0 (false). */
  public func isSet(_ i: Int) -> Bool {
    let (j, m) = indexOf(i)
    return (bytes[j] & m) != 0
  }

  /*
   Returns the number of bits that are 1. Time complexity is O(s) where s is
   the number of 1-bits.
   */
  public var cardinality: Int {
    var count = 0
    for var x in bytes {
      while x != 0 {
        let y = x & ~(x - 1)  // find lowest 1-bit
        x = x ^ y             // and erase it
        count += 1
      }
    }
    return count
  }

  /* Checks if all the bits are set. */
  public func all() -> Bool {
    for i in 0 ..< bytes.count - 1 {
      if bytes[i] != allOnes { return false }
    }
    return bytes[bytes.count - 1] == lastByteMask()
  }

  /* Checks if any of the bits are set. */
  public func any() -> Bool {
    for x in bytes {
      if x != 0 { return true }
    }
    return false
  }

  /* Checks if none of the bits are set. */
  public func none() -> Bool {
    for x in bytes {
      if x != 0 { return false }
    }
    return true
  }
}

// MARK: - Equality

extension BitSet: Equatable {
}

public func == (lhs: BitSet, rhs: BitSet) -> Bool {
  return lhs.bytes == rhs.bytes
}

// MARK: - Hashing

extension BitSet: Hashable {
  /* Based on the hashing code from Java's BitSet. */
  public var hashValue: Int {
    var h = Int(1234)
    for i in stride(from: bytes.count, to: 0, by: -1) {
      h ^= Int(bytes[i - 1]) &* Int(i)
    }
    return (h >> 32) ^ h
  }
}

// MARK: - Bitwise operations

private func copyLargest(_ lhs: BitSet, _ rhs: BitSet) -> BitSet {
  return (lhs.bytes.count > rhs.bytes.count) ? lhs : rhs
}

/*
 Note: In all of these bitwise operations, lhs and rhs are allowed to have a
 different number of bits. The new BitSet always has the larger size.
 The extra bits that get added to the smaller BitSet are considered to be 0.
 That will strip off the higher bits from the larger BitSet when doing &.
 */

public func & (lhs: BitSet, rhs: BitSet) -> BitSet {
  let m = max(lhs.size, rhs.size)
  var out = BitSet(size: m)
  let n = min(lhs.bytes.count, rhs.bytes.count)
  for i in 0 ..< n {
    out.bytes[i] = lhs.bytes[i] & rhs.bytes[i]
  }
  return out
}

public func | (lhs: BitSet, rhs: BitSet) -> BitSet {
  var out = copyLargest(lhs, rhs)
  let n = min(lhs.bytes.count, rhs.bytes.count)
  for i in 0 ..< n {
    out.bytes[i] = lhs.bytes[i] | rhs.bytes[i]
  }
  return out
}

public func ^ (lhs: BitSet, rhs: BitSet) -> BitSet {
  var out = copyLargest(lhs, rhs)
  let n = min(lhs.bytes.count, rhs.bytes.count)
  for i in 0 ..< n {
    out.bytes[i] = lhs.bytes[i] ^ rhs.bytes[i]
  }
  return out
}

public prefix func ~ (rhs: BitSet) -> BitSet {
  var out = BitSet(size: rhs.size)
  for i in 0 ..< rhs.bytes.count {
    out.bytes[i] = ~rhs.bytes[i]
  }
  out.clearUnusedBits()
  return out
}

// MARK: - Debugging

extension UInt8 {

  /* Writes the bits in little-endian order, LSB first. */
  public func bitsToString() -> String {
    var s = ""
    var n = self
    for _ in 1 ... 8 {
      s += ((n & 1 == 1) ? "1" : "0")
      n >>= 1
    }
    return s
  }

}

extension BitSet: CustomStringConvertible {

  public var description: String {
    var s = ""
    for x in bytes {
      s += x.bitsToString() + " "
    }
    return s
  }

}
