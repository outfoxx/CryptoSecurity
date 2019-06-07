//
//  Cryptor.h
//  CryptoSecurity
//
//  Created by Kevin Wooten on 7/28/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


extern NSString *const CryptorErrorDomain;


typedef NS_ENUM(NSUInteger, CryptorOperation) {
  CryptorOperationEncrypt,
  CryptorOperationDecrypt
};


typedef NS_ENUM(NSUInteger, CryptorAlgorithm) {
  CryptorAlgorithmAES,
  CryptorAlgorithmDES,
  CryptorAlgorithmTripleDES,
  CryptorAlgorithmCAST,
  CryptorAlgorithmRC2,
  CryptorAlgorithmRC4,
  CryptorAlgorithmBlowfish
};

BOOL CryptorAlgorithmIsValidKeySize(CryptorAlgorithm algorithm, NSUInteger keySize);
NSUInteger CryptorAlgorithmBlockSize(CryptorAlgorithm algorithm);


typedef NS_OPTIONS(UInt32, CryptorOptions) {
  CryptorOptionsPKCS7Padding  = 1 << 0,
  CryptorOptionsECBMode       = 1 << 1,
};


@interface Cryptor : NSObject

+(NSInteger) blockSizeForAlgorithm:(CryptorAlgorithm)algorithm NS_SWIFT_NAME(blockSize(algorithm:));
@property(nonatomic, assign, readonly) NSInteger blockSize;

-(instancetype) init NS_UNAVAILABLE;
-(nullable instancetype) initWithOperation:(CryptorOperation)operation algorithm:(CryptorAlgorithm)algorithm options:(CryptorOptions)options key:(NSData *)key iv:(NSData *)iv error:(NSError **)error NS_DESIGNATED_INITIALIZER;

-(BOOL) resetWithIV:(NSData *)iv error:(NSError **)error NS_SWIFT_NAME(reset(iv:));
-(BOOL) updateWithData:(NSData *)data atOffset:(size_t)dataOffset length:(size_t)dataLength intoData:(NSMutableData *)outData returningLength:(size_t *)outDataLength error:(NSError **)error NS_SWIFT_NAME(update(data:atOffset:length:intoData:returningLength:));
-(BOOL) finalIntoData:(NSMutableData *)data returningLength:(size_t *)outDataLength error:(NSError **)error NS_SWIFT_NAME(final(intoData:returningLength:));

-(NSInteger) getOutputLengthForInputLength:(size_t)inputLength isFinal:(BOOL)final NS_SWIFT_NAME(getOutputLength(inputLength:isFinal:));

+(nullable NSData *) encryptData:(NSData *)data using:(CryptorAlgorithm)algorithm options:(CryptorOptions)options key:(NSData *)key iv:(NSData *)iv error:(NSError **)error NS_SWIFT_NAME(encrypt(data:using:options:key:iv:));
+(nullable NSData *) decryptData:(NSData *)data using:(CryptorAlgorithm)algorithm options:(CryptorOptions)options key:(NSData *)key iv:(NSData *)iv error:(NSError **)error NS_SWIFT_NAME(decrypt(data:using:options:key:iv:));

@end


NS_ASSUME_NONNULL_END
