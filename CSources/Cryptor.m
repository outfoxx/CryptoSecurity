//
//  Cryptor.m
//  CryptoSecurityObjC
//
//  Created by Kevin Wooten on 7/28/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

#import "Cryptor.h"

#import <CommonCrypto/CommonCrypto.h>


@interface Cryptor () {
  CCCryptorRef _engine;
  NSUInteger _blockSize;
}

@end


NSString *const CryptorErrorDomain = @"CryptorErrorDomain";


typedef NS_ENUM(NSUInteger, CryptorError) {
  CryptorErrorGeneral,
  CryptorErrorInitFailed,
  CryptorErrorResetFailed,
  CryptorErrorInvalidKeySize,
};


#define THROW(stat, cd, msg, ret) if (error) { *error = [NSError errorWithDomain:CryptorErrorDomain code:cd userInfo: @{NSLocalizedDescriptionKey:msg, @"status":@(stat)}]; } return ret;

#define CHECK_THROW(stat, cd, msg, ret)   \
if (stat != kCCSuccess) {                 \
  THROW(stat, cd, msg, ret)               \
}


CCOperation toOperation(CryptorOperation operation) {
  switch (operation) {
    case CryptorOperationEncrypt:
      return kCCEncrypt;
      
    case CryptorOperationDecrypt:
      return kCCDecrypt;
  }
}


CCAlgorithm toAlgorithm(CryptorAlgorithm algorithm) {
  switch (algorithm) {
    case CryptorAlgorithmAES:
      return kCCAlgorithmAES;
      
    case CryptorAlgorithmDES:
      return kCCAlgorithmDES;
      
    case CryptorAlgorithmTripleDES:
      return kCCAlgorithm3DES;
      
    case CryptorAlgorithmCAST:
      return kCCAlgorithmCAST;
      
    case CryptorAlgorithmRC2:
      return kCCAlgorithmRC2;
      
    case CryptorAlgorithmRC4:
      return kCCAlgorithmRC4;
      
    case CryptorAlgorithmBlowfish:
      return kCCAlgorithmBlowfish;
  }
}


@implementation Cryptor

-(instancetype) initWithOperation:(CryptorOperation)operation algorithm:(CryptorAlgorithm)algorithm options:(CryptorOptions)options key:(NSData *)key iv:(NSData *)iv error:(NSError **)error
{
  self = [super init];
  if (self) {
    _blockSize = CryptorAlgorithmBlockSize(algorithm);
    CCCryptorStatus status = CCCryptorCreate(toOperation(operation), toAlgorithm(algorithm), options, key.bytes, key.length, iv.bytes, &_engine);
    CHECK_THROW(status,CryptorErrorInitFailed,@"Initialization failed",nil);
  }
  return self;
}

-(void) dealloc
{
  CCCryptorRelease(_engine);
  _engine = NULL;
}

-(NSInteger) blockSize
{
  return _blockSize;
}

+(NSInteger) blockSizeForAlgorithm:(CryptorAlgorithm)algorithm
{
  return CryptorAlgorithmBlockSize(algorithm);
}

-(BOOL) resetWithIV:(NSData *)iv error:(NSError **)error
{
  CCCryptorStatus status = CCCryptorReset(_engine, iv.bytes);
  CHECK_THROW(status,CryptorErrorResetFailed,@"Reset failed",NO);
  return YES;
}

-(BOOL) updateWithData:(NSData *)data atOffset:(size_t)dataOffset length:(size_t)dataLength intoData:(NSMutableData *)outData returningLength:(size_t *)outDataLength error:(NSError **)error
{
  CCCryptorStatus status = CCCryptorUpdate(_engine, data.bytes + dataOffset, dataLength, outData.mutableBytes, outData.length, outDataLength);
  CHECK_THROW(status,CryptorErrorGeneral,@"Update failed",NO);
  return YES;
}

-(BOOL) finalIntoData:(NSMutableData *)outData returningLength:(size_t *)outDataLength error:(NSError **)error
{
  CCCryptorStatus status = CCCryptorFinal(_engine, outData.mutableBytes, outData.length, outDataLength);
  CHECK_THROW(status,CryptorErrorGeneral,@"Finalization failed",NO);
  return YES;
}

-(NSInteger) getOutputLengthForInputLength:(size_t)inputLength isFinal:(BOOL)final
{
  return CCCryptorGetOutputLength(_engine, inputLength, final);
}

+(NSData *) run:(Cryptor *)cryptor data:(NSData *)data error:(NSError **)error
{
  NSMutableData *result = [NSMutableData dataWithCapacity:data.length + cryptor.blockSize];
  NSMutableData *buffer = [NSMutableData dataWithLength:1024 + cryptor.blockSize];
  size_t totalBytes = data.length;
  size_t totalBytesRead = 0;
  
  while (totalBytesRead < totalBytes) {
    
    size_t bytesToRead = MIN(1024, totalBytes - totalBytesRead);

    size_t processedBytes = 0;
    if (![cryptor updateWithData:data atOffset:totalBytesRead length:bytesToRead
                        intoData:buffer returningLength:&processedBytes error:error]) {
      return nil;
    }
    
    [result appendBytes:buffer.bytes length:processedBytes];
    totalBytesRead += bytesToRead;
  }
  
  size_t processedBytes = 0;
  if (![cryptor finalIntoData:buffer returningLength:&processedBytes error:error]) {
    return nil;
  }

  [result appendBytes:buffer.bytes length:processedBytes];
  
  return result;
}

+(NSData *) encryptData:(NSData *)data using:(CryptorAlgorithm)algorithm options:(CryptorOptions)options key:(NSData *)key iv:(NSData *)iv error:(NSError **)error
{
  Cryptor *cryptor = [Cryptor.alloc initWithOperation:CryptorOperationEncrypt
                                            algorithm:algorithm
                                              options:options
                                                  key:key
                                                   iv:iv
                                                error:error];
  if (!cryptor) {
    return nil;
  }
  
  return [self run:cryptor data:data error:error];
}

+(NSData *) decryptData:(NSData *)data using:(CryptorAlgorithm)algorithm options:(CryptorOptions)options key:(NSData *)key iv:(NSData *)iv error:(NSError **)error
{
  Cryptor *cryptor = [Cryptor.alloc initWithOperation:CryptorOperationDecrypt
                                            algorithm:algorithm
                                              options:options
                                                  key:key
                                                   iv:iv
                                                error:error];
  if (!cryptor) {
    return nil;
  }

  return [self run:cryptor data:data error:error];
}

@end


NSUInteger CryptorAlgorithmBlockSize(CryptorAlgorithm algorithm)
{
  switch (algorithm) {
    case CryptorAlgorithmAES:
      return kCCBlockSizeAES128;
    case CryptorAlgorithmDES:
      return kCCBlockSizeDES;
    case CryptorAlgorithmTripleDES:
      return kCCBlockSize3DES;
    case CryptorAlgorithmCAST:
      return kCCBlockSizeCAST;
    case CryptorAlgorithmRC2:
      return kCCBlockSizeRC2;
    case CryptorAlgorithmRC4:
      return kCCBlockSizeRC2;
    case CryptorAlgorithmBlowfish:
      return kCCBlockSizeBlowfish;
  }
}


BOOL CryptorAlgorithmIsValidKeySize(CryptorAlgorithm algorithm, NSUInteger keySize)
{
  switch (algorithm) {
    case CryptorAlgorithmAES:
      return keySize == kCCKeySizeAES128 || keySize == kCCKeySizeAES192 || keySize == kCCKeySizeAES256;
    case CryptorAlgorithmDES:
      return keySize == kCCKeySizeDES;
    case CryptorAlgorithmTripleDES:
      return keySize == kCCKeySize3DES;
    case CryptorAlgorithmCAST:
      return keySize >= kCCKeySizeMinCAST && keySize <= kCCKeySizeMaxCAST;
    case CryptorAlgorithmRC2:
      return keySize >= kCCKeySizeMinRC2 && keySize <= kCCKeySizeMaxRC2;
    case CryptorAlgorithmRC4:
      return keySize >= kCCKeySizeMinRC4 && keySize <= kCCKeySizeMaxRC4;
    case CryptorAlgorithmBlowfish:
      return keySize >= kCCKeySizeMinBlowfish && keySize <= kCCKeySizeMaxBlowfish;
  }
}
