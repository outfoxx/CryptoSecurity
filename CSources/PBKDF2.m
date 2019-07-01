//
//  PBKDF2.m
//  CryptoSecurityObjC
//
//  Created by Kevin Wooten on 8/3/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

#import "PBKDF2.h"
#import "Random.h"

#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonCryptoError.h>

NSString *const PBKDF2ErrorDomain = @"DigestError";

typedef NS_ENUM(NSUInteger, PBKDF2ErrorCode) {
  PBKDF2ErrorCodeCalibrationFailed,
  PBKDF2ErrorCodeDerivationFailed
};


#define THROW(stat, cd, msg, ret) if (error) { *error = [NSError errorWithDomain:PBKDF2ErrorDomain code:cd userInfo: @{NSLocalizedDescriptionKey:msg, @"status":@(stat)}]; } return ret
#define CHECK_THROW(stat, cd, msg, ret) if (stat != kCCSuccess) { THROW(stat, cd, msg, ret); }

@implementation PBKDF2

+(NSInteger) calibrateForPasswordLength:(NSInteger)passwordLength saltLength:(NSInteger)saltLength keySize:(NSInteger)keySize algorithm:(PBKDF2HmacAlgorithm)algorithm taking:(NSInteger)milliseconds
{
  return CCCalibratePBKDF(kCCPBKDF2, passwordLength, saltLength, kCCPRFHmacAlgSHA256, keySize, (uint32_t)milliseconds);
}

+(NSData *) deriveKeyOfSize:(NSInteger)keySize withPassword:(NSData *)password andSalt:(NSData *)salt usingRounds:(NSInteger)rounds ofAlgorithm:(PBKDF2HmacAlgorithm)algorithm error:(NSError **)error
{
  NSMutableData *key = [NSMutableData dataWithLength:keySize];
  
  int status = CCKeyDerivationPBKDF(kCCPBKDF2, password.bytes, password.length, salt.bytes, salt.length, algorithm, (uint32_t)rounds, key.mutableBytes, key.length);
  CHECK_THROW(status, PBKDF2ErrorCodeDerivationFailed, @"Derivation failed", nil)
  
  return key;
}

@end
