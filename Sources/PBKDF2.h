//
//  PBKDF2.h
//  CryptoSecurity
//
//  Created by Kevin Wooten on 8/3/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


extern NSString *const PBKDF2ErrorDomain;


typedef NS_ENUM(NSUInteger, PBKDF2HmacAlgorithm) {
  PBKDF2HmacAlgorithmSHA1   = 1,
  PBKDF2HmacAlgorithmSHA224 = 2,
  PBKDF2HmacAlgorithmSHA256 = 3,
  PBKDF2HmacAlgorithmSHA384 = 4,
  PBKDF2HmacAlgorithmSHA512 = 5,
};

@interface PBKDF2 : NSObject

+(NSInteger) calibrateForPasswordLength:(NSInteger)passwordLength saltLength:(NSInteger)saltLength keySize:(NSInteger)keySize algorithm:(PBKDF2HmacAlgorithm)algorithm taking:(NSInteger)milliseconds NS_SWIFT_NAME(calibrate(passwordLength:saltLength:keySize:algorithm:taking:));
+(nullable NSData *) deriveKeyOfSize:(NSInteger)keySize withPassword:(NSData *)password andSalt:(NSData *)salt usingRounds:(NSInteger)rounds ofAlgorithm:(PBKDF2HmacAlgorithm)algorithm error:(NSError **)error NS_SWIFT_NAME(deriveKey(ofSize:withPassword:andSalt:usingRounds:ofAlgorithm:));

@end


NS_ASSUME_NONNULL_END
