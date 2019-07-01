//
//  Hmac.h
//  CryptoSecurityObjC
//
//  Created by Kevin Wooten on 7/21/17.
//  Copyright © 2017 Outfox, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


extern NSString *const HmacErrorDomain;


typedef NS_ENUM(UInt32, HmacAlgorithm) {
  HmacAlgorithmSHA1,
  HmacAlgorithmMD5,
  HmacAlgorithmSHA256,
  HmacAlgorithmSHA384,
  HmacAlgorithmSHA512,
  HmacAlgorithmSHA224
};


@interface Hmac : NSObject

@property(nonatomic, readonly) int status;

-(instancetype) init NS_UNAVAILABLE;
-(instancetype) initWithAlgorithm:(HmacAlgorithm)algorithm key:(NSData *)key;
-(instancetype) initWithAlgorithm:(HmacAlgorithm)algorithm keyBytes:(const void *)keyBytes keyLength:(size_t)keyLength NS_DESIGNATED_INITIALIZER;

-(instancetype) resetWithKeyBytes:(const void *)keyBytes length:(size_t)keyLength NS_SWIFT_NAME(reset(key:length:));
-(instancetype) resetWithKeyData:(NSData *)key NS_SWIFT_NAME(reset(key:));

-(instancetype) updateWithBytes:(const void *)buffer count:(size_t)count NS_SWIFT_NAME(update(bytes:count:));
-(instancetype) updateWithData:(NSData *)data NS_SWIFT_NAME(update(data:));

-(NSData *) final;

+(NSData *) hmacWithAlgorithm:(HmacAlgorithm)algorithm keyBytes:(const void *)keyBytes keyLength:(size_t)keyLength
                    dataBytes:(const void *)bytes dataCount:(size_t)count NS_SWIFT_NAME(hmac(algorithm:key:keyLength:data:count:));
+(NSData *) hmacWithAlgorithm:(HmacAlgorithm)algorithm key:(NSData *)key data:(NSData *)data NS_SWIFT_NAME(hmac(algorithm:key:data:));

@end


NS_ASSUME_NONNULL_END

