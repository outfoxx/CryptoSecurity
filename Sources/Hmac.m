//
//  Hmac.m
//  CryptoSecurity
//
//  Created by Kevin Wooten on 7/21/17.
//  Copyright © 2017 Outfox, Inc. All rights reserved.
//

#import "Hmac.h"

#import <CommonCrypto/CommonHMAC.h>


NSString *const HmacErrorDomain = @"HmacError";

typedef NS_ENUM(NSUInteger, HmacErrorCode) {
  HmacErrorCodeInitError,
  HmacErrorCodeUpdateError,
  HmacErrorCodeFinalError
};


size_t digestLengths[6] = {
  CC_SHA1_DIGEST_LENGTH,
  CC_MD5_DIGEST_LENGTH,
  CC_SHA256_DIGEST_LENGTH,
  CC_SHA384_DIGEST_LENGTH,
  CC_SHA512_DIGEST_LENGTH,
  CC_SHA224_DIGEST_LENGTH
};


@interface Hmac () {
  CCHmacContext ctx;
  CCHmacAlgorithm algorithm;
}
@end


@implementation Hmac

-(instancetype) initWithAlgorithm:(HmacAlgorithm)algorithm key:(NSData *)key
{
  self = [self initWithAlgorithm:algorithm keyBytes:key.bytes keyLength:key.length];
  return self;
}

-(instancetype) initWithAlgorithm:(HmacAlgorithm)algorithm keyBytes:(const void *)keyBytes keyLength:(size_t)keyLength
{
  self = [super init];
  if (self) {

    self->algorithm = (CCHmacAlgorithm)algorithm;

    [self resetWithKeyBytes:keyBytes length:keyLength];
  }
  return self;
}

-(instancetype) resetWithKeyData:(NSData *)key
{
  return [self resetWithKeyBytes:key.bytes length:key.length];
}

-(instancetype) resetWithKeyBytes:(const void *)keyBytes length:(size_t)keyLength
{
  CCHmacInit(&ctx, algorithm, keyBytes, keyLength);
  return self;
}

-(instancetype) updateWithBytes:(const void *)buffer count:(size_t)count
{
  CCHmacUpdate(&ctx, buffer, count);
  return self;
}

-(instancetype) updateWithData:(NSData *)data
{
  CCHmacUpdate(&ctx, data.bytes, data.length);
  return self;
}

-(NSData *) final
{
  NSMutableData *digest = [NSMutableData dataWithLength:digestLengths[algorithm]];

  CCHmacFinal(&ctx, digest.mutableBytes);

  return [digest copy];
}

+(NSData *) hmacWithAlgorithm:(HmacAlgorithm)algorithm keyBytes:(const void *)keyBytes keyLength:(size_t)keyLength
                    dataBytes:(const void *)data dataCount:(size_t)count
{
  CCHmacAlgorithm ccAlgorithm = (CCHmacAlgorithm)algorithm;
  NSMutableData *digest = [NSMutableData dataWithLength:digestLengths[ccAlgorithm]];

  CCHmac(algorithm, keyBytes, keyLength, data, count, digest.mutableBytes);

  return [digest copy];
}

+(NSData *) hmacWithAlgorithm:(HmacAlgorithm)algorithm key:(NSData *)key data:(NSData *)data
{
  CCHmacAlgorithm ccAlgorithm = (CCHmacAlgorithm)algorithm;
  NSMutableData *digest = [NSMutableData dataWithLength:digestLengths[ccAlgorithm]];

  CCHmac(algorithm, key.bytes, key.length, data.bytes, data.length, digest.mutableBytes);

  return [digest copy];
}

@end
