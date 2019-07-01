//
//  Digest.h
//  CryptoSecurityObjC
//
//  Created by Kevin Wooten on 7/28/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


extern NSString *const DigestErrorDomain;


typedef NS_ENUM(NSUInteger, DigestAlgorithm) {
  DigestAlgorithmSHA1,
  DigestAlgorithmSHA224,
  DigestAlgorithmSHA256,
  DigestAlgorithmSHA384,
  DigestAlgorithmSHA512
};


@interface Digester : NSObject

@property(nonatomic, readonly) int status;

-(instancetype) init NS_UNAVAILABLE;
-(nullable instancetype) initWithAlgorithm:(DigestAlgorithm)algorithm error:(NSError **)error NS_DESIGNATED_INITIALIZER;

-(nullable instancetype) updateWithBytes:(const void *)buffer count:(size_t)count error:(NSError **)error NS_SWIFT_NAME(update(bytes:count:));
-(nullable instancetype) updateWithData:(NSData *)data error:(NSError **)error NS_SWIFT_NAME(update(data:));

-(nullable NSData *) finalWithError:(NSError **)error;

+(nullable NSData *) digestWithAlgorithm:(DigestAlgorithm)algorithm bytes:(const void *)buffer count:(size_t)count error:(NSError **)error NS_SWIFT_NAME(digest(algorithm:bytes:count:));
+(nullable NSData *) digestWithAlgorithm:(DigestAlgorithm)algorithm data:(NSData *)data error:(NSError **)error NS_SWIFT_NAME(digest(algorithm:data:));

@end




typedef int (*DigesterEngineInit)(void *);
typedef int (*DigesterEngineUpdate)(void *, const void *, size_t);
typedef int (*DigesterEngineFinal)(unsigned char *, void *);

@interface DigesterEngine : NSObject {
  void *_context;
  NSUInteger _length;
  DigesterEngineInit _init;
  DigesterEngineUpdate _update;
  DigesterEngineFinal _final;
}

-(instancetype) init NS_UNAVAILABLE;
-(instancetype) initWithContext:(void *)context length:(NSUInteger)length init:(DigesterEngineInit)init update:(DigesterEngineUpdate)update final:(DigesterEngineFinal)final error:(NSError **)error NS_DESIGNATED_INITIALIZER;

-(int) update:(const void *)buffer byteCount:(size_t)byteCount;

-(int) finalReturningMessageDigest:(NSData *__nullable __autoreleasing *__nonnull)messageDigest;

@end


NS_ASSUME_NONNULL_END
