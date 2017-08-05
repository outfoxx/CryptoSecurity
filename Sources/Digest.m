//
//  Digest.m
//  CryptoSecurity
//
//  Created by Kevin Wooten on 7/28/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

#import "Digest.h"

#import <CommonCrypto/CommonCrypto.h>


NSString *const DigestErrorDomain = @"DigestError";

typedef NS_ENUM(NSUInteger, DigestErrorCode) {
  DigestErrorCodeInitError,
  DigestErrorCodeUpdateError,
  DigestErrorCodeFinalError
};


#define THROW(stat, cd, msg, ret) if (error) { *error = [NSError errorWithDomain:DigestErrorDomain code:cd userInfo: @{NSLocalizedDescriptionKey:msg, @"status":@(stat)}]; } return ret;


@implementation DigesterEngine

-(instancetype) initWithContext:(void *)context length:(NSUInteger)length init:(DigesterEngineInit)init update:(DigesterEngineUpdate)update final:(DigesterEngineFinal)final error:(NSError **)error
{
  self = [super init];
  if (self) {
    
    _context = context;
    _length = length;
    _init = init;
    _update = update;
    _final = final;
  
    int status = _init(context);
    if (status != 1) {
      THROW(status, DigestErrorCodeInitError, @"Error initializing digest engine", nil)
    }
    
  }
  
  return self;
}

-(void) dealloc {
  free(_context);
}

-(int) update:(const void *)buffer byteCount:(size_t)byteCount
{
  return _update(_context, buffer, byteCount);
}

-(int) finalReturningMessageDigest:(NSData **)messageDigest
{
  NSMutableData *data = [NSMutableData dataWithLength:_length];
  
  int status = _final(data.mutableBytes, _context);
  
  *messageDigest = data;
  
  return status;
}

@end


@interface SHA1DigesterEngine : DigesterEngine {
}

-(instancetype) initReturningError:(NSError **)error;

@end

@implementation SHA1DigesterEngine

-(instancetype) initReturningError:(NSError **)error
{
  CC_SHA1_CTX* ctx = malloc(sizeof(CC_SHA1_CTX));
  self = [super initWithContext:ctx length:CC_SHA1_DIGEST_LENGTH
                           init:(DigesterEngineInit)CC_SHA1_Init
                         update:(DigesterEngineUpdate)CC_SHA1_Update
                          final:(DigesterEngineFinal)CC_SHA1_Final
                          error:error];
  if (!self) {
    free(ctx);
  }
  return self;
}

@end


@interface SHA224DigesterEngine : DigesterEngine {
}

-(instancetype) initReturningError:(NSError **)error;

@end

@implementation SHA224DigesterEngine

-(instancetype) initReturningError:(NSError **)error
{
  CC_SHA256_CTX *ctx = malloc(sizeof(CC_SHA256_CTX));
  self = [super initWithContext:ctx length:CC_SHA224_DIGEST_LENGTH
                           init:(DigesterEngineInit)CC_SHA224_Init update:(DigesterEngineUpdate)CC_SHA224_Update final:(DigesterEngineFinal)CC_SHA224_Final
                          error:error];
  if (!self) {
    free(ctx);
  }
  return self;
}

@end


@interface SHA256DigesterEngine : DigesterEngine {
}

-(instancetype) initReturningError:(NSError **)error;

@end

@implementation SHA256DigesterEngine

-(instancetype) initReturningError:(NSError **)error
{
  CC_SHA256_CTX *ctx = malloc(sizeof(CC_SHA256_CTX));
  self = [super initWithContext:ctx length:CC_SHA256_DIGEST_LENGTH
                           init:(DigesterEngineInit)CC_SHA256_Init update:(DigesterEngineUpdate)CC_SHA256_Update final:(DigesterEngineFinal)CC_SHA256_Final
                          error:error];
  if (!self) {
    free(ctx);
  }
  return self;
}

@end


@interface SHA384DigesterEngine : DigesterEngine {
}

-(instancetype) initReturningError:(NSError **)error;

@end

@implementation SHA384DigesterEngine

-(instancetype) initReturningError:(NSError **)error
{
  CC_SHA512_CTX *ctx = malloc(sizeof(CC_SHA512_CTX));
  self = [super initWithContext:ctx length:CC_SHA384_DIGEST_LENGTH
                           init:(DigesterEngineInit)CC_SHA384_Init update:(DigesterEngineUpdate)CC_SHA384_Update final:(DigesterEngineFinal)CC_SHA384_Final
                          error:error];
  if (!self) {
    free(ctx);
  }
  return self;
}

@end


@interface SHA512DigesterEngine : DigesterEngine {
}

-(instancetype) initReturningError:(NSError **)error;

@end

@implementation SHA512DigesterEngine

-(instancetype) initReturningError:(NSError **)error
{
  CC_SHA512_CTX *ctx = malloc(sizeof(CC_SHA512_CTX));
  self = [super initWithContext:ctx length:CC_SHA512_DIGEST_LENGTH
                           init:(DigesterEngineInit)CC_SHA512_Init update:(DigesterEngineUpdate)CC_SHA512_Update final:(DigesterEngineFinal)CC_SHA512_Final
                          error:error];
  if (!self) {
    free(ctx);
  }
  return self;
}

@end



@interface Digester ()

@property(nonatomic, assign) int status;
@property(nonatomic, nonnull) DigesterEngine *engine;

@end


@implementation Digester

-(instancetype) initWithAlgorithm:(DigestAlgorithm)algorithm error:(NSError **)error
{
  self = [super init];
  if (self) {
    
    switch (algorithm) {
      case DigestAlgorithmSHA1:
        self.engine = [SHA1DigesterEngine.alloc initReturningError:error];
        break;
        
      case DigestAlgorithmSHA224:
        self.engine = [SHA224DigesterEngine.alloc initReturningError:error];
        break;
        
      case DigestAlgorithmSHA256:
        self.engine = [SHA256DigesterEngine.alloc initReturningError:error];
        break;
        
      case DigestAlgorithmSHA384:
        self.engine = [SHA384DigesterEngine.alloc initReturningError:error];
        break;
        
      case DigestAlgorithmSHA512:
        self.engine = [SHA512DigesterEngine.alloc initReturningError:error];
        break;
    }
    
    if (self.engine == nil) {
      return nil;
    }
    
  }
  
  return self;
}

-(instancetype) updateWithData:(NSData *)data error:(NSError **)error
{
  return [self updateWithBytes:data.bytes count:data.length error:error];
}

-(instancetype) updateWithBytes:(const void *)buffer count:(size_t)count error:(NSError **)error
{
  self.status = [self.engine update:buffer byteCount:(CC_LONG)count];
  if (self.status != 1) {
    THROW(self.status, DigestErrorCodeUpdateError, @"Error updating digest engine", nil)
  }
  
  return self;
}

-(NSData *) finalWithError:(NSError **)error
{
  NSData *messageDigest = nil;
  
  self.status = [self.engine finalReturningMessageDigest:&messageDigest];
  if (self.status != 1) {
    THROW(self.status, DigestErrorCodeFinalError, @"Error finalizing digest engine", nil)
    return nil;
  }
  
  return messageDigest;
}

+(NSData *)digestWithAlgorithm:(DigestAlgorithm)algorithm bytes:(const void *)buffer count:(size_t)count error:(NSError **)error
{
  NSMutableData *data;
  switch (algorithm) {
    case DigestAlgorithmSHA1:
      data = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
      CC_SHA1(buffer, (CC_LONG)count, data.mutableBytes);
      break;
      
    case DigestAlgorithmSHA224:
      data = [NSMutableData dataWithLength:CC_SHA224_DIGEST_LENGTH];
      CC_SHA224(buffer, (CC_LONG)count, data.mutableBytes);
      break;
      
    case DigestAlgorithmSHA256:
      data = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
      CC_SHA256(buffer, (CC_LONG)count, data.mutableBytes);
      break;
      
    case DigestAlgorithmSHA384:
      data = [NSMutableData dataWithLength:CC_SHA384_DIGEST_LENGTH];
      CC_SHA384(buffer, (CC_LONG)count, data.mutableBytes);
      break;
      
    case DigestAlgorithmSHA512:
      data = [NSMutableData dataWithLength:CC_SHA512_DIGEST_LENGTH];
      CC_SHA512(buffer, (CC_LONG)count, data.mutableBytes);
      break;
  }
  
  return data.copy;
}

+(nullable NSData *) digestWithAlgorithm:(DigestAlgorithm)algorithm data:(NSData *)data error:(NSError **)error
{
  return [self digestWithAlgorithm:algorithm bytes:data.bytes count:data.length error:error];
}

@end
