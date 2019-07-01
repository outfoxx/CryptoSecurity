//
//  Random.m
//  CryptoSecurityObjC
//
//  Created by Kevin Wooten on 7/28/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

#import "Random.h"

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonRandom.h>


@implementation Random

+(nullable NSData *) generateBytesOfSize:(NSInteger)size error:(NSError **)error
{
  NSMutableData *data = [NSMutableData.alloc initWithLength:size];
  CCRandomGenerateBytes(data.mutableBytes, data.length);
  return data.copy;
}

@end
