//
//  Random.h
//  CryptoSecurity
//
//  Created by Kevin Wooten on 7/28/16.
//  Copyright © 2016 Outfox, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


@interface Random : NSObject

+(nullable NSData *) generateBytesOfSize:(NSInteger)size error:(NSError **)error NS_SWIFT_NAME(generateBytes(ofSize:));

@end


NS_ASSUME_NONNULL_END
