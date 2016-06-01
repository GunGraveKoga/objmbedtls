#import <ObjFW/OFObject.h>
#import "macros.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

@class OFString;

@interface MBEDEntropy: OFObject
{
	mbedtls_entropy_context _entropy;
	mbedtls_ctr_drbg_context _ctr_drbg;
	OFString* _personalizationData;
}

@property(assign, readonly)mbedtls_entropy_context* entropy;
@property(assign, readonly)mbedtls_ctr_drbg_context* ctr_drbg;
@property(copy, readonly)OFString* personalizationData;

+ (instancetype)defaultEntropy;
+ (instancetype)entropyWithPersonalization:(OFString *)pers;
+ (void)setDefaultPersonalization:(OFString *)pers;

@end