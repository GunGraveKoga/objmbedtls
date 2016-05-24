#import <ObjFW/ObjFW.h>
#import "MBEDTLSException.h"
#import "PEM.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PEM_PARSE_C) || defined(MBEDTLS_PEM_WRITE_C)

#include "mbedtls/pem.h"
#include "mbedtls/base64.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/md5.h"
#include "mbedtls/cipher.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

@implementation MBEDPEM

+ (OFArray *)parsePEMString:(OFString *)pem header:(OFString *)header footer:(OFString *)footer password:(OFString *)password
{
	if (pem == nil)
		@throw [OFInvalidArgumentException exception];

#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_MODE_CBC) &&         \
    ( defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C) )
    unsigned char pem_iv[16];
    mbedtls_cipher_type_t enc_alg = MBEDTLS_CIPHER_NONE;
#else
    password = nil;
#endif /* MBEDTLS_MD5_C && MBEDTLS_CIPHER_MODE_CBC &&
          ( MBEDTLS_AES_C || MBEDTLS_DES_C ) */

    
    of_range_t headerRange;
    of_range_t footerRange;
    size_t pos = 0;


    OFMutableArray* DERData = [OFMutableArray new];

    OFAutoreleasePool* pool = [OFAutoreleasePool new];

    while (true) {

    	headerRange = [pem rangeOfString:header options:0 range:of_range(pos, [pem length])];

    	if (headerRange.location == OF_NOT_FOUND) {
    		if ([DERData count] > 0) {
    			break;

    		} else {
    			[pool release];
    			[DERData release];

    			@throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_BAD_INPUT_DATA];
    		}
    	}

    	footerRange = [pem rangeOfString:footer options:0 range:of_range((headerRange.location + headerRange.length), [pem length])];

    	if (footerRange.location == OF_NOT_FOUND) {
    		if ([DERData count] > 0) {
    			break;

    		} else {
    			[pool release];
    			[DERData release];

    			@throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_BAD_INPUT_DATA];
    		}
    	}

    	pos = (footerRange.location + footerRange.length);

    	for (size_t idx = (headerRange.location + headerRange.length); idx < footerRange.location; idx++) {
    		of_unichar_t ch = [pem characterAtIndex:idx];

    		switch (ch) {
    			case ' ':
    			case '\r':
    			case '\n':
    				continue;
    			default:
    				break;
    		}

    		of_range_t encriptionTagRange = [pem rangeOfString:@"Proc-Type: 4,ENCRYPTED" options:0 range:of_range(idx, footerRange.location)];

    		if (encriptionTagRange.location != OF_NOT_FOUND) {
#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_MODE_CBC) &&         \
    ( defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C) )

    			//

    		}
#endif
    	}

    }

    [pool release];

    [DERData makeImmutable];

    return [DERData autorelease];

}

@end