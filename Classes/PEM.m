#import <ObjFW/ObjFW.h>
#import "MBEDTLSException.h"
#import "PEM.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

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


#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_MODE_CBC) && ( defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C) )
/*
 * Read a 16-byte hex string and convert it to binary
 */
static int pem_get_iv( const unsigned char *s, unsigned char *iv,
                       size_t iv_len )
{
    size_t i, j, k;

    memset( iv, 0, iv_len );

    for( i = 0; i < iv_len * 2; i++, s++ )
    {
        if( *s >= '0' && *s <= '9' ) j = *s - '0'; else
        if( *s >= 'A' && *s <= 'F' ) j = *s - '7'; else
        if( *s >= 'a' && *s <= 'f' ) j = *s - 'W'; else
            return( MBEDTLS_ERR_PEM_INVALID_ENC_IV );

        k = ( ( i & 1 ) != 0 ) ? j : j << 4;

        iv[i >> 1] = (unsigned char)( iv[i >> 1] | k );
    }

    return( 0 );
}

static void pem_pbkdf1( unsigned char *key, size_t keylen,
                        unsigned char *iv,
                        const unsigned char *pwd, size_t pwdlen )
{
    mbedtls_md5_context md5_ctx;
    unsigned char md5sum[16];
    size_t use_len;

    mbedtls_md5_init( &md5_ctx );

    /*
     * key[ 0..15] = MD5(pwd || IV)
     */
    mbedtls_md5_starts( &md5_ctx );
    mbedtls_md5_update( &md5_ctx, pwd, pwdlen );
    mbedtls_md5_update( &md5_ctx, iv,  8 );
    mbedtls_md5_finish( &md5_ctx, md5sum );

    if( keylen <= 16 )
    {
        memcpy( key, md5sum, keylen );

        mbedtls_md5_free( &md5_ctx );
        mbedtls_zeroize( md5sum, 16 );
        return;
    }

    memcpy( key, md5sum, 16 );

    /*
     * key[16..23] = MD5(key[ 0..15] || pwd || IV])
     */
    mbedtls_md5_starts( &md5_ctx );
    mbedtls_md5_update( &md5_ctx, md5sum,  16 );
    mbedtls_md5_update( &md5_ctx, pwd, pwdlen );
    mbedtls_md5_update( &md5_ctx, iv,  8 );
    mbedtls_md5_finish( &md5_ctx, md5sum );

    use_len = 16;
    if( keylen < 32 )
        use_len = keylen - 16;

    memcpy( key + 16, md5sum, use_len );

    mbedtls_md5_free( &md5_ctx );
    mbedtls_zeroize( md5sum, 16 );
}

#if defined(MBEDTLS_DES_C)
/*
 * Decrypt with DES-CBC, using PBKDF1 for key derivation
 */
static void pem_des_decrypt( unsigned char des_iv[8],
                               unsigned char *buf, size_t buflen,
                               const unsigned char *pwd, size_t pwdlen )
{
    mbedtls_des_context des_ctx;
    unsigned char des_key[8];

    mbedtls_des_init( &des_ctx );

    pem_pbkdf1( des_key, 8, des_iv, pwd, pwdlen );

    mbedtls_des_setkey_dec( &des_ctx, des_key );
    mbedtls_des_crypt_cbc( &des_ctx, MBEDTLS_DES_DECRYPT, buflen,
                     des_iv, buf, buf );

    mbedtls_des_free( &des_ctx );
    mbedtls_zeroize( des_key, 8 );
}

/*
 * Decrypt with 3DES-CBC, using PBKDF1 for key derivation
 */
static void pem_des3_decrypt( unsigned char des3_iv[8],
                               unsigned char *buf, size_t buflen,
                               const unsigned char *pwd, size_t pwdlen )
{
    mbedtls_des3_context des3_ctx;
    unsigned char des3_key[24];

    mbedtls_des3_init( &des3_ctx );

    pem_pbkdf1( des3_key, 24, des3_iv, pwd, pwdlen );

    mbedtls_des3_set3key_dec( &des3_ctx, des3_key );
    mbedtls_des3_crypt_cbc( &des3_ctx, MBEDTLS_DES_DECRYPT, buflen,
                     des3_iv, buf, buf );

    mbedtls_des3_free( &des3_ctx );
    mbedtls_zeroize( des3_key, 24 );
}
#endif /* MBEDTLS_DES_C */

#if defined(MBEDTLS_AES_C)
/*
 * Decrypt with AES-XXX-CBC, using PBKDF1 for key derivation
 */
static void pem_aes_decrypt( unsigned char aes_iv[16], unsigned int keylen,
                               unsigned char *buf, size_t buflen,
                               const unsigned char *pwd, size_t pwdlen )
{
    mbedtls_aes_context aes_ctx;
    unsigned char aes_key[32];

    mbedtls_aes_init( &aes_ctx );

    pem_pbkdf1( aes_key, keylen, aes_iv, pwd, pwdlen );

    mbedtls_aes_setkey_dec( &aes_ctx, aes_key, keylen * 8 );
    mbedtls_aes_crypt_cbc( &aes_ctx, MBEDTLS_AES_DECRYPT, buflen,
                     aes_iv, buf, buf );

    mbedtls_aes_free( &aes_ctx );
    mbedtls_zeroize( aes_key, keylen );
}
#endif /* MBEDTLS_AES_C */

#endif /* MBEDTLS_MD5_C && MBEDTLS_CIPHER_MODE_CBC && ( MBEDTLS_AES_C || MBEDTLS_DES_C ) */

@implementation MBEDPEM

+ (OFArray *)parsePEMString:(OFString *)pem header:(OFString *)header footer:(OFString *)footer password:(OFString *)password
{
	if (pem == nil)
		@throw [OFInvalidArgumentException exception];

#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_MODE_CBC) && ( defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C) )
    unsigned char pem_iv[16];
    mbedtls_cipher_type_t enc_alg = MBEDTLS_CIPHER_NONE;
#else
    password = nil;
#endif /* MBEDTLS_MD5_C && MBEDTLS_CIPHER_MODE_CBC && ( MBEDTLS_AES_C || MBEDTLS_DES_C ) */

    
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

        pos = (size_t)(headerRange.location + headerRange.length);

    	footerRange = [pem rangeOfString:footer options:0 range:of_range(pos, [pem length])];

    	if (footerRange.location == OF_NOT_FOUND) {
    		if ([DERData count] > 0) {
    			break;

    		} else {
    			[pool release];
    			[DERData release];

    			@throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_BAD_INPUT_DATA];
    		}
    	}

        bool encrtypted = false;

        of_range_t encryptionTagRange = [pem rangeOfString:@"Proc-Type: 4,ENCRYPTED" options:0 range:of_range(pos, footerRange.location)];

        if (encryptionTagRange.location != OF_NOT_FOUND) {
#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_MODE_CBC) && ( defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C) )
            encrtypted = true;
            pos = (size_t)(encryptionTagRange.location + encryptionTagRange.length);
#if defined(MBEDTLS_DES_C)
            encryptionTagRange = [pem rangeOfString:@"DEK-Info: DES-EDE3-CBC," options:0 range:of_range(pos, footerRange.location)];

            if (encryptionTagRange.location != OF_NOT_FOUND) {
                enc_alg = MBEDTLS_CIPHER_DES_EDE3_CBC;

                pos = (size_t)(encryptionTagRange.location + encryptionTagRange.length);

                OFString* iv = [pem substringWithRange:of_range(pos, 8)];

                if (pem_get_iv([iv UTF8String], pem_iv, 8) != 0) {
                    if ([DERData count] > 0) {
                        break;

                    } else {
                        [pool release];
                        [DERData release];

                        @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_INVALID_ENC_IV];
                    }
                }

                pos += 16;

            } else {

                encryptionTagRange = [pem rangeOfString:@"DEK-Info: DES-CBC," options:0 range:of_range(pos, footerRange.location)];

                if (encryptionTagRange.location != OF_NOT_FOUND) {

                    enc_alg = MBEDTLS_CIPHER_DES_CBC;

                    pos = (size_t)(encryptionTagRange.location + encryptionTagRange.length);

                    OFString* iv = [pem substringWithRange:of_range(pos, 8)];

                    if (pem_get_iv([iv UTF8String], pem_iv, 8) != 0) {
                        if ([DERData count] > 0) {
                            break;

                        } else {
                            [pool release];
                            [DERData release];

                            @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_INVALID_ENC_IV];
                        }
                    }

                    pos += 16;
                }

            }

#endif /* MBEDTLS_DES_C */
#if defined(MBEDTLS_AES_C)
            encryptionTagRange = [pem rangeOfString:@"DEK-Info: AES-" options:0 range:of_range(pos, footerRange.location)];

            if (encryptionTagRange.location != OF_NOT_FOUND) {

                pos = encryptionTagRange.location;

                OFString* AES = [pem substringWithRange:of_range(pos, 22)];

                if ([AES isEqual:@"DEK-Info: AES-128-CBC,"]) {
                    enc_alg = MBEDTLS_CIPHER_AES_128_CBC;

                } else if ([AES isEqual:@"DEK-Info: AES-192-CBC,"]) {
                    enc_alg = MBEDTLS_CIPHER_AES_192_CBC;

                } else if ([AES isEqual:@"DEK-Info: AES-256-CBC,"]) {
                    enc_alg = MBEDTLS_CIPHER_AES_256_CBC;  

                } else {
                     if ([DERData count] > 0) {
                        break;

                     } else {
                        [pool release];
                        [DERData release];

                        @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG];
                     }
                }

                pos += 22;

                OFString* iv = [pem substringWithRange:of_range(pos, 16)];

                if (pem_get_iv([iv UTF8String], pem_iv, 16) != 0) {
                    if ([DERData count] > 0) {
                        break;

                     } else {
                        [pool release];
                        [DERData release];

                        @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_INVALID_ENC_IV];
                     }
                }

                pos += 32;

            }

#endif /* MBEDTLS_AES_C */  

            if( enc_alg == MBEDTLS_CIPHER_NONE ) {
                if ([DERData count] > 0) {
                    break;
                }

                [pool release];
                [DERData release];

                @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG];
            }

            of_unichar_t ch;

            if ((ch = [pem characterAtIndex:pos]) == '\r') pos++;
            if ((ch = [pem characterAtIndex:pos]) == '\n') pos++;
            else {
                if ([DERData count] > 0) {
                    break;
                }

                [pool release];
                [DERData release];

                @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_INVALID_DATA];

            }
#else

            if ([DERData count] > 0) {
                break;
            }

            [pool release];
            [DERData release];

            @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE];

#endif            
        }

        if (pos == footerRange.location) {
            if ([DERData count] > 0) {
                break;
            }

            [pool release];
            [DERData release];

            @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_INVALID_DATA];
        }

        OFString* BASE64String = [pem substringWithRange:of_range(pos, footerRange.location)];

        BASE64String = [BASE64String stringByReplacingOccurrencesOfString:@"\r" withString:@""];
        BASE64String = [BASE64String stringByReplacingOccurrencesOfString:@"\n" withString:@""];

        OFDataArray* DER = nil;

        @try {
            DER = [OFDataArray dataArrayWithBase64EncodedString:BASE64String];

        } @catch(id e) {
            DER = nil;
        }

        if (DER == nil) {
            if ([DERData count] > 0) {
                break;
            }

            [pool release];
            [DERData release];

            @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_INVALID_DATA + MBEDTLS_ERR_BASE64_INVALID_CHARACTER];
        }

        if (encrtypted) {
#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_MODE_CBC) && ( defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C) )
            if (password == nil) {
                if ([DERData count] > 0) {
                    break;
                }

                [pool release];
                [DERData release];

                @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_PASSWORD_REQUIRED];
            }

            unsigned char *buf = (unsigned char *)[DER items];
            size_t buflen = [DER count];
            const unsigned char *pwd = (const unsigned char *)[password UTF8String];
            size_t pwdlen = [password UTF8StringLength]

#if defined(MBEDTLS_DES_C)
            if( enc_alg == MBEDTLS_CIPHER_DES_EDE3_CBC )
                pem_des3_decrypt( pem_iv, buf, buflen, pwd, pwdlen );
            else if( enc_alg == MBEDTLS_CIPHER_DES_CBC )
                pem_des_decrypt( pem_iv, buf, buflen, pwd, pwdlen );
#endif /* MBEDTLS_DES_C */
#if defined(MBEDTLS_AES_C)
            if( enc_alg == MBEDTLS_CIPHER_AES_128_CBC )
                pem_aes_decrypt( pem_iv, 16, buf, buflen, pwd, pwdlen );
            else if( enc_alg == MBEDTLS_CIPHER_AES_192_CBC )
                pem_aes_decrypt( pem_iv, 24, buf, buflen, pwd, pwdlen );
            else if( enc_alg == MBEDTLS_CIPHER_AES_256_CBC )
                pem_aes_decrypt( pem_iv, 32, buf, buflen, pwd, pwdlen );
#endif /* MBEDTLS_AES_C */

            if( len <= 2 || buf[0] != 0x30 || buf[1] > 0x83 )
            {
                if ([DERData count] > 0) {
                    break;
                }

                [pool release];
                [DERData release];

                @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_PASSWORD_MISMATCH];
            }
#else
            if ([DERData count] > 0) {
                break;
            }

            [pool release];
            [DERData release];

            @throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE];

#endif /* MBEDTLS_MD5_C && MBEDTLS_CIPHER_MODE_CBC && ( MBEDTLS_AES_C || MBEDTLS_DES_C ) */  
     
        }

        [DERData addObject:DER];

        pos = (size_t)(footerRange.location + footerRange.length);

        [pool releaseObjects];

    }

    [pool release];

    [DERData makeImmutable];

    return [DERData autorelease];

}

@end
