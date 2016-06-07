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

OFString *const kPEMString_X509_CRT_Old = @"X509 CERTIFICATE";
OFString *const kPEMString_X509_CRT =     @"CERTIFICATE";
OFString *const kPEMString_X509_CRT_Pair =    @"CERTIFICATE PAIR";
OFString *const kPEMString_X509_CRT_Trusted = @"TRUSTED CERTIFICATE";
OFString *const kPEMString_X509_CSR_Old = @"NEW CERTIFICATE REQUEST";
OFString *const kPEMString_X509_CSR = @"CERTIFICATE REQUEST";
OFString *const kPEMString_X509_CRL = @"X509 CRL";
OFString *const kPEMString_EVP_PrivateKey = @"ANY PRIVATE KEY";
OFString *const kPEMString_PublicKey =   @"PUBLIC KEY";
OFString *const kPEMString_RSA =      @"RSA PRIVATE KEY";
OFString *const kPEMString_RSA_Public =   @"RSA PUBLIC KEY";
OFString *const kPEMString_DSA =      @"DSA PRIVATE KEY";
OFString *const kPEMString_DSA_Public =   @"DSA PUBLIC KEY";
OFString *const kPEMString_PKCS7 =    @"PKCS7";
OFString *const kPEMString_PKCS7_Signed = @"PKCS #7 SIGNED DATA";
OFString *const kPEMString_PKCS8 =    @"ENCRYPTED PRIVATE KEY";
OFString *const kPEMString_PKCS8INF = @"PRIVATE KEY";
OFString *const kPEMString_DH_Params = @"DH PARAMETERS";
OFString *const kPEMString_SSL_Session =  @"SSL SESSION PARAMETERS";
OFString *const kPEMString_DSA_Params =    @"DSA PARAMETERS";
OFString *const kPEMString_ECDSA_Public = @"ECDSA PUBLIC KEY";
OFString *const kPEMString_EC_Parameters = @"EC PARAMETERS";
OFString *const kPEMString_EC_Privatekey = @"EC PRIVATE KEY";
OFString *const kPEMString_Parameters =   @"PARAMETERS";
OFString *const kPEMString_CMS =      @"CMS";

static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_MODE_CBC) && ( defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C) )

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

static void checkForDES(OFString** pem, size_t* pos, size_t len, OFString** iv, mbedtls_cipher_type_t* alg) {

	of_range_t range = [*pem rangeOfString:@"DEK-Info: DES-CBC," options:0 range:of_range(*pos, len)];

	if (range.location == OF_NOT_FOUND)
		return;
	else {

		*alg = MBEDTLS_CIPHER_DES_CBC;

        *pos = (size_t)(range.location + range.length);

        *iv = [*pem substringWithRange:of_range(*pos, 16)];

        *pos += 16;

	}

}

static void checkForDES3(OFString** pem, size_t* pos, size_t len, OFString** iv, mbedtls_cipher_type_t* alg) {

	of_range_t range = [*pem rangeOfString:@"DEK-Info: DES-EDE3-CBC," options:0 range:of_range(*pos, len)];

	if (range.location == OF_NOT_FOUND)
		return;
	else {

		*alg = MBEDTLS_CIPHER_DES_EDE3_CBC;

        *pos = (size_t)(range.location + range.length);

        *iv = [*pem substringWithRange:of_range(*pos, 16)];

        *pos += 16;

	}
}

OFArray* PEMtoDER(OFString *pem, OFString *header, OFString *footer, _Nullable OFString *password) {
	if (pem == nil)
		@throw [OFInvalidArgumentException exception];

#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_MODE_CBC) && ( defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C) )
    unsigned char pem_iv[16];
    mbedtls_cipher_type_t enc_alg = MBEDTLS_CIPHER_NONE;
    OFString* IVHex = nil;
#else
    password = nil;
#endif /* MBEDTLS_MD5_C && MBEDTLS_CIPHER_MODE_CBC && ( MBEDTLS_AES_C || MBEDTLS_DES_C ) */

    
    of_range_t headerRange;
    of_range_t footerRange;
    size_t pos = 0;


    OFMutableArray* DERData = [OFMutableArray new];

    OFAutoreleasePool* pool = [OFAutoreleasePool new];

    while (true) {

    	headerRange = [pem rangeOfString:header options:0 range:of_range(pos, ([pem length] - pos))];

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

    	footerRange = [pem rangeOfString:footer options:0 range:of_range(pos, ([pem length] - pos))];

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

        of_range_t encryptionTagRange = [pem rangeOfString:@"Proc-Type: 4,ENCRYPTED" options:0 range:of_range(pos, (footerRange.location - pos))];

        if (encryptionTagRange.location != OF_NOT_FOUND) {
#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_MODE_CBC) && ( defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C) )
            encrtypted = true;
            pos = (size_t)(encryptionTagRange.location + encryptionTagRange.length);


#if defined(MBEDTLS_DES_C)
            encryptionTagRange = [pem rangeOfString:@"DEK-Info: DES-" options:0 range:of_range(pos, (footerRange.location - pos))];

            if (encryptionTagRange.location != OF_NOT_FOUND) {

            	pos = encryptionTagRange.location;

            	checkForDES3(&pem, &pos, (footerRange.location - pos), &IVHex, &enc_alg);

            	checkForDES(&pem, &pos, (footerRange.location - pos), &IVHex, &enc_alg);

            }

#endif /* MBEDTLS_DES_C */
#if defined(MBEDTLS_AES_C)
            encryptionTagRange = [pem rangeOfString:@"DEK-Info: AES-" options:0 range:of_range(pos, (footerRange.location - pos))];

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

                IVHex = [pem substringWithRange:of_range(pos, 32)];

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

        OFString* BASE64String = [pem substringWithRange:of_range(pos, (footerRange.location - pos))];

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

            if (IVHex == nil) {

            	if ([DERData count] > 0) {
            		break;

            	}

            	[pool release];
            	[DERData release];

            	@throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_INVALID_ENC_IV];

            }

            size_t IVSize = [IVHex length] / 2;

            if ((IVSize & 1) != 0) {
            	if ([DERData count] > 0) {
            		break;

            	}

            	[pool release];
            	[DERData release];

            	@throw [MBEDTLSException exceptionWithObject:nil errorNumber:MBEDTLS_ERR_PEM_INVALID_ENC_IV];
            }

            memset(pem_iv, 0, sizeof(pem_iv));
            of_range_t byteRange = of_range(0, 2);

            for (size_t idx = 0; idx < IVSize; idx++) {

            	OFString* byte = [IVHex substringWithRange:byteRange];

            	pem_iv[idx] = (unsigned char)[byte hexadecimalValue];

            	byteRange = of_range((byteRange.location + byteRange.length), byteRange.length);
            }

            unsigned char *buf = (unsigned char *)[DER items];
            size_t buflen = [DER count];
            const unsigned char *pwd = (const unsigned char *)[password UTF8String];
            size_t pwdlen = [password UTF8StringLength];

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

            if( buflen <= 2 || buf[0] != 0x30 || buf[1] > 0x83 )
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

bool isPEM(OFDataArray* buffer) {

	if (hasHeader(buffer, @"-----BEGIN")) {

		if (hasFooter(buffer, @"-----END"))
			return true;

		@throw [MBEDTLSException exceptionWithObject:buffer errorNumber:MBEDTLS_ERR_PEM_INVALID_DATA];
	}

	return false;
}

bool hasHeader(OFDataArray* buffer, OFString* header) {
    const char* p = (const char *)[buffer items];
    bool res = (strstr( p, [header UTF8String] ) != NULL);

	return res;
}

bool hasFooter(OFDataArray* buffer, OFString* footer) {
    const char* p = (const char *)[buffer items];
    bool res = (strstr( p, [footer UTF8String] ) != NULL);

	return res;
}

OFString* DERtoPEM(OFDataArray *der, OFString* header, OFString* footer, size_t line_length) {

	if (der == nil || [der count] <= 0)
		@throw [OFInvalidArgumentException exception];

	if (header == nil || [header length] <= 0)
		@throw [OFInvalidArgumentException exception];

	if (footer == nil || [footer length] <= 0)
		@throw [OFInvalidArgumentException exception];

	if (line_length == 0)
		line_length = 64;

	OFMutableString* pem = [OFMutableString string];

    OFAutoreleasePool* pool = [OFAutoreleasePool new];

	[pem appendFormat:@"%@\n", header];

	OFString* BASE64String = [der stringByBase64Encoding];

	size_t pem_len = [BASE64String length];
	of_range_t lineRange;
	size_t pos = 0;
	OFString* line = nil;

	while (pem_len) {
		lineRange = of_range(pos, (pem_len > line_length) ? line_length : pem_len);

		line = [BASE64String substringWithRange:lineRange];
		[pem appendFormat:@"%@\n", line];

		pos = (size_t)(lineRange.location + lineRange.length );

		pem_len -= lineRange.length;

	}

	[pem appendFormat:@"%@", footer];

	[pem makeImmutable];

    [pool release];

	return pem;
}
