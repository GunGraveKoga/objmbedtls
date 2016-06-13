#import <ObjFW/ObjFW.h>
#import "MBEDSSLConfig.h"
#import "MBEDEntropy.h"
#import "MBEDTLSException.h"
#import "MBEDInitializationFailedException.h"
#import "MBEDX509Certificate.h"
#import "MBEDCRL.h"
#import "MBEDPKey.h"

#include <mbedtls/debug.h>

#if defined(SSL_DEBUG)
static OFFile* __log = nil;

static int my_verify( void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags )
{
    char buf[1024];
    MBEDSSLConfig* cfg = (__bridge MBEDSSLConfig*)data;

    of_log(@"%@", cfg);

    of_log( @"Verify requested for (Depth %d):", depth );
    mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, "", crt );
    of_log( @"%s", buf );

    if ( ( *flags ) == 0 )
        of_log( @"  This certificate has no flags" );
    else
    {
        mbedtls_x509_crt_verify_info( buf, sizeof( buf ), "  ! ", *flags );
        of_log( @"%s\n", buf );
    }

    return( 0 );
}

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    if (__log == nil)
    	__log = [OFFile fileWithPath:@"ssl.log" mode:@"a+"];

    [__log writeFormat:@"%s:%04d: |%d| %s\n", file, line, level, str];
    //of_log(@"%s:%04d: |%d| %s", file, line, level, str);
}
#endif

const mbedtls_x509_crt_profile kDefaultProfile = {
	/* Hashes from SHA-1 and above */
  	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1) |
  	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_RIPEMD160) |
  	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA224) |
  	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
  	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) |
  	MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512),
  	0xFFFFFFF, /* Any PK alg    */
  	0xFFFFFFF, /* Any curve     */
  	1024,      /* RSA min key len */
};

const mbedtls_x509_crt_profile kNextDefaultProfile =
{
    /* Hashes from SHA-256 and above */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF, /* Any PK alg    */
#if defined(MBEDTLS_ECP_C)
    /* Curves at or above 128-bit security level */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP384R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP521R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_BP256R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_BP384R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_BP512R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256K1 ),
#else
    0,
#endif
    2048,
};

const mbedtls_x509_crt_profile kNSASuiteBProfile =
{
    /* Only SHA-256 and 384 */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ),
    /* Only ECDSA */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECDSA ),
#if defined(MBEDTLS_ECP_C)
    /* Only NIST P-256 and P-384 */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256R1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP384R1 ),
#else
    0,
#endif
    0,
};

@interface MBEDSSLConfig()


@end


@implementation MBEDSSLConfig

@dynamic context;

+ (instancetype)configForTCPServer
{
	return [[[self alloc] initTCPServerConfig] autorelease];
}

+ (instancetype)configForTCPClient
{
	return [[[self alloc] initTCPClientConfig] autorelease];
}

+ (instancetype)configForTCPServerWithPeerCertificateVerification
{
	return [[[self alloc] initTCPServerConfigWithPeerCertificateVerification] autorelease];
}

+ (instancetype)configForTCPClientWithPeerCertificateVerification
{
    return [[[self alloc] initTCPClientConfigWithPeerCertificateVerification] autorelease];
}


- (instancetype)init
{
	self = [super init];

	mbedtls_ssl_config_init(self.context);

	return self;
}

- (void)dealloc
{
	mbedtls_ssl_config_free(self.context);

	[super dealloc];
}

- (mbedtls_ssl_config *)context
{
	return &_context;
}

- (instancetype)initTCPServerConfig
{
	self = [self initWithEndpoint:MBEDTLS_SSL_IS_SERVER transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT authMode:MBEDTLS_SSL_VERIFY_NONE];

	return self;
}

- (instancetype)initTCPClientConfig
{
	self = [self initWithEndpoint:MBEDTLS_SSL_IS_CLIENT transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT authMode:MBEDTLS_SSL_VERIFY_OPTIONAL];

	return self;
}

- (instancetype)initTCPServerConfigWithPeerCertificateVerification
{
	self = [self initWithEndpoint:MBEDTLS_SSL_IS_SERVER transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT authMode:MBEDTLS_SSL_VERIFY_OPTIONAL];

	return self;
}

- (instancetype)initTCPClientConfigWithPeerCertificateVerification
{
    self = [self initWithEndpoint:MBEDTLS_SSL_IS_CLIENT transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT authMode:MBEDTLS_SSL_VERIFY_REQUIRED];

    return self;
}

- (instancetype)initWithEndpoint:(int)endpoint transport:(int)transport preset:(int)preset authMode:(int)mode
{
	self = [self init];

	int ret = 0;

	if ((ret = mbedtls_ssl_config_defaults(self.context, endpoint, transport, preset)) != 0) {
		[self release];

		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDSSLConfig class] errorNumber:ret];
	}
#if defined(SSL_DEBUG)
	mbedtls_debug_set_threshold(7);

	mbedtls_ssl_conf_verify( self.context, my_verify, (__bridge void*)(self) );
	mbedtls_ssl_conf_dbg(self.context, my_debug, (__bridge void*)(self));
#endif
	mbedtls_ssl_conf_authmode(self.context, mode);

	MBEDEntropy* entropy = [MBEDEntropy defaultEntropy];

	mbedtls_ssl_conf_rng(self.context, mbedtls_ctr_drbg_random, entropy.ctr_drbg);

	return self;
}

- (void)setCertificateProfile:(const mbedtls_x509_crt_profile)profile
{
	mbedtls_ssl_conf_cert_profile(self.context, &profile);
}

- (void)setValidSSLVersion:(objmbed_ssl_version_t)version
{
	switch (version) {
		case OBJMBED_SSLVERSION_TLSv1:
			mbedtls_ssl_conf_min_version(self.context, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
			break;
		case OBJMBED_SSLVERSION_SSLv3:
			mbedtls_ssl_conf_min_version(self.context, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_0);
    		mbedtls_ssl_conf_max_version(self.context, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_0);
			break;
		case OBJMBED_SSLVERSION_TLSv1_0:
			mbedtls_ssl_conf_min_version(self.context, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
    		mbedtls_ssl_conf_max_version(self.context, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
			break;
		case OBJMBED_SSLVERSION_TLSv1_1:
			mbedtls_ssl_conf_min_version(self.context, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);
    		mbedtls_ssl_conf_max_version(self.context, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);
			break;
		case OBJMBED_SSLVERSION_TLSv1_2:
			mbedtls_ssl_conf_min_version(self.context, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    		mbedtls_ssl_conf_max_version(self.context, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
			break;
		default:
			@throw [OFInvalidArgumentException exception];
	}

	mbedtls_ssl_conf_ciphersuites(self.context, mbedtls_ssl_list_ciphersuites());
}

- (void)setCertificateAuthorityChain:(MBEDX509Certificate *)CA
{
	[self setCertificateAuthorityChain:CA withCRL:nil];
}

- (void)setCertificateAuthorityChain:(MBEDX509Certificate *)CA withCRL:(MBEDCRL *)crl
{
	mbedtls_ssl_conf_ca_chain(self.context, CA.context, (crl != nil) ? crl.context : NULL);
}

- (void)setOwnCertificate:(MBEDX509Certificate *)crt withPrivateKey:(MBEDPKey *)prv
{
	int ret = 0;

	if ((ret = mbedtls_ssl_conf_own_cert(self.context, crt.context, prv.context)) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
}

@end