#import <ObjFW/ObjFW.h>
#import "MBEDSSLConfig.h"
#import "MBEDEntropy.h"
#import "MBEDTLSException.h"
#import "MBEDInitializationFailedException.h"
#import "MBEDX509Certificate.h"
#import "MBEDCRL.h"
#import "MBEDPKey.h"


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

@interface MBEDSSLConfig()


@end


@implementation MBEDSSLConfig

@dynamic context;

+ (instancetype)configForTCPServer
{
	return [[[self alloc] initWithTCPServerConfig] autorelease];
}

+ (instancetype)configForTCPClient
{
	return [[[self alloc] initWithTCPClientConfig] autorelease];
}

+ (instancetype)configForTCPServerWithClientCertificateRequest
{
	return [[[self alloc] initWithTCPServerConfigClientCertificateRequired] autorelease];
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

- (instancetype)initWithTCPServerConfig
{
	self = [self initWithEndpoint:MBEDTLS_SSL_IS_SERVER transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT authMode:MBEDTLS_SSL_VERIFY_OPTIONAL];

	return self;
}

- (instancetype)initWithTCPClientConfig
{
	self = [self initWithEndpoint:MBEDTLS_SSL_IS_CLIENT transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT authMode:MBEDTLS_SSL_VERIFY_NONE];

	return self;
}

- (instancetype)initWithTCPServerConfigClientCertificateRequired
{
	self = [self initWithEndpoint:MBEDTLS_SSL_IS_SERVER transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT authMode:MBEDTLS_SSL_VERIFY_OPTIONAL];

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

	mbedtls_ssl_conf_authmode(self.context, mode);

	MBEDEntropy* entropy = [MBEDEntropy defaultEntropy];

	mbedtls_ssl_conf_rng(self.context, mbedtls_ctr_drbg_random, entropy.ctr_drbg);

	mbedtls_ssl_conf_ciphersuites(self.context, mbedtls_ssl_list_ciphersuites());

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