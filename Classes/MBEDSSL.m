#import <ObjFW/ObjFW.h>
#import "MBEDSSL.h"
#import "MBEDSSLSocket.h"
#import "MBEDX509Certificate.h"
#import "MBEDPKey.h"
#import "MBEDCRL.h"

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


@interface MBEDSSL()
@property(copy, readwrite)OFString* cipherSuite;
@end

@implementation MBEDSSL

@dynamic context;
@dynamic config;
@dynamic ctr_drbg;
@dynamic entropy;
@synthesize cipherSuite = _cipherSuite;

- (instancetype)init
{
	self = [super init];

	_configured = false;
	_cipherSuite = nil;

	mbedtls_ctr_drbg_init( self.ctr_drbg );
	mbedtls_ssl_init( self.context );
	mbedtls_ssl_config_init( self.config );
	mbedtls_entropy_init( self.entropy );

	void* pool = objc_autoreleasePoolPush();

	OFString* pers = [self className];
	pers = [pers stringByAppendingFormat:@"%p", self];
	if (mbedtls_ctr_drbg_seed(self.ctr_drbg, mbedtls_entropy_func, self.entropy, (const unsigned char *)[pers UTF8String], [pers UTF8StringLength]) != 0) {
		objc_autoreleasePoolPop(pool);
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDSSLSocket class]];
	}
	objc_autoreleasePoolPop(pool);

	return self;
}

- (void)dealloc
{
	mbedtls_ssl_free( self.context );
    mbedtls_ssl_config_free( self.config );
	mbedtls_ctr_drbg_free( self.ctr_drbg );
	mbedtls_entropy_free( self.entropy );
	[super dealloc];
}

+ (instancetype)ssl
{
	return [[[self alloc] init] autorelease];
}

- (mbedtls_ssl_context *)context
{
	return &_ssl;
}

- (mbedtls_ssl_config *)config
{
	return &_conf;
}

- (mbedtls_ctr_drbg_context *)ctr_drbg
{
	return &_ctr_drbg;
}

- (mbedtls_entropy_context *)entropy
{
	return &_entropy;
}

- (void)setDefaultConfigEndpoint:(int)endpoint transport:(int)transport preset:(int)preset
{
	if ( (mbedtls_ssl_setup(self.context, self.config)) != 0) {
		@throw [OFException exception];
	}

	if ( (mbedtls_ssl_config_defaults(self.config, endpoint, transport, preset)) != 0) {
		@throw [OFInvalidArgumentException exception];
	}

	mbedtls_ssl_conf_authmode(self.config, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_rng(self.config, mbedtls_ctr_drbg_random, self.ctr_drbg);
	mbedtls_ssl_conf_ciphersuites(self.config, mbedtls_ssl_list_ciphersuites());

	_configured = true;
}

- (void)setDefaultTCPClientConfig
{
	[self setDefaultConfigEndpoint:MBEDTLS_SSL_IS_CLIENT transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT];
}

- (void)setDefaultTCPServerConfig
{
	[self setDefaultConfigEndpoint:MBEDTLS_SSL_IS_SERVER transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT];
}

- (void)setCertificateProfile:(const mbedtls_x509_crt_profile)profile
{
	mbedtls_ssl_conf_cert_profile(self.config, &profile);
}

- (void)setConfigSSLVersion:(objmbed_ssl_version_t)version
{
	if (!_configured)
		@throw [OFException exception];

	switch (version) {
		case OBJMBED_SSLVERSION_TLSv1:
			mbedtls_ssl_conf_min_version(self.config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
			break;
		case OBJMBED_SSLVERSION_SSLv3:
			mbedtls_ssl_conf_min_version(self.config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_0);
    		mbedtls_ssl_conf_max_version(self.config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_0);
			break;
		case OBJMBED_SSLVERSION_TLSv1_0:
			mbedtls_ssl_conf_min_version(self.config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
    		mbedtls_ssl_conf_max_version(self.config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
			break;
		case OBJMBED_SSLVERSION_TLSv1_1:
			mbedtls_ssl_conf_min_version(self.config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);
    		mbedtls_ssl_conf_max_version(self.config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);
			break;
		case OBJMBED_SSLVERSION_TLSv1_2:
			mbedtls_ssl_conf_min_version(self.config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    		mbedtls_ssl_conf_max_version(self.config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
			break;
		default:
			@throw [OFInvalidArgumentException exception];
	}
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-method-access"

- (void)configureBIOSocket:(id<OFTLSSocket>)socket
{
	if (![socket isKindOfClass:[MBEDSSLSocket class]])
		@throw [OFInvalidArgumentException exception];

	MBEDSSLSocket* sslSocket = (MBEDSSLSocket *)socket;

	//mbedtls_ssl_conf_authmode(self.config, MBEDTLS_SSL_VERIFY_OPTIONAL);
	//mbedtls_ssl_conf_rng(self.config, mbedtls_ctr_drbg_random, self.ctr_drbg);
  	mbedtls_ssl_set_bio(self.context, sslSocket.context, mbedtls_net_send, mbedtls_net_recv, NULL);
  	//mbedtls_ssl_conf_ciphersuites(self.config, mbedtls_ssl_list_ciphersuites());

  	//if ( (mbedtls_ssl_set_session(self.context, ssl_session);) != 0) {
  		//@throw [OFException exception];
  	//}
}

- (void)configureCAChainForSocket:(id<OFTLSSocket>)socket
{
	if (![socket isKindOfClass:[MBEDSSLSocket class]])
		@throw [OFInvalidArgumentException exception];

	MBEDSSLSocket* sslSocket = (MBEDSSLSocket *)socket;

	[self setChainForCA:sslSocket.CA withCRL:sslSocket.CRL];
}

- (void)setChainForCA:(MBEDX509Certificate *)ca withCRL:(MBEDCRL *)crl
{
	mbedtls_ssl_conf_ca_chain(self.config, ca.certificate, crl.context);
}

- (void)configureOwnCertificateForSocket:(id<OFTLSSocket>)socket
{
	if (![socket isKindOfClass:[MBEDSSLSocket class]])
		@throw [OFInvalidArgumentException exception];

	MBEDSSLSocket* sslSocket = (MBEDSSLSocket *)socket;

	[self ownCertificate:sslSocket.clientCertificate privateKey:sslSocket.PK];
}

#pragma clang diagnostic pop

- (void)ownCertificate:(MBEDX509Certificate *)crt privateKey:(MBEDPKey *)pk
{
	mbedtls_ssl_conf_own_cert(self.config, crt.certificate, pk.context);
}

- (void)setHostName:(OFString *)host
{
	if ( (mbedtls_ssl_set_hostname(self.context, [host UTF8String])) != 0) {
		@throw [OFInvalidArgumentException exception];
	}
}

- (void)configureALPN
{
	//if ( (mbedtls_ssl_conf_alpn_protocols(self.config, self.protocols[0]) ) != 0) {
		//@throw [OFException exception];
	//}
}

- (void)handshake
{
	int ret = 0;

	while( ( ret = mbedtls_ssl_handshake( self.context ) ) != 0 ) {
		if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
			@throw [OFException exception];
		}
	}

	@autoreleasepool{
		if (!self.cipherSuite)
			self.cipherSuite = [OFString stringWithUTF8String:mbedtls_ssl_get_ciphersuite(self.context)];
	}
}

- (uint32_t)peerCertificateVerified
{
	return mbedtls_ssl_get_verify_result(self.context);
}

- (const mbedtls_x509_crt *)peerCertificate
{
	const mbedtls_x509_crt *peerCrt = mbedtls_ssl_get_peer_cert(self.context);

	if (!peerCrt)
		@throw [OFException exception];

	return peerCrt;
}

- (void)writeBuffer:(const void*)buffer length:(size_t)length
{
	int ret = 0;

	while( ( ret = mbedtls_ssl_write( self.context, (unsigned char *)buffer, length ) ) <= 0 ) {
		if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
			@throw [OFWriteFailedException exceptionWithObject: self requestedLength: length];
		}
	}
}

- (ssize_t)readIntoBuffer:(void*)buffer length:(size_t)length
{
	return (ssize_t)mbedtls_ssl_read(self.context, (unsigned char *)buffer, length);
}

- (void)notifyPeerToClose
{
	mbedtls_ssl_close_notify(self.context);
}

@end

@interface MBEDSSLCertificateVerificationFailedException()

@property(retain, readwrite)MBEDX509Certificate* certificate;
@property(assign, readwrite)uint32_t verifyCodes;

@end


@implementation MBEDSSLCertificateVerificationFailedException

@synthesize certificate = _certificate;
@synthesize verifyCodes = _verifyCodes;

- (instancetype)initWithCode:(uint32_t)codes certificate:(MBEDX509Certificate *)crt
{
	self = [super init];

	self.verifyCodes = codes;
	self.certificate = crt;

	return self;
}

- (void)dealloc
{
	[_certificate release];
	[super dealloc];
}

+ (instancetype)exceptionWithCode:(uint32_t)codes certificate:(MBEDX509Certificate *)crt
{
	return [[[self alloc] initWithCode:codes certificate:crt] autorelease];
}

- (OFString *)description
{
	OFMutableString* desc = [OFMutableString stringWithUTF8String:"Certificate vrification failed:\n"];

	char buf[1024];

	int ret = mbedtls_x509_crt_verify_info(buf, 1024, "", _verifyCodes);

	if (ret > 0)
		[desc appendUTF8String:buf];
	else
		[desc appendUTF8String:"Unknown!"];

	[desc makeImmutable];

	return desc;
}

@end