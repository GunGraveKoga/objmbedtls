#import <ObjFW/ObjFW.h>
#import "MBEDSSL.h"
#import "MBEDSSLSocket.h"
#import "MBEDX509Certificate.h"
#import "MBEDPKey.h"
#import "MBEDCRL.h"
#import "MBEDTLSException.h"

#include <mbedtls/error.h>

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
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDSSL class]];
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

- (void)setDefaultConfigEndpoint:(int)endpoint transport:(int)transport preset:(int)preset authMode:(int)mode
{
	int ret = 0;

	if ( (ret = mbedtls_ssl_setup(self.context, self.config)) != 0) {
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
	}

	if ( (ret = mbedtls_ssl_config_defaults(self.config, endpoint, transport, preset)) != 0) {
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
	}

	mbedtls_ssl_conf_authmode(self.config, mode);
	mbedtls_ssl_conf_rng(self.config, mbedtls_ctr_drbg_random, self.ctr_drbg);
	mbedtls_ssl_conf_ciphersuites(self.config, mbedtls_ssl_list_ciphersuites());

	_configured = true;
}

- (void)setDefaultTCPClientConfig
{
	[self setDefaultConfigEndpoint:MBEDTLS_SSL_IS_CLIENT transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT authMode:MBEDTLS_SSL_VERIFY_OPTIONAL];
}

- (void)setDefaultTCPServerConfig
{
	[self setDefaultConfigEndpoint:MBEDTLS_SSL_IS_SERVER transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT authMode:MBEDTLS_SSL_VERIFY_NONE];
}

- (void)setTCPServerConfigWithClientCertificate
{
	[self setDefaultConfigEndpoint:MBEDTLS_SSL_IS_SERVER transport:MBEDTLS_SSL_TRANSPORT_STREAM preset:MBEDTLS_SSL_PRESET_DEFAULT authMode:MBEDTLS_SSL_VERIFY_OPTIONAL];
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

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	@try {
		if (sslSocket.CA == nil) {
			sslSocket.CA = [MBEDX509Certificate certificate];

			if (sslSocket.certificateAuthorityFile != nil)
				[sslSocket.CA parseFile:sslSocket.certificateAuthorityFile];

		}

		//if (sslSocket.CRL == nil) {
			//sslSocket.CRL = [MBEDCRL crl];

			//if (sslSocket.certificateRevocationListFile != nil)
				//[sslSocket.CRL parseFile:sslSocket.certificateRevocationListFile];
		
		//}
	}@catch(id e) {
		[pool release];
		@throw e;
	}

	[pool release];

	[self setChainForCA:sslSocket.CA withCRL:sslSocket.CRL];
}

- (void)setChainForCA:(MBEDX509Certificate *)ca withCRL:(MBEDCRL *)crl
{
	mbedtls_ssl_conf_ca_chain(self.config, ca.certificate, (crl != nil) ? crl.context : NULL);
}

- (void)configureOwnCertificateForSocket:(id<OFTLSSocket>)socket
{
	if (![socket isKindOfClass:[MBEDSSLSocket class]])
		@throw [OFInvalidArgumentException exception];

	MBEDSSLSocket* sslSocket = (MBEDSSLSocket *)socket;

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	@try {
		if (sslSocket.ownCertificate == nil) {
			sslSocket.ownCertificate = [MBEDX509Certificate certificate];

			if (sslSocket.certificateFile != nil)
				[sslSocket.ownCertificate parseFile:sslSocket.certificateFile];
		}

		if (sslSocket.PK == nil) {
			sslSocket.PK = [MBEDPKey key];

			if (sslSocket.privateKeyFile != nil)
				[sslSocket.PK parsePrivateKeyFile:sslSocket.privateKeyFile password:[OFString stringWithUTF8String:sslSocket.privateKeyPassphrase]];
		}

	}@catch(id e) {
		[pool release];
		@throw e;
	}

	[pool release];

	[self ownCertificate:sslSocket.ownCertificate privateKey:sslSocket.PK];
}

#pragma clang diagnostic pop

- (void)ownCertificate:(MBEDX509Certificate *)crt privateKey:(MBEDPKey *)pk
{
	mbedtls_ssl_conf_own_cert(self.config, crt.certificate, pk.context);
}

- (void)setHostName:(OFString *)host
{
	int ret = 0;

	if ( (ret = mbedtls_ssl_set_hostname(self.context, [host UTF8String])) != 0) {
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
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
			@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
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
			@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
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

- (void)resetSession
{
	int ret = 0;

	if ((ret = mbedtls_ssl_session_reset(self.context)) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
}

- (size_t)bytesAvailable
{
	return mbedtls_ssl_get_bytes_avail(self.context);
}


@end
