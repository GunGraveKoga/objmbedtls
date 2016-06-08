#import <ObjFW/ObjFW.h>
#import "MBEDSSL.h"
#import "MBEDSSLConfig.h"
#import "MBEDSSLSocket.h"
#import "MBEDX509Certificate.h"
#import "MBEDPKey.h"
#import "MBEDCRL.h"
#import "MBEDTLSException.h"
#import "MBEDInitializationFailedException.h"
#import "MBEDEntropy.h"

#include <mbedtls/error.h>




@interface MBEDSSL()
@property(copy, readwrite)OFString* cipherSuite;
@property(assign, readwrite)MBEDEntropy* entropy;
@end

@implementation MBEDSSL

@dynamic context;
@synthesize cipherSuite = _cipherSuite;

- (instancetype)init
{
	self = [super init];
	_cipherSuite = nil;

	mbedtls_ssl_init( self.context );

	return self;
}

- (void)dealloc
{
	mbedtls_ssl_free( self.context );

	[super dealloc];
}

+ (instancetype)ssl
{
	return [[[self alloc] init] autorelease];
}

+ (instancetype)sslWithConfig:(MBEDSSLConfig *)config
{
	return [[[self alloc] initWithConfig:config] autorelease];
}

- (instancetype)initWithConfig:(MBEDSSLConfig *)config
{
	self = [self init];

	int ret = 0;

	if ((ret = mbedtls_ssl_setup(self.context, config.context)) != 0) {
		[self release];

		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDSSL class] errorNumber:ret];
	}

	return self;

}

- (mbedtls_ssl_context *)context
{
	return &_ssl;
}

- (void)setBinaryIO:(MBEDSSLSocket *)socket
{
  	mbedtls_ssl_set_bio(self.context, socket.context, mbedtls_net_send, mbedtls_net_recv, NULL);
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
	int ret = 0;

	while ((ret = mbedtls_ssl_close_notify(self.context)) < 0) {
		if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
        	break;
        }
	}
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

- (void)setHostName:(OFString *)host
{
	int ret = 0;

	if ( (ret = mbedtls_ssl_set_hostname(self.context, [host UTF8String])) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
}


@end
