#import <ObjFW/ObjFW.h>
#import "MBEDSSLSocket.h"
#import "MBEDX509Certificate.h"
#import "MBEDCRL.h"
#import "MBEDPKey.h"

#include <mbedtls/certs.h>
#include <mbedtls/threading.h>

@interface MBEDSSLSocket()

- (void)SSL_startTLSWithExpectedHost:(OFString*)host port:(uint16_t)port isClient:(bool)isClient;
- (void)reinit_SSL;

@end

static int objmbed_verify( void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags )
{
    char buf[1024];
    ((void) data);

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

static void objmbed_debug( void *ctx, int level, const char *file, int line, const char *str )
{
    ((void) level);

    of_log( @"%s:%04d: %s", file, line, str );
}


@implementation MBEDSSLSocket

@synthesize delegate = _delegate;
@synthesize certificateFile = _certificateFile;
@synthesize privateKeyFile = _privateKeyFile;
@synthesize privateKeyPassphrase = _privateKeyPassphrase;
@dynamic certificateVerificationEnabled;

@synthesize CA = _CA;
@synthesize CRL = _CRL;
@synthesize clientCertificate = _clientCertificate;
@synthesize PK = _PK;
@dynamic sslVersion;

@dynamic context;

+ (void)load
{
	of_tls_socket_class = self;
}

+ (void)initialize
{
	if (self == [MBEDSSLSocket class]) {
		mbedtls_threading_set_alt(objfw_mbedtls_mutex_init, objfw_mbedtls_mutex_free, objfw_mbedtls_mutex_lock, objfw_mbedtls_mutex_unlock);
	}
}

- (instancetype)init
{
	self = [super init];

	self.delegate = nil;
	self.certificateFile = nil;
	self.privateKeyFile = nil;
	self.certificateVerificationEnabled = true;
	_SSL = [MBEDSSL new];
	_CA = [MBEDX509Certificate new];
	_CRL = [MBEDCRL new];
	_clientCertificate = [MBEDX509Certificate new];
	_PK = [MBEDPKey new];
	_peerCertificate = nil;
	_sslVersion = OBJMBED_SSLVERSION_SSLv3;

	mbedtls_net_init(self.context);

	return self;

}

- (void)reinit_SSL
{
	[_SSL release];
	if (_peerCertificate != nil) {
		[_peerCertificate release];
		_peerCertificate = nil;
	}
	_SSL = [MBEDSSL new];
}

- (instancetype)initWithSocket:(OFTCPSocket *)socket
{
	self = [self init];

	@try {
		if ((_socket = dup(socket->_socket)) <= 0) {
			@throw [OFInitializationFailedException exceptionWithClass:[MBEDSSLSocket class]];

		}
	} @catch (id e) {
		[self release];
		@throw e;
	}

	return self;
}

- (void)dealloc
{
	[self close];
	_delegate = nil;

	[_SSL release];
	[_certificateFile release];
	[_privateKeyFile release];
	mbedtls_net_free(self.context);
	[_CA release];
	[_CRL release];
	[_PK release];
	[_clientCertificate release];
	[_peerCertificate release];

	[super dealloc];
}

- (mbedtls_net_context *)context
{
	return &_context;
}

- (void)setSslVersion:(objmbed_ssl_version_t)version
{
	if (self.sslVersion != OBJMBED_SSLVERSION_SSLv3)
		@throw [OFException exception];

	switch (version) {
		case OBJMBED_SSLVERSION_TLSv1:
		case OBJMBED_SSLVERSION_TLSv1_0:
		case OBJMBED_SSLVERSION_TLSv1_1:
		case OBJMBED_SSLVERSION_TLSv1_2:
		case OBJMBED_SSLVERSION_SSLv3:
			break;
		default:
			@throw [OFInvalidArgumentException exception];
			break;
	}

	_sslVersion = version;

}

- (objmbed_ssl_version_t)sslVersion
{
	return _sslVersion;
}

- (bool)isCertificateVerificationEnabled
{
	return _certificateVerificationEnabled;
}

- (void)setCertificateVerificationEnabled:(bool)enabled
{
	_certificateVerificationEnabled = enabled;
}

- (void)SSL_startTLSWithExpectedHost:(OFString*)host port:(uint16_t)port isClient:(bool)isClient
{
	bool CAChainVerification = false;
	
	if (self.CA != nil && self.CRL != nil) {
		if (self.CA.version != 0 && self.CRL.context->version != 0) {
			if (!self.CA.isCA) {
				[super close];
				@throw [MBEDSSLCertificationAuthorityMissingException exceptionWithSocket:self];
			}

			CAChainVerification = true;
		}

	} else {
		[super close];
		@throw [MBEDSSLCertificationAuthorityMissingException exceptionWithSocket:self];
	}

	self.context->fd = (int)_socket;

	@try {
		if (isClient)
			[_SSL setDefaultTCPClientConfig];
		else
			[_SSL setDefaultTCPServerConfig];

		[_SSL setCertificateProfile:kDefaultProfile];

		[_SSL setConfigSSLVersion:self.sslVersion];

		[_SSL configureSocket:self];

		[_SSL configureCAChainForSocket:self];

		[_SSL configureOwnCertificateForSocket:self];

		[_SSL setHostName:host];

	} @catch(id e) {
		[super close];
		[self reinit_SSL];
		@throw [OFConnectionFailedException exceptionWithHost: host port: port socket: self];
	}

	@try {
		[_SSL handshake];
	}@catch(id e) {
		[self close];
		@throw e;
	}


	if (self.isCertificateVerificationEnabled) {
		int res = 0;
		if (CAChainVerification) {
			res = [_SSL peerCertificateVerified];
			if (res != 0) {
				if (self.delegate != nil) {
					if ([self.delegate respondsToSelector:@selector(socket:shouldAcceptCertificate:)]) {
						if ([self.delegate socket:self shouldAcceptCertificate:nil]) {
							return;
						}
					}
				}
			
			}
		} else {
			if (![self.peerCertificate hasCommonNameMatchingDomain:host]) {
				if (![self.peerCertificate hasDNSNameMatchingDomain:host]) {
					if (self.delegate != nil) {
						if ([self.delegate respondsToSelector:@selector(socket:shouldAcceptCertificate:)]) {
							if ([self.delegate socket:self shouldAcceptCertificate:nil]) {
								return;
							}
						}
					}
					[self close];
					@throw [MBEDSSLCertificateVerificationFailedException exceptionWithCode:MBEDTLS_X509_BADCERT_CN_MISMATCH certificate:[self peerCertificate]];
				}
			}
			return;
		}

		[self close];
		@throw [MBEDSSLCertificateVerificationFailedException exceptionWithCode:res certificate:[self peerCertificate]];
		
	}
	
}

- (void)close
{
	if (_socket != INVALID_SOCKET) {
		[_SSL notifyPeerToClose];
		[self reinit_SSL];
		[super close];

	}

}

- (void)startTLSWithExpectedHost:(nullable OFString*)host
{
	if ([self isListening])
		[self SSL_startTLSWithExpectedHost:host port:0 isClient:false];
	else
		[self SSL_startTLSWithExpectedHost:host port:0 isClient:true];
}

- (void)connectToHost: (OFString*)host port: (uint16_t)port
{
	[super connectToHost: host port: port];

	[self SSL_startTLSWithExpectedHost:host port:port isClient:true];
}

- (instancetype)accept
{
	OF_UNRECOGNIZED_SELECTOR
}

- (size_t)lowlevelReadIntoBuffer: (void*)buffer length: (size_t)length
{
	ssize_t ret;

	if (length > INT_MAX)
		@throw [OFOutOfRangeException exception];

	if (_socket == INVALID_SOCKET)
		@throw [OFNotOpenException exceptionWithObject: self];

	if (_atEndOfStream)
		@throw [OFReadFailedException exceptionWithObject: self
						  requestedLength: length
							    errNo: ENOTCONN];

	ret = [_SSL readIntoBuffer:buffer length:length];

	if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
		return 0;

	if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ) {
		_atEndOfStream = true;
		return 0;
	}

	if (ret < 0)
		@throw [OFReadFailedException exceptionWithObject: self requestedLength: length];

	if (ret == 0)
		_atEndOfStream = true;

	return ret;
}

- (void)lowlevelWriteBuffer: (const void*)buffer length: (size_t)length
{
	if (length > INT_MAX)
		@throw [OFOutOfRangeException exception];

	if (_socket == INVALID_SOCKET)
		@throw [OFNotOpenException exceptionWithObject: self];

	if (_atEndOfStream)
		@throw [OFWriteFailedException exceptionWithObject: self
						   requestedLength: length
							     errNo: ENOTCONN];

	[_SSL writeBuffer:buffer length:length];
}

- (OFString*)certificateFileForSNIHost: (OFString*)SNIHost
{
	/* TODO */
	OF_UNRECOGNIZED_SELECTOR
}

- (OFString*)privateKeyFileForSNIHost: (OFString*)SNIHost
{
	/* TODO */
	OF_UNRECOGNIZED_SELECTOR
}

- (void)setPrivateKeyPassphrase: (const char*)privateKeyPassphrase
		     forSNIHost: (OFString*)SNIHost
{
	/* TODO */
	OF_UNRECOGNIZED_SELECTOR
}

- (const char*)privateKeyPassphraseForSNIHost: (OFString*)SNIHost
{
	/* TODO */
	OF_UNRECOGNIZED_SELECTOR
}

- (MBEDX509Certificate *)peerCertificate
{
	if (_peerCertificate == nil) {
		_peerCertificate = [[MBEDX509Certificate alloc] initWithX509Struct:[_SSL peerCertificate]];
	}
	return _peerCertificate;
}

@end

@interface MBEDSSLCertificationAuthorityMissingException()

@property(retain, readwrite)MBEDSSLSocket* socket;

@end


@implementation MBEDSSLCertificationAuthorityMissingException

@synthesize socket = _socket;

- (instancetype)initWithSocket:(MBEDSSLSocket *)socket
{
	self = [super init];

	self.socket = socket;

	return self;
}

+ (instancetype)exceptionWithSocket:(MBEDSSLSocket *)socket
{
	return [[[self alloc] initWithSocket:socket] autorelease];
}

@end