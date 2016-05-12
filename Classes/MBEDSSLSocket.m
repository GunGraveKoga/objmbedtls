#import <ObjFW/ObjFW.h>
#import "MBEDSSLSocket.h"
#import "MBEDX509Certificate.h"
#import "MBEDCRL.h"
#import "MBEDPKey.h"

#include <mbedtls/certs.h>
#include <mbedtls/threading.h>

#if defined(OF_WINDOWS)
#define dup(x) _dup(x)
#define dup2(x, y) _dup2(x, y)
#endif

@interface MBEDSSLSocket()

- (void)SSL_startTLSWithExpectedHost:(OFString*)host port:(uint16_t)port asClient:(bool)client;
- (void)SSL_peerCertificateVerificationWithCA:(bool)flag host:(OFString *)host;
- (void)reinit_SSL;
- (void)SSL_super_close;

@end


@implementation MBEDSSLSocket

@synthesize delegate = _delegate;
@synthesize certificateFile = _certificateFile;
@synthesize privateKeyFile = _privateKeyFile;
@synthesize privateKeyPassphrase = _privateKeyPassphrase;
@synthesize certificateAuthorityFile = _certificateAuthorityFile;
@synthesize certificateRevocationListFile = _certificateRevocationListFile;
@dynamic certificateVerificationEnabled;

@synthesize CA = _CA;
@synthesize CRL = _CRL;
@synthesize PK = _PK;
@synthesize certificateProfile = _certificateProfile;
@synthesize ownCertificate = _ownCertificate;
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
	self.privateKeyFile = nil;
	self.certificateVerificationEnabled = true;
	self.certificateFile = nil;
	self.privateKeyPassphrase = NULL;
	self.certificateAuthorityFile = nil;
	self.certificateRevocationListFile = nil;
	self.CA = nil;
	self.CRL = nil;
	self.PK = nil;
	self.ownCertificate = nil;
	_SSL = [MBEDSSL new];
	//_CA = [MBEDX509Certificate new];
	//_CRL = [MBEDCRL new];

	//_PK = [MBEDPKey new];
	_peerCertificate = nil;
	//_ownCertificate = nil;
	_sslVersion = OBJMBED_SSLVERSION_SSLv3;
	_certificateProfile = kDefaultProfile;

	mbedtls_net_init(self.context);

	_isSSLServer = false;

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
	of_log(@"s1 %d", socket->_socket);

	@try {
		if ((dup2(socket->_socket, self->_socket)) != 0) {
			@throw [OFInitializationFailedException exceptionWithClass:[MBEDSSLSocket class]];

		}
		of_log(@"s2 %d", self->_socket);
	} @catch (id e) {
		[self release];
		@throw e;
	}
	of_log(@"s2 %d", self->_socket);
	return self;
}

- (instancetype)initWithAcceptedSocket:(OFTCPSocket *)socket
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

	_isSSLServer = true;

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
	[_ownCertificate release];
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


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-method-access"
#pragma clang diagnostic ignored "-Wincompatible-pointer-types-discards-qualifiers"

- (void)SSL_startTLSWithExpectedHost:(OFString*)host port:(uint16_t)port asClient:(bool)client
{
	bool CAChainVerification = false;

	self.context->fd = (int)_socket;

	@try {
		if (client)
			[_SSL setDefaultTCPClientConfig];
		else
			[_SSL setDefaultTCPServerConfig];

		[_SSL setCertificateProfile:self.certificateProfile];

		[_SSL setConfigSSLVersion:self.sslVersion];


		[_SSL configureCAChainForSocket:self];

		[_SSL configureOwnCertificateForSocket:self];

		if (client)
			[_SSL setHostName:host];

		if (self.CA.version != 0 && self.CRL.context->version != 0) {
			if (!self.CA.isCA) {
				@throw [MBEDSSLCertificationAuthorityMissingException exceptionWithSocket:self];
			}

			CAChainVerification = true;
		}

		[_SSL configureBIOSocket:self];

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

	
	[self SSL_peerCertificateVerificationWithCA:CAChainVerification host:host];
	
	
}


- (void)SSL_peerCertificateVerificationWithCA:(bool)flag host:(OFString *)host
{
	if (!_isSSLServer && host == nil) {
		[self close];
		@throw [OFInvalidArgumentException exception];
	}

	if (self.isCertificateVerificationEnabled) {
		int res = 0;
		if (flag) {
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
			if (host != nil) {
				if (self.peerCertificate == nil) {
					[self close];
					@throw [MBEDSSLCertificateVerificationFailedException exceptionWithCode:MBEDTLS_X509_BADCERT_MISSING certificate:nil];
				}

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

- (void)SSL_super_close
{
	[super close];
}

- (void)startTLSWithExpectedHost:(nullable OFString*)host
{
	if (_isSSLServer)
		[self SSL_startTLSWithExpectedHost:host port:0 asClient:false];
	else
		[self SSL_startTLSWithExpectedHost:host port:0 asClient:true];
}

- (void)connectToHost: (OFString*)host port: (uint16_t)port
{
	[super connectToHost: host port: port];

	[self SSL_startTLSWithExpectedHost:host port:port asClient:true];
}
/*
- (void)listenWithBackLog:(int)backLog	
{
	[super listenWithBackLog:backlog];

	if (self.PK == nil || self.ownCertificate == nil || self.CA == nil)
		@throw [OFListenFailedException exceptionWithSocket:self backLog:backLog errNo:0];

	@try {

		[_SSL setDefaultTCPServerConfig];

		[_SSL setCertificateProfile:self.certificateProfile];

		[_SSL setConfigSSLVersion:self.sslVersion];

		[_SSL configureCAChainForSocket:self];

		[_SSL configureOwnCertificateForSocket:self];

	}@catch(id e) {
		[super close];
		[self reinit_SSL];
		@throw [OFListenFailedException exceptionWithSocket:self backLog:backLog errNo:0];
	}
}

- (instancetype)accept
{
	
}*/

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

- (bool)hasDataInReadBuffer
{
	if (_SSL != nil && (_SSL.context->state != MBEDTLS_SSL_CLIENT_FINISHED && _SSL.context->state != MBEDTLS_SSL_SERVER_FINISHED) && [_SSL bytesAvailable] > 0)
		return true;

	return [super hasDataInReadBuffer];
}

- (MBEDX509Certificate *)peerCertificate
{
	if (_peerCertificate == nil) {
		mbedtls_x509_crt *peerCrt = NULL;
		@try {
			peerCrt = [_SSL peerCertificate];
		}@catch (id e) {
			return nil;
		}

		_peerCertificate = [[MBEDX509Certificate alloc] initWithX509Struct:peerCrt];
	}
	return _peerCertificate;
}
#pragma clang diagnostic pop

//Not implemented
- (nullable OFString*)privateKeyFileForSNIHost:(OFString *)SNIHost
{
	OF_UNRECOGNIZED_SELECTOR
}

- (nullable const char*)privateKeyPassphraseForSNIHost:(OFString*)SNIHost
{
	OF_UNRECOGNIZED_SELECTOR
}

- (void)setPrivateKeyPassphrase:(const char*)privateKeyPassphrase forSNIHost:(OFString*)SNIHost
{
	OF_UNRECOGNIZED_SELECTOR
}

- (void)setPrivateKeyFile:(OFString*)privateKeyFile forSNIHost:(OFString*)SNIHost
{
	OF_UNRECOGNIZED_SELECTOR
}

- (nullable OFString*)certificateFileForSNIHost: (OFString*)SNIHost
{
	OF_UNRECOGNIZED_SELECTOR
}

- (void)setCertificateFile:(OFString*)certificateFile forSNIHost:(OFString*)SNIHost
{
	OF_UNRECOGNIZED_SELECTOR
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