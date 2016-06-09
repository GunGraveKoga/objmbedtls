#import <ObjFW/ObjFW.h>
#import "MBEDSSLSocket.h"
#import "MBEDSSL.h"
#import "MBEDX509Certificate.h"
#import "MBEDCRL.h"
#import "MBEDPKey.h"
#import "SSLConnectionFailedException.h"
#import "SSLAcceptFailedException.h"
#import "SSLWriteFailedException.h"
#import "SSLReadFailedException.h"
#import "MBEDTLSException.h"
#import "SSLCertificateVerificationFailedException.h"
#import "SSLCertificationAuthorityMissingException.h"

#include <mbedtls/certs.h>
#include <mbedtls/threading.h>
#include <assert.h>


@interface MBEDSSLSocket()

@property OF_NULLABLE_PROPERTY (retain, readwrite)MBEDSSLConfig* config;
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
@synthesize config = _config;
@dynamic certificateVerificationEnabled;
@dynamic requestClientCertificatesEnabled;
@dynamic SSL;

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

- (instancetype)init
{
	self = [super init];

	self.delegate = nil;
	self.privateKeyFile = nil;
	self.certificateVerificationEnabled = true;
	self.requestClientCertificatesEnabled = false;
	self.certificateFile = nil;
	self.privateKeyPassphrase = NULL;
	self.certificateAuthorityFile = nil;
	self.certificateRevocationListFile = nil;
	self.CA = nil;
	self.CRL = nil;
	self.PK = nil;
	self.ownCertificate = nil;
	self.config = nil;

	_SSL = nil;

	_peerCertificate = nil;
	_sslVersion = OBJMBED_SSLVERSION_SSLv3;
	_certificateProfile = kDefaultProfile;

	mbedtls_net_init(self.context);

	_isSSLServer = false;

	return self;

}

- (void)reinit_SSL
{
	[_SSL release];
	[_config release];

	if (_peerCertificate != nil) {
		[_peerCertificate release];
		_peerCertificate = nil;
	}

	_SSL = nil;
	_config = nil;
	
}

- (instancetype)initWithSocket:(OFTCPSocket *)socket
{
	self = [self init];

	@try {
#if defined(OF_WINDOWS)
		WSAPROTOCOL_INFOW protInfo;

		if ((WSADuplicateSocketW((SOCKET)socket->_socket, GetCurrentProcessId(), &protInfo)) != 0)
			@throw [OFInitializationFailedException exceptionWithClass:[MBEDSSLSocket class]];

		_socket = WSASocketW(AF_INET, SOCK_STREAM, 0, &protInfo, 0, WSA_FLAG_OVERLAPPED);

		if (_socket == INVALID_SOCKET)
			@throw [OFInitializationFailedException exceptionWithClass:[MBEDSSLSocket class]];
#else
		if ((_socket = dup(socket->_socket)) <= 0) {
			@throw [OFInitializationFailedException exceptionWithClass:[MBEDSSLSocket class]];

		}
#endif		
		
	} @catch (id e) {
		[self release];
		@throw e;
	}
	
	return self;
}

- (instancetype)initWithAcceptedSocket:(OFTCPSocket *)socket
{
	self = [self init];

	@try {
#if defined(OF_WINDOWS)
		WSAPROTOCOL_INFOW protInfo;

		if ((WSADuplicateSocketW((SOCKET)socket->_socket, GetCurrentProcessId(), &protInfo)) != 0)
			@throw [OFInitializationFailedException exceptionWithClass:[MBEDSSLSocket class]];

		_socket = WSASocketW(AF_INET, SOCK_STREAM, 0, &protInfo, 0, WSA_FLAG_OVERLAPPED);

		if (_socket == INVALID_SOCKET)
			@throw [OFInitializationFailedException exceptionWithClass:[MBEDSSLSocket class]];
#else
		if ((_socket = dup(socket->_socket)) <= 0) {
			@throw [OFInitializationFailedException exceptionWithClass:[MBEDSSLSocket class]];

		}
#endif
	} @catch (id e) {
		[self release];
		@throw e;
	}

	_isSSLServer = true;

	return self;
}

- (void)dealloc
{
	//[self close];

	_delegate = nil;
	
	[_certificateFile release];
	[_privateKeyFile release];
	mbedtls_net_free(self.context);
	[_CA release];
	[_CRL release];
	[_PK release];
	[_ownCertificate release];
	[_peerCertificate release];
	[_SSL release];
	[_config release];

	[super dealloc];
}

- (mbedtls_net_context *)context
{
	return &_context;
}

- (void)setSslVersion:(objmbed_ssl_version_t)version
{
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

- (bool)isRequestClientCertificatesEnabled
{
	return _requestClientCertificatesEnabled;
}

- (void)setRequestClientCertificatesEnabled:(bool)enabled
{
	_requestClientCertificatesEnabled = enabled;
}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-method-access"
#pragma clang diagnostic ignored "-Wincompatible-pointer-types-discards-qualifiers"

- (void)SSL_startTLSWithExpectedHost:(OFString*)host port:(uint16_t)port asClient:(bool)client
{
	bool CAChainVerification = false;

	self.context->fd = (int)_socket;

	id exception = nil;

	void* pool = objc_autoreleasePoolPush();

	@try {
		if (client){
			self.config = [MBEDSSLConfig configForTCPClient];

		}
		else {
			if (self.isRequestClientCertificatesEnabled)
				self.config = [MBEDSSLConfig configForTCPServerWithClientCertificateRequest];
			else
				self.config = [MBEDSSLConfig configForTCPServer];
		}


		if (self.CA == nil) {
			if (self.certificateAuthorityFile != nil) {
				self.CA = [MBEDX509Certificate certificateWithFile:self.certificateAuthorityFile];

			} else {
				self.CA = [MBEDX509Certificate certificate];
			}
		}

		if (self.CRL == nil) {
			if (self.certificateRevocationListFile != nil) {
				self.CRL = [MBEDCRL crlWithFile:self.certificateRevocationListFile];

			}
		}

		if (self.CRL == nil)
			self.config.certificateAuthorityChain = self.CA;
		else
			[self.config setCertificateAuthorityChain:self.CA withCRL:self.CRL];

		if (self.ownCertificate == nil && self.certificateFile != nil)
			self.ownCertificate = [MBEDX509Certificate certificateWithFile:self.certificateFile];

		if (self.PK == nil && self.privateKeyFile != nil)
			self.PK = [MBEDPKey keyWithPrivateKeyFile:self.privateKeyFile password:[OFString stringWithUTF8String:self.privateKeyPassphrase]];

		if (self.PK != nil && self.ownCertificate != nil)
			[self.config setOwnCertificate:self.ownCertificate withPrivateKey:self.PK];


		self.config.validSSLVersion = self.sslVersion;

		_SSL = [[MBEDSSL alloc] initWithConfig:self.config];

		if (client)
			[_SSL setHostName:host];

		if (self.CA.version != 0) {
			if (!self.CA.isCA) {
				@throw [SSLCertificationAuthorityMissingException exceptionWithSocket:self];
			}

			CAChainVerification = true;
		}

		[_SSL setBinaryIO:self];

	} @catch(id e) {
		if (client)
			[super close];

		[self reinit_SSL];

		if (client) {
			if ([e isKindOfClass:[MBEDTLSException class]])
				exception = [SSLConnectionFailedException exceptionWithHost:host port:port socket:self errNo:((MBEDTLSException *)e).errNo];
			else
				exception = [SSLConnectionFailedException exceptionWithHost: host port: port socket: self];

			[exception retain];

			@throw exception;
		}
		else {
			exception = [e retain];

			@throw;
		}

	}@finally {
		objc_autoreleasePoolPop(pool);

		if (exception != nil)
			[exception autorelease];
	}

	@try {
		[_SSL handshake];

	}@catch(id e) {
		
		if (client) {
			[self close];

			if ([e isKindOfClass:[MBEDTLSException class]])
				@throw [SSLConnectionFailedException exceptionWithHost:host port:port socket:self errNo:((MBEDTLSException *)e).errNo];
			else
				@throw [SSLConnectionFailedException exceptionWithHost:host port:port socket:self];
		}
		else
			@throw e;
	}

	
	[self SSL_peerCertificateVerificationWithCA:CAChainVerification host:host];
	
	
}


- (void)SSL_peerCertificateVerificationWithCA:(bool)flag host:(OFString *)host
{
	if (!_isSSLServer && host == nil) {

		if (self.isCertificateVerificationEnabled) {
			[self close];
			@throw [OFInvalidArgumentException exception];
		}
	}

	if (self.isCertificateVerificationEnabled) {
		if (_isSSLServer && !self.isRequestClientCertificatesEnabled)
			return;

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
					of_log(@"Nil peer certificate!");
					@throw [SSLCertificateVerificationFailedException exceptionWithCode:MBEDTLS_X509_BADCERT_MISSING certificate:nil];
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
						@throw [SSLCertificateVerificationFailedException exceptionWithCode:MBEDTLS_X509_BADCERT_CN_MISMATCH certificate:[self peerCertificate]];
					}
				}
				return;
			}
			
		}

		[self close];
		@throw [SSLCertificateVerificationFailedException exceptionWithCode:res certificate:[self peerCertificate]];
		
	}
}

- (void)close
{
	if (_socket != INVALID_SOCKET)
		[_SSL notifyPeerToClose];


	[self reinit_SSL];

	[super close];

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

- (uint16_t)bindToHost:(OFString*)host port: (uint16_t)port
{
	uint16_t port_ = [super bindToHost:host port:port];

	_isSSLServer = true;

	return port_;
}

- (instancetype)accept
{
	MBEDSSLSocket *client = [[[[self class] alloc] init] autorelease];
#if (!defined(HAVE_PACCEPT) && !defined(HAVE_ACCEPT4)) || !defined(SOCK_CLOEXEC)
# if defined(HAVE_FCNTL) && defined(FD_CLOEXEC)
	int flags;
# endif
#endif

	client->_address = [client
	    allocMemoryWithSize: sizeof(struct sockaddr_storage)];
	client->_addressLength = (socklen_t)sizeof(struct sockaddr_storage);

#if defined(HAVE_PACCEPT) && defined(SOCK_CLOEXEC)
	if ((client->_socket = paccept(_socket, client->_address,
	   &client->_addressLength, NULL, SOCK_CLOEXEC)) == INVALID_SOCKET)
		@throw [OFAcceptFailedException
		    exceptionWithSocket: self
				  errNo: of_socket_errno()];
#elif defined(HAVE_ACCEPT4) && defined(SOCK_CLOEXEC)
	if ((client->_socket = accept4(_socket, client->_address,
	   &client->_addressLength, SOCK_CLOEXEC)) == INVALID_SOCKET)
		@throw [OFAcceptFailedException
		    exceptionWithSocket: self
				  errNo: of_socket_errno()];
#else
	if ((client->_socket = accept(_socket, client->_address,
	   &client->_addressLength)) == INVALID_SOCKET)
		@throw [OFAcceptFailedException
		    exceptionWithSocket: self
				  errNo: of_socket_errno()];

# if defined(HAVE_FCNTL) && defined(FD_CLOEXEC)
	if ((flags = fcntl(client->_socket, F_GETFD, 0)) != -1)
		fcntl(client->_socket, F_SETFD, flags | FD_CLOEXEC);
# endif
#endif

	assert(client->_addressLength <=
	    (socklen_t)sizeof(struct sockaddr_storage));

	if (client->_addressLength != sizeof(struct sockaddr_storage)) {
		@try {
			client->_address = [client
			    resizeMemory: client->_address
				    size: client->_addressLength];
		} @catch (OFOutOfMemoryException *e) {
			/* We don't care, as we only made it smaller */
		}
	}
	
	client->_isSSLServer = true;
	client.certificateVerificationEnabled = self.certificateVerificationEnabled;
	client.requestClientCertificatesEnabled = self.requestClientCertificatesEnabled;
	client.PK = self.PK;
	client.CA = self.CA;
	client.CRL = self.CRL;
	client.ownCertificate = self.ownCertificate;
	client.delegate = self.delegate;
	client.sslVersion = self.sslVersion;
	client.certificateProfile = self.certificateProfile;
	client.certificateFile = self.certificateFile;
	client.privateKeyFile = self.privateKeyFile;
	client.privateKeyPassphrase = self.privateKeyPassphrase;
	client.certificateAuthorityFile = self.certificateAuthorityFile;
	client.certificateRevocationListFile = self.certificateRevocationListFile;

	[client SSL_startTLSWithExpectedHost:nil port:0 asClient:false];
	/*
	@try {
		[client SSL_startTLSWithExpectedHost:nil port:0 asClient:false];
	}@catch(id e) {
		if ([e isKindOfClass:[SSLCertificateVerificationFailedException class]])
			@throw e;
		else if ([e isKindOfClass:[MBEDTLSException class]])
			@throw [SSLAcceptFailedException exceptionWithSocket:self errNo:((MBEDTLSException *)e).errNo];
		else
			@throw [SSLAcceptFailedException exceptionWithSocket:client errNo:0];
	}*/

	return client;
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
		@throw [SSLReadFailedException exceptionWithObject:self requestedLength:length errNo:ret];

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
	@try {
		[_SSL writeBuffer:buffer length:length];
	}@catch(id e){
		if ([e isKindOfClass:[MBEDTLSException class]])
			@throw [SSLWriteFailedException exceptionWithObject:self requestedLength:length errNo:((MBEDTLSException*)e).errNo];
		else
			@throw e;
	}
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

		peerCrt = [_SSL peerCertificate];

		if (peerCrt == NULL)
			return nil;

		OFAutoreleasePool* pool = [OFAutoreleasePool new];

		OFDataArray* bytes = [OFDataArray dataArrayWithItemSize:sizeof(char)];

		[bytes addItems: peerCrt->raw.p count: peerCrt->raw.len];

		_peerCertificate = [[MBEDX509Certificate alloc] initWithDER:bytes];

		[pool release];

	}

	return _peerCertificate;
}

- (MBEDSSL *)SSL
{
	return _SSL;
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
