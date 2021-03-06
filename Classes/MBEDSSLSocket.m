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

- (void)SSL_startTLSWithExpectedHost:(OFString*)host port:(uint16_t)port;
- (void)SSL_peerCertificateVerificationWithHost:(OFString *)host;
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
@dynamic SSL;

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
	self.certificateFile = nil;
	self.privateKeyPassphrase = NULL;
	self.certificateAuthorityFile = nil;
	self.certificateRevocationListFile = nil;
	self.config = nil;

	_SSL = nil;

	_peerCertificate = nil;
	_sslVersion = OBJMBED_SSLVERSION_SSLv3;
	_certificateProfile = kDefaultProfile;

	mbedtls_net_init(self.context);

	_isSSLServer = false;

	_SNIHostCertificates = nil;
	_SNIHostPKeys = nil;
	_SNIHostPKPasswords = nil;

	return self;

}

- (void)reinit_SSL
{
	[_SSL release];

	if (_peerCertificate != nil) {
		[_peerCertificate release];
		_peerCertificate = nil;
	}

	_SSL = nil;
	
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
	[_peerCertificate release];
	[_SSL release];
	[_config release];
	[_SNIHostCertificates release];
	[_SNIHostPKeys release];
	[_SNIHostPKPasswords release];

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


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-method-access"
#pragma clang diagnostic ignored "-Wincompatible-pointer-types-discards-qualifiers"

- (void)SSL_startTLSWithExpectedHost:(OFString*)host port:(uint16_t)port
{
	self.context->fd = (int)_socket;

	id exception = nil;

	void* pool = objc_autoreleasePoolPush();

	@try {
		if (self.config == nil) {
			if (self.isCertificateVerificationEnabled) {
				if (_isSSLServer)
					self.config = [MBEDSSLConfig configForTCPServerWithPeerCertificateVerification];
				else {
					self.config = [MBEDSSLConfig configForTCPClientWithPeerCertificateVerification];
					
				}

			} else {
				if (_isSSLServer)
					self.config = [MBEDSSLConfig configForTCPServer];
				else
					self.config = [MBEDSSLConfig configForTCPClient];

			}

			if (self.certificateAuthorityFile != nil)
				self.config.CA = [MBEDX509Certificate certificateWithFile:self.certificateAuthorityFile];
			else
				self.config.CA = [MBEDX509Certificate certificate]; //must be system CA

			if (self.certificateRevocationListFile != nil)
				self.config.CRL = [MBEDCRL crlWithFile:self.certificateRevocationListFile]; //must be system CRL

			if (self.certificateFile != nil)
				self.config.ownCertificate = [MBEDX509Certificate certificateWithFile:self.certificateFile];

			if (self.privateKeyFile != nil)
				self.config.PK = [MBEDPKey keyWithPrivateKeyFile:self.privateKeyFile password:[OFString stringWithUTF8String:self.privateKeyPassphrase]];

		}

		if (self.CRL == nil)
			self.config.certificateAuthorityChain = self.CA;
		else
			[self.config setCertificateAuthorityChain:self.CA withCRL:self.CRL];

		if (self.PK != nil && self.ownCertificate != nil)
			[self.config setOwnCertificate:self.ownCertificate withPrivateKey:self.PK];


		self.config.validSSLVersion = self.sslVersion;

		_SSL = [[MBEDSSL alloc] initWithConfig:self.config];

		if (!_isSSLServer)
			[_SSL setHostName:host];

		[_SSL setBinaryIO:self];

	} @catch(MBEDTLSException* exc) {
		exception = [SSLConnectionFailedException exceptionWithHost:host port:port socket:self errNo:exc.errNo];

		[exception retain];

		@throw exception;

	} @catch(id e) {
		exception = [e retain];

		@throw;

	}@finally {
		objc_autoreleasePoolPop(pool);

		if (exception != nil) {
			[exception autorelease];

			if (!_isSSLServer)
				[super close];

			[self reinit_SSL];
		}
	}

	@try {
		[_SSL handshake];

	}@catch(MBEDTLSException* exc) {

		if (!_isSSLServer)
			[self close];
		else
			[self reinit_SSL];

		@throw [SSLConnectionFailedException exceptionWithHost:host port:port socket:self errNo:exc.errNo];
		

	} @catch(id e) {

		if (!_isSSLServer)
			[self close];

		@throw [SSLConnectionFailedException exceptionWithHost:host port:port socket:self];

	}

	[self SSL_peerCertificateVerificationWithHost:host];
	
	
}


- (void)SSL_peerCertificateVerificationWithHost:(OFString *)host
{
	if ((!_isSSLServer && self.isCertificateVerificationEnabled) ||
		(_isSSLServer && self.isCertificateVerificationEnabled))
		return;

	if (!_isSSLServer && host == nil) {

		[self close];

		@throw [MBEDTLSException exceptionWithObject:self errorNumber:MBEDTLS_ERR_X509_BAD_INPUT_DATA];
	}

	int res = 0;

	if ((res = (int)[_SSL peerCertificateVerified]) != 0) {
		
		if (self.peerCertificate == nil) {
			if (!_isSSLServer)
				[self close];
			else {
				[_SSL sendFatal:MBEDTLS_SSL_ALERT_MSG_NO_CERT];
				[_SSL notifyPeerToClose];
				[self reinit_SSL];
			}

			@throw [MBEDTLSException exceptionWithObject:self errorNumber:MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE];
		}

		if ((![self.peerCertificate hasCommonNameMatchingDomain:host]) && (![self.peerCertificate hasDNSNameMatchingDomain:host])) {

			if (self.delegate != nil) {

				if ([self.delegate respondsToSelector:@selector(socket:shouldAcceptCertificate:)]) {

					if ([self.delegate socket:self shouldAcceptCertificate:nil]) {

						return;

					} else {
						if(!_isSSLServer)
							[self close];
						else {
							[_SSL sendFatal:MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN];
							[_SSL notifyPeerToClose];
							[self reinit_SSL];
						}
						
						return;
					}
				}

			}

			if (!_isSSLServer)
				[self close];
			else {
				[_SSL sendFatal:MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR];
				[_SSL notifyPeerToClose];
				[self reinit_SSL];
			}

			@throw [MBEDTLSException exceptionWithObject:self errorNumber:MBEDTLS_ERR_X509_CERT_VERIFY_FAILED];

		}

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
	[self SSL_startTLSWithExpectedHost:host port:0];
}

- (void)connectToHost: (OFString*)host port: (uint16_t)port
{
	[super connectToHost: host port: port];

	[self SSL_startTLSWithExpectedHost:host port:port];
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

		mbedtls_x509_crt *next = NULL;

		mbedtls_x509_crt *prev = peerCrt;

		while ((next = prev->next) != NULL) {
			[bytes removeAllItems];
			[bytes addItems:next->raw.p count:next->raw.len];

			[_peerCertificate parseDER:bytes];

			prev = next;
		}

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
	if (_SNIHostPKeys == nil)
		return nil;

	return [_SNIHostPKeys valueForKey:SNIHost];
}

- (nullable const char*)privateKeyPassphraseForSNIHost:(OFString*)SNIHost
{
	if (_SNIHostPKPasswords == nil)
		return NULL;

	if ([_SNIHostPKPasswords valueForKey:SNIHost] != nil)
		return [[_SNIHostPKPasswords valueForKey:SNIHost] UTF8String];

	return NULL;
}

- (void)setPrivateKeyPassphrase:(const char*)privateKeyPassphrase forSNIHost:(OFString*)SNIHost
{
	if (_SNIHostPKPasswords == nil)
		_SNIHostPKPasswords = [[OFMutableDictionary alloc] init];

	OFAutoreleasePool* pool = [OFAutoreleasePool new];
	id exception = nil;
	@try {
		[_SNIHostPKPasswords setValue:[OFString stringWithUTF8String:privateKeyPassphrase] forKey:SNIHost];

	}@catch (id e) {
		exception = [e retain];
		@throw;

	}@finally {
		[pool release];

		if (exception != nil)
			[exception autorelease];
	}
}

- (void)setPrivateKeyFile:(OFString*)privateKeyFile forSNIHost:(OFString*)SNIHost
{
	if (_SNIHostPKeys == nil)
		_SNIHostPKeys = [[OFMutableDictionary alloc] init];

	[_SNIHostPKeys setValue:privateKeyFile forKey:SNIHost];
}

- (nullable OFString*)certificateFileForSNIHost: (OFString*)SNIHost
{
	if (_SNIHostCertificates == nil)
		return nil;

	return [_SNIHostCertificates valueForKey:SNIHost];
}

- (void)setCertificateFile:(OFString*)certificateFile forSNIHost:(OFString*)SNIHost
{
	if (_SNIHostCertificates == nil)
		_SNIHostCertificates = [[OFMutableDictionary alloc] init];

	[_SNIHostCertificates setValue:certificateFile forKey:SNIHost];
}

@end
