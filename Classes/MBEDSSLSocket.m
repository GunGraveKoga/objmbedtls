#import <ObjFW/ObjFW.h>
#import "MBEDSSLSocket.h"
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
	_SSL = [MBEDSSL new];
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

	@try {
		if (client)
			[_SSL setDefaultTCPClientConfig];
		else {
			if (self.isRequestClientCertificatesEnabled)
				[_SSL setTCPServerConfigWithClientCertificate];
			else
				[_SSL setDefaultTCPServerConfig];
		}

		[_SSL setCertificateProfile:self.certificateProfile];

		[_SSL setConfigSSLVersion:self.sslVersion];


		[_SSL configureCAChainForSocket:self];

		[_SSL configureOwnCertificateForSocket:self];

		if (client)
			[_SSL setHostName:host];

		if (self.CA.version != 0) {
			if (!self.CA.isCA) {
				@throw [SSLCertificationAuthorityMissingException exceptionWithSocket:self];
			}

			CAChainVerification = true;
		}

		[_SSL configureBIOSocket:self];

	} @catch(id e) {
		[super close];
		[self reinit_SSL];
		if (client)
			if ([e isKindOfClass:[MBEDTLSException class]])
				@throw [SSLConnectionFailedException exceptionWithHost:host port:port socket:self errNo:((MBEDTLSException *)e).errNo];
			else
				@throw [SSLConnectionFailedException exceptionWithHost: host port: port socket: self];
		else
			@throw e;
	}

	@try {
		[_SSL handshake];
	}@catch(id e) {
		
		[self close];
		if (client)
			if ([e isKindOfClass:[MBEDTLSException class]])
				@throw [SSLConnectionFailedException exceptionWithHost:host port:port socket:self errNo:((MBEDTLSException *)e).errNo];
			else
				@throw [SSLConnectionFailedException exceptionWithHost:host port:port socket:self];
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

- (uint16_t)bindToHost:(OFString*)host port: (uint16_t)port
{
	uint16_t port_ = [super bindToHost:host port:port];

	_isSSLServer = true;

	return port_;
}

- (instancetype)accept
{
	MBEDSSLSocket* client = (MBEDSSLSocket *)[super accept];
	
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

	@try {
		[client SSL_startTLSWithExpectedHost:nil port:0 asClient:false];
	}@catch(id e) {
		if ([e isKindOfClass:[SSLCertificateVerificationFailedException class]])
			@throw e;
		else if ([e isKindOfClass:[MBEDTLSException class]])
			@throw [SSLAcceptFailedException exceptionWithSocket:self errNo:((MBEDTLSException *)e).errNo];
		else
			@throw [SSLAcceptFailedException exceptionWithSocket:client errNo:0];
	}

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
		@try {
			peerCrt = [_SSL peerCertificate];
		}@catch (id e) {
			return nil;
		}

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
