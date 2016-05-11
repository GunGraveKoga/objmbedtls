#import <ObjFW/OFObject.h>
#import <ObjFW/OFTCPSocket.h>
#import <ObjFW/OFTLSSocket.h>
#import <ObjFW/OFException.h>
#import "MBEDSSL.h"

#include <mbedtls/net.h>

@class OFString;
@class MBEDX509Certificate;
@class MBEDCRL;
@class MBEDPKey;

@interface MBEDSSLSocket: OFTCPSocket<OFTLSSocket>
{
    MBEDX509Certificate* _CA;
    MBEDX509Certificate* _clientCertificate;
    MBEDCRL* _CRL;
    MBEDPKey* _PK;
    MBEDSSL* _SSL;

    mbedtls_net_context _context;

    id<OFTLSSocketDelegate> _delegate;
    OFString* _certificateFile;
    OFString* _privateKeyFile;
    const char *_privateKeyPassphrase;
    bool _certificateVerificationEnabled;
    objmbed_ssl_version_t _sslVersion;
    mbedtls_x509_crt_profile _certificateProfile;

    bool _isSSLServer;

    MBEDX509Certificate* _peerCertificate;
}

@property (retain, readwrite)MBEDX509Certificate* CA;
@property (retain, readwrite)MBEDCRL* CRL;
@property (retain, readwrite)MBEDX509Certificate* clientCertificate;
@property (retain, readwrite)MBEDPKey* PK;

@property (assign, readonly)mbedtls_net_context* context;
@property (assign, readwrite)mbedtls_x509_crt_profile certificateProfile;

@property OF_NULLABLE_PROPERTY (assign) id <OFTLSSocketDelegate> delegate;
@property OF_NULLABLE_PROPERTY (copy) OFString *certificateFile;
@property OF_NULLABLE_PROPERTY (copy) OFString *privateKeyFile;
@property OF_NULLABLE_PROPERTY (assign) const char *privateKeyPassphrase;
@property (getter=isCertificateVerificationEnabled)bool certificateVerificationEnabled;
@property (assign, readwrite)objmbed_ssl_version_t sslVersion;

- (instancetype)initWithSocket:(OFTCPSocket *)socket;
- (instancetype)initWithAcceptedSocket:(OFTCPSocket *)socket;
- (void)startTLSWithExpectedHost:(nullable OFString*)host;
- (MBEDX509Certificate *)peerCertificate;

//Not imlemented
- (nullable OFString*)privateKeyFileForSNIHost:(OFString *)SNIHost;
- (nullable const char*)privateKeyPassphraseForSNIHost:(OFString*)SNIHost;
- (void)setPrivateKeyPassphrase:(const char*)privateKeyPassphrase forSNIHost:(OFString*)SNIHost;
- (void)setPrivateKeyFile:(OFString*)privateKeyFile forSNIHost:(OFString*)SNIHost;
- (nullable OFString*)certificateFileForSNIHost: (OFString*)SNIHost;
- (void)setCertificateFile:(OFString*)certificateFile forSNIHost:(OFString*)SNIHost;


@end

@interface MBEDSSLCertificationAuthorityMissingException: OFException
{
    MBEDSSLSocket* _socket;
}

@property(retain, readonly)MBEDSSLSocket* socket;

- (instancetype)initWithSocket:(MBEDSSLSocket *)socket;
+ (instancetype)exceptionWithSocket:(MBEDSSLSocket *)socket;

@end