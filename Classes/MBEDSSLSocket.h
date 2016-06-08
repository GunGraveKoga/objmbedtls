#import <ObjFW/OFObject.h>
#import <ObjFW/OFTCPSocket.h>
#import <ObjFW/OFTLSSocket.h>
#import "macros.h"
#import "MBEDSSLConfig.h"

#include <mbedtls/net.h>

@class OFString;
@class MBEDX509Certificate;
@class MBEDCRL;
@class MBEDPKey;
@class MBEDSSL;

@interface MBEDSSLSocket: OFTCPSocket<OFTLSSocket>
{
    MBEDX509Certificate* _CA;
    MBEDCRL* _CRL;
    MBEDPKey* _PK;
    MBEDX509Certificate* _ownCertificate;
    MBEDSSL* _SSL;
    MBEDSSLConfig* _config;

    mbedtls_net_context _context;

    id<OFTLSSocketDelegate> _delegate;
    OFString* _certificateFile;
    OFString* _privateKeyFile;
    const char *_privateKeyPassphrase;
    OFString* _certificateAuthorityFile;
    OFString* _certificateRevocationListFile;
    bool _certificateVerificationEnabled;
    bool _requestClientCertificatesEnabled;
    objmbed_ssl_version_t _sslVersion;
    mbedtls_x509_crt_profile _certificateProfile;

    bool _isSSLServer;

    MBEDX509Certificate* _peerCertificate;
}

@property OF_NULLABLE_PROPERTY (retain, readwrite)MBEDX509Certificate* CA;
@property OF_NULLABLE_PROPERTY (retain, readwrite)MBEDCRL* CRL;
@property OF_NULLABLE_PROPERTY (retain, readwrite)MBEDPKey* PK;
@property OF_NULLABLE_PROPERTY (retain, readwrite)MBEDX509Certificate* ownCertificate;
@property OF_NULLABLE_PROPERTY (retain, readonly)MBEDSSLConfig* config;
@property OF_NULLABLE_PROPERTY (retain, readonly)MBEDSSL* SSL;

@property (assign, readonly)mbedtls_net_context* context;
@property (assign, readwrite)mbedtls_x509_crt_profile certificateProfile;

@property OF_NULLABLE_PROPERTY (assign) id <OFTLSSocketDelegate> delegate;
@property OF_NULLABLE_PROPERTY (copy) OFString *certificateFile;
@property OF_NULLABLE_PROPERTY (copy) OFString *privateKeyFile;
@property OF_NULLABLE_PROPERTY (assign) const char *privateKeyPassphrase;
@property OF_NULLABLE_PROPERTY (copy) OFString* certificateAuthorityFile;
@property OF_NULLABLE_PROPERTY (copy) OFString* certificateRevocationListFile;
@property (getter=isCertificateVerificationEnabled)bool certificateVerificationEnabled;
@property (getter=isRequestClientCertificatesEnabled)bool requestClientCertificatesEnabled;
@property (assign, readwrite)objmbed_ssl_version_t sslVersion;


- (instancetype)initWithSocket:(OFTCPSocket *)socket;
- (instancetype)initWithAcceptedSocket:(OFTCPSocket *)socket;
- (void)startTLSWithExpectedHost:(nullable OFString*)host;
- (nullable MBEDX509Certificate *)peerCertificate;

//Not imlemented
- (nullable OFString*)privateKeyFileForSNIHost:(OFString *)SNIHost;
- (nullable const char*)privateKeyPassphraseForSNIHost:(OFString*)SNIHost;
- (void)setPrivateKeyPassphrase:(const char*)privateKeyPassphrase forSNIHost:(OFString*)SNIHost;
- (void)setPrivateKeyFile:(OFString*)privateKeyFile forSNIHost:(OFString*)SNIHost;
- (nullable OFString*)certificateFileForSNIHost: (OFString*)SNIHost;
- (void)setCertificateFile:(OFString*)certificateFile forSNIHost:(OFString*)SNIHost;

@end
