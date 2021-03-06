#import <ObjFW/OFObject.h>
#import <ObjFW/OFTCPSocket.h>
#import <ObjFW/OFTLSSocket.h>
#import "macros.h"
#import "MBEDSSLConfig.h"

#include <mbedtls/net.h>

@class OFString;
@class OFMutableDictionary;
@class MBEDX509Certificate;
@class MBEDCRL;
@class MBEDPKey;
@class MBEDSSL;

@interface MBEDSSLSocket: OFTCPSocket<OFTLSSocket>
{
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
    objmbed_ssl_version_t _sslVersion;
    mbedtls_x509_crt_profile _certificateProfile;


    MBEDX509Certificate* _peerCertificate;

@protected
    bool _isSSLServer;

    OFMutableDictionary* _SNIHostPKeys;
    OFMutableDictionary* _SNIHostPKPasswords;
    OFMutableDictionary* _SNIHostCertificates;
}

@property OF_NULLABLE_PROPERTY (retain, readwrite)MBEDSSLConfig* config;
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
