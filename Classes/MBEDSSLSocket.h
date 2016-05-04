#import <ObjFW/OFObject.h>
#import <ObjFW/OFTCPSocket.h>
#import <ObjFW/OFTLSSocket.h>
#import <ObjFW/OFException.h>

#include <mbedtls/net.h>

@class OFString;
@class MBEDX509Certificate;
@class MBEDCRL;
@class MBEDPrivateKey;
@class MBEDSSL;

@interface MBEDSSLSocket: OFTCPSocket<OFTLSSocket>
{
    MBEDX509Certificate* _CA;
    MBEDX509Certificate* _clientCertificate;
    MBEDCRL* _CRL;
    MBEDPrivateKey* _PK;
    MBEDSSL* _SSL;

    mbedtls_net_context _context;

    id<OFTLSSocketDelegate> _delegate;
    OFString* _certificateFile;
    OFString* _privateKeyFile;
    const char *_privateKeyPassphrase;
    bool _certificateVerificationEnabled;
}

@property (retain, readwrite)MBEDX509Certificate* CA;
@property (retain, readwrite)MBEDCRL* CRL;
@property (retain, readwrite)MBEDX509Certificate* clientCertificate;
@property (retain, readwrite)MBEDPrivateKey* PK;

@property (assign, readonly)mbedtls_net_context* context;

@property OF_NULLABLE_PROPERTY (assign) id <OFTLSSocketDelegate> delegate;
@property OF_NULLABLE_PROPERTY (copy) OFString *certificateFile;
@property OF_NULLABLE_PROPERTY (copy) OFString *privateKeyFile;
@property OF_NULLABLE_PROPERTY (assign) const char *privateKeyPassphrase;
@property (getter=isCertificateVerificationEnabled)bool certificateVerificationEnabled;

- (instancetype)initWithSocket:(OFTCPSocket*)socket;
- (void)startTLSWithExpectedHost:(nullable OFString*)host;
- (void)setCertificateFile:(OFString*)certificateFile forSNIHost:(OFString*)SNIHost;
- (nullable OFString*)certificateFileForSNIHost:(OFString*)SNIHost;
- (void)setPrivateKeyFile:(OFString*)privateKeyFile forSNIHost:(OFString*)SNIHost;
- (nullable OFString*)privateKeyFileForSNIHost:(OFString*)SNIHost;
- (void)setPrivateKeyPassphrase:(const char*)privateKeyPassphrase forSNIHost:(OFString*)SNIHost;
- (nullable const char*)privateKeyPassphraseForSNIHost:(OFString*)SNIHost;
- (MBEDX509Certificate *)peerCertificate;

@end

@interface MBEDSSLCertificationAuthorityMissingException: OFException
{
    MBEDSSLSocket* _socket;
}

@property(retain, readonly)MBEDSSLSocket* socket;

- (instancetype)initWithSocket:(MBEDSSLSocket *)socket;
+ (instancetype)exceptionWithSocket:(MBEDSSLSocket *)socket;

@end