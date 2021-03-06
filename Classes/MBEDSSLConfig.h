#import <ObjFW/OFObject.h>
#import "macros.h"

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

@class OFString;
@class OFDataArray;
@class OFDictionary;
@class MBEDX509Certificate;
@class MBEDCRL;
@class MBEDPKey;

OBJMBEDTLS_EXPORT const mbedtls_x509_crt_profile kDefaultProfile;
OBJMBEDTLS_EXPORT const mbedtls_x509_crt_profile kNextDefaultProfile;
OBJMBEDTLS_EXPORT const mbedtls_x509_crt_profile kNSASuiteBProfile;

typedef enum {
	OBJMBED_SSLVERSION_TLSv1 = 0,
	OBJMBED_SSLVERSION_SSLv3,
	OBJMBED_SSLVERSION_TLSv1_0,
	OBJMBED_SSLVERSION_TLSv1_1,
	OBJMBED_SSLVERSION_TLSv1_2

}objmbed_ssl_version_t;


@interface MBEDSSLConfig: OFObject
{
	mbedtls_ssl_config _context;

	MBEDX509Certificate* _CA;
    MBEDCRL* _CRL;
    MBEDPKey* _PK;
    MBEDX509Certificate* _ownCertificate;
}

@property (assign, readonly)mbedtls_ssl_config *context;

@property OF_NULLABLE_PROPERTY (retain, readwrite)MBEDX509Certificate* CA;
@property OF_NULLABLE_PROPERTY (retain, readwrite)MBEDCRL* CRL;
@property OF_NULLABLE_PROPERTY (retain, readwrite)MBEDPKey* PK;
@property OF_NULLABLE_PROPERTY (retain, readwrite)MBEDX509Certificate* ownCertificate;

+ (instancetype)configForTCPServer;
+ (instancetype)configForTCPClient;
+ (instancetype)configForTCPServerWithPeerCertificateVerification;
+ (instancetype)configForTCPClientWithPeerCertificateVerification;

- (instancetype)initTCPServerConfig;
- (instancetype)initTCPClientConfig;
- (instancetype)initTCPServerConfigWithPeerCertificateVerification;
- (instancetype)initTCPClientConfigWithPeerCertificateVerification;
- (instancetype)initWithEndpoint:(int)endpoint transport:(int)transport preset:(int)preset authMode:(int)mode;

- (void)setCertificateProfile:(const mbedtls_x509_crt_profile)profile;
- (void)setValidSSLVersion:(objmbed_ssl_version_t)version;
- (void)setCertificateAuthorityChain:(MBEDX509Certificate *)CA;
- (void)setCertificateAuthorityChain:(MBEDX509Certificate *)CA withCRL:(MBEDCRL *)crl;
- (void)setOwnCertificate:(MBEDX509Certificate *)crt withPrivateKey:(MBEDPKey *)prv;


@end