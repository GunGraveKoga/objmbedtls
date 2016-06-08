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
}

@property (assign, readonly)mbedtls_ssl_config *context;

+ (instancetype)configForTCPServer;
+ (instancetype)configForTCPClient;
+ (instancetype)configForTCPServerWithClientCertificateRequest;

- (instancetype)initWithTCPServerConfig;
- (instancetype)initWithTCPClientConfig;
- (instancetype)initWithTCPServerConfigClientCertificateRequired;
- (instancetype)initWithEndpoint:(int)endpoint transport:(int)transport preset:(int)preset authMode:(int)mode;

- (void)setCertificateProfile:(const mbedtls_x509_crt_profile)profile;
- (void)setValidSSLVersion:(objmbed_ssl_version_t)version;
- (void)setCertificateAuthorityChain:(MBEDX509Certificate *)CA;
- (void)setCertificateAuthorityChain:(MBEDX509Certificate *)CA withCRL:(MBEDCRL *)crl;
- (void)setOwnCertificate:(MBEDX509Certificate *)crt withPrivateKey:(MBEDPKey *)prv;


@end