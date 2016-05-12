#import <ObjFW/OFObject.h>
#import <ObjFW/OFTLSSocket.h>
#import <ObjFW/OFException.h>

#import "macros.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

@class OFString;
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


@interface MBEDSSL: OFObject
{
	mbedtls_entropy_context _entropy;
    mbedtls_ctr_drbg_context _ctr_drbg;
    mbedtls_ssl_context _ssl;
    mbedtls_ssl_config _conf;
    bool _configured;
    OFString* _cipherSuite;
}

@property(assign, readonly)mbedtls_ssl_context* context;
@property(assign, readonly)mbedtls_ssl_config* config;
@property(assign, readonly)mbedtls_ctr_drbg_context* ctr_drbg;
@property(assign, readonly)mbedtls_entropy_context* entropy;
@property(copy, readonly)OFString* cipherSuite;

+ (instancetype)ssl;
- (instancetype)initWithConfig:(mbedtls_ssl_config *)config;

- (void)setDefaultConfigEndpoint:(int)endpoint transport:(int)transport preset:(int)preset;
- (void)setDefaultTCPClientConfig;
- (void)setDefaultTCPServerConfig;
- (void)setCertificateProfile:(const mbedtls_x509_crt_profile)profile;
- (void)setConfigSSLVersion:(objmbed_ssl_version_t)version;
- (void)configureBIOSocket:(id<OFTLSSocket>)socket;
- (void)configureCAChainForSocket:(id<OFTLSSocket>)socket;
- (void)setChainForCA:(MBEDX509Certificate *)ca withCRL:(MBEDCRL *)crl;
- (void)configureOwnCertificateForSocket:(id<OFTLSSocket>)socket;
- (void)ownCertificate:(MBEDX509Certificate *)crt privateKey:(MBEDPKey *)pk;
- (void)setHostName:(OFString *)host;
- (void)configureALPN;
- (void)handshake;
- (uint32_t)peerCertificateVerified;
- (const mbedtls_x509_crt *)peerCertificate;
- (void)writeBuffer:(const void*)buffer length:(size_t)length;
- (ssize_t)readIntoBuffer:(void*)buffer length:(size_t)length;
- (void)notifyPeerToClose;
- (void)resetSession;
- (size_t)bytesAvailable;

@end


@interface MBEDSSLCertificateVerificationFailedException: OFException
{
	uint32_t _verifyCodes;
	MBEDX509Certificate* _certificate;
}

@property(retain, readonly)MBEDX509Certificate* certificate;
@property(assign, readonly)uint32_t verifyCodes;

- (instancetype)initWithCode:(uint32_t)codes certificate:(MBEDX509Certificate *)crt;
+ (instancetype)exceptionWithCode:(uint32_t)codes certificate:(MBEDX509Certificate *)crt;

@end