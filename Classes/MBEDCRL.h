#import <ObjFW/OFObject.h>
#import "macros.h"
#import "X509Object.h"

#include <mbedtls/x509.h>
#include <mbedtls/x509_crl.h>

@class OFString;
@class OFDictionary;
@class OFDate;
@class OFArray;
@class OFDataArray;

OBJMBEDTLS_EXPORT OFString *const kRCSerialNumber;
OBJMBEDTLS_EXPORT OFString *const kRCRevocationDate;

@interface MBEDCRL: X509Object<X509ObjectsChain>
{
	mbedtls_x509_crl _context;
	uint8_t _version;
	OFDictionary *_issuer;
	OFDate *_thisUpdate;
	OFDate *_nextUpdate;
	OFArray *_revokedCertificates;
	OFString *_signatureAlgorithm;
	bool _parsed;
}

@property(assign, readonly)mbedtls_x509_crl* context;
@property(assign, readonly)uint8_t version;
@property(copy, readonly)OFDictionary* issuer;
@property(copy, readonly)OFDate* thisUpdate;
@property(copy, readonly)OFDate* nextUpdate;
@property(copy, readonly)OFArray* revokedCertificates;
@property(copy, readonly)OFString* signatureAlgorithm;

+ (instancetype)crl;
+ (instancetype)crlWithPEM:(OFString *)pem;
+ (instancetype)crlWithDER:(OFDataArray *)der;
+ (instancetype)crlWithFile:(OFString *)file;
+ (instancetype)crlWithFilesAtPath:(OFString *)path;
- (instancetype)initWithFile:(OFString *)file;
- (instancetype)initWithFilesAtPath:(OFString *)path;
- (instancetype)initWithPEM:(OFString *)pem;
- (instancetype)initWithDER:(OFDataArray *)der;

#if defined(OF_WINDOWS) || defined(OF_LINUX) || defined(OF_MAC_OS_X)
- (instancetype)initWithSystemCRL;
+ (instancetype)crlWithSystemCRL;
#endif

@end;