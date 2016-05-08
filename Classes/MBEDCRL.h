#import <ObjFW/OFObject.h>

#import "macros.h"

#include <mbedtls/x509.h>
#include <mbedtls/x509_crl.h>

@class OFString;
@class OFDictionary;
@class OFDate;
@class OFArray;

OBJMBEDTLS_EXPORT OFString *const kRCSerialNumber;
OBJMBEDTLS_EXPORT OFString *const kRCRevocationDate;

@interface MBEDCRL: OFObject
{
	mbedtls_x509_crl _context;
	uint8_t _version;
	OFDictionary *_issuer;
	OFDate *_thisUpdate;
	OFDate *_nextUpdate;
	OFArray *_revokedCertificates;
	OFString *_signatureAlgorithm;
}

@property(assign, readonly)mbedtls_x509_crl* context;
@property(assign, readonly)uint8_t version;
@property(copy, readonly)OFDictionary* issuer;
@property(copy, readonly)OFDate* thisUpdate;
@property(copy, readonly)OFDate* nextUpdate;
@property(copy, readonly)OFArray* revokedCertificates;
@property(copy, readonly)OFString* signatureAlgorithm;

+ (instancetype)crl;
+ (instancetype)crlWithFile:(OFString *)file;
- (instancetype)initWithFile:(OFString *)file;
- (void)parseFile:(OFString *)file;

@end;