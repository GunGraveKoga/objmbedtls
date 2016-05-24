#import <ObjFW/OFObject.h>

#import "macros.h"

#include <mbedtls/x509.h>
#include <mbedtls/x509_crl.h>

@class OFString;
@class OFDictionary;
@class OFDate;
@class OFArray;
@class OFDataArray;

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
+ (instancetype)crlWithPEMString:(OFString *)string;
+ (instancetype)crlWithPEMorDERData:(OFDataArray *)data;
+ (instancetype)crlWithFile:(OFString *)file;
+ (instancetype)crlWithCRLStruct:(mbedtls_x509_crl *)crl;
- (instancetype)initWithCRLStruct:(mbedtls_x509_crl *)crl;
- (instancetype)initWithFile:(OFString *)file;
- (instancetype)initWithPEMString:(OFString *)string;
- (instancetype)initWithPEMorDERData:(OFDataArray *)data;
- (void)parseFile:(OFString *)file;
- (OFDataArray *)DER;
- (OFString *)PEM;
- (OFString *)PEMWithHeader:(OFString *)header bottom:(OFString *)bottom;

#if defined(OF_WINDOWS) || defined(OF_LINUX) || defined(OF_MAC_OS_X)
- (instancetype)initWithSystemCRL;
+ (instancetype)crlWithSystemCRL;
#endif

- (void)parseDER:(OFDataArray *)der;

- (void)parsePEM:(OFString *)pem;

- (MBEDCRL *)next;

@end;