#import <ObjFW/OFObject.h>

#include <mbedtls/x509.h>
#include <mbedtls/x509_crl.h>

@class OFString;

@interface MBEDCRL: OFObject
{
	mbedtls_x509_crl _context;
}

@property(assign, readonly)mbedtls_x509_crl* context;

+ (instancetype)crl;
- (instancetype)initWithFile:(OFString *)file;
- (void)parseFile:(OFString *)file;

@end;