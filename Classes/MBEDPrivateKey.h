#import <ObjFW/OFObject.h>

#include <mbedtls/pk.h>

@class OFString;

@interface MBEDPrivateKey: OFObject
{
	mbedtls_pk_context _context;
	mbedtls_pk_type_t _type;
}

@property(assign, readonly)mbedtls_pk_context* context;
@property(assign, readonly)mbedtls_pk_type_t type;

- (void)parseFile:(OFString *)file password:(OFString *)password;
- (void)parseFile:(OFString *)file password:(OFString *)password tyupe:(mbedtls_pk_type_t)type;
- (instancetype)initWithFile:(OFString *)file;

@end