#import <ObjFW/OFObject.h>
#import "macros.h"
#import "X509Object.h"

#include <mbedtls/pk.h>

@class OFString;
@class OFDataArray;

@interface MBEDPKey: X509Object
{
	mbedtls_pk_context _context;
	mbedtls_pk_type_t _type;
	bool _isPublic;
	OFString *_name;
}

@property(assign, readonly)mbedtls_pk_context* context;
@property(assign, readonly)mbedtls_pk_type_t type;
@property(assign, readonly)bool isPublic;
@property(copy, readonly)OFString* name;


- (void)parsePrivateKeyFile:(OFString *)file password:(OFString *)password;
- (void)parsePublicKeyFile:(OFString *)file;
- (instancetype)initWithPublicKeyFile:(OFString *)file;
- (instancetype)initWithPrivateKeyFile:(OFString *)file password:(OFString *)password;
- (instancetype)initWithPEM:(OFString *)pem password:(OFString *)password isPublic:(bool)flag;
- (instancetype)initWithDER:(OFDataArray *)der password:(OFString *)password isPublic:(bool)flag;

+ (instancetype)keyWithPublicKeyFile:(OFString *)file;
+ (instancetype)keyWithPrivateKeyFile:(OFString *)file password:(OFString *)password;
+ (instancetype)keyWithPEM:(OFString *)pem password:(OFString *)password isPublic:(bool)flag;
+ (instancetype)keyWithDER:(OFDataArray *)der password:(OFString *)password isPublic:(bool)flag;
+ (instancetype)key;

@end