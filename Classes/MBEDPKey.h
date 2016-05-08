#import <ObjFW/OFObject.h>

#include <mbedtls/pk.h>

@class OFString;
@class OFDataArray;

@interface MBEDPKey: OFObject
{
	mbedtls_pk_context _context;
	mbedtls_pk_type_t _type;
	bool _isPublic;
	OFString *_PEM;
	OFDataArray *_DER;
	OFString *_name;
}

@property(assign, readonly)mbedtls_pk_context* context;
@property(assign, readonly)mbedtls_pk_type_t type;
@property(assign, readonly)bool isPublic;
@property OF_NULLABLE_PROPERTY (copy, readonly)OFDataArray* DER;
@property OF_NULLABLE_PROPERTY (copy, readonly)OFString* PEM;
@property(copy, readonly)OFString* name;

- (void)parseFile:(OFString *)file password:(OFString *)password isPublic:(bool)flag;
- (void)parseFile:(OFString *)file password:(OFString *)password type:(mbedtls_pk_type_t)type isPublic:(bool)flag;
- (void)parsePrivateKeyFile:(OFString *)file password:(OFString *)password;
- (void)parsePublicKeyFile:(OFString *)file;
- (instancetype)initWithPublicKeyFile:(OFString *)file;
- (instancetype)initWithPrivateKeyFile:(OFString *)file password:(OFString *)password;
- (instancetype)initWithFile:(OFString *)file password:(OFString *)password isPublic:(bool)flag;
- (instancetype)initWithPEM:(OFString *)PEMString password:(OFString *)password isPublic:(bool)flag;
- (instancetype)initWithDER:(OFDataArray *)DERData password:(OFString *)password isPublic:(bool)flag;
- (instancetype)initWithStruct:(mbedtls_pk_context *)context isPublic:(bool)flag;

+ (instancetype)keyWithPublicKeyFile:(OFString *)file;
+ (instancetype)keyWithPrivateKeyFile:(OFString *)file password:(OFString *)password;
+ (instancetype)keyWithFile:(OFString *)file password:(OFString *)password isPublic:(bool)flag;
+ (instancetype)keyWithPEM:(OFString *)PEMString password:(OFString *)password isPublic:(bool)flag;
+ (instancetype)keyWithDER:(OFDataArray *)DERData password:(OFString *)password isPublic:(bool)flag;
+ (instancetype)keyWithStruct:(mbedtls_pk_context *)context isPublic:(bool)flag;

@end