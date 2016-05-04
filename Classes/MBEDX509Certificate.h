#import <ObjFW/OFObject.h>

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/certs.h>

@class OFString;
@class OFDictionary;
@class OFArray;

@interface MBEDX509Certificate: OFObject
{
	mbedtls_x509_crt _certificate;
	OFString *_issuer;
	OFString *_subject;
	OFString *_subjectAlternativeNames;
}

@property(assign, readonly)mbedtls_x509_crt* certificate;
@property(copy, readonly)OFString* issuer;
@property(copy, readonly)OFString* subject;
@property(copy, readonly)OFString* subjectAlternativeNames;

+ (instancetype)certificate;
+ (instancetype)certificateWithFile:(OFString *)file;
+ (instancetype)certificateWithFilesAtPath:(OFString *)path;
+ (instancetype)certificateWithX509Struct:(mbedtls_x509_crt *)crt;
- (instancetype)initWithFile:(OFString *)file;
- (instancetype)initWithFilesAtPath:(OFString *)path;
- (instancetype)initWithX509Struct:(mbedtls_x509_crt *)crt;
- (void)parseFilesAtPath:(OFString *)path;
- (void)parseFile:(OFString *)file;

@end
