#import <ObjFW/OFObject.h>

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/certs.h>

@class OFString;

@interface MBEDX509Certificate: OFObject
{
	mbedtls_x509_crt _certificate;
}

@property(assign, readonly)mbedtls_x509_crt* certificate;

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
