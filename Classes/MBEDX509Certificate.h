#import <ObjFW/OFObject.h>

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/certs.h>

@class OFString;
@class OFDictionary;
@class OFArray;
@class OFNumber;
@class OFDate;

@interface MBEDX509Certificate: OFObject
{
	mbedtls_x509_crt _certificate;
	OFDictionary *_issuer;
	OFDictionary *_subject;
	OFDictionary *_subjectAlternativeNames;
	uint8_t _version;
	OFString *_signatureAlgorithm;
	OFDate *_issued;
	OFDate *_expires;
	int _keySize;
	OFString *_type;

}

@property(assign, readonly)mbedtls_x509_crt* certificate;
@property(copy, readonly)OFDictionary* issuer;
@property(copy, readonly)OFDictionary* subject;
@property(copy, readonly)OFDictionary* subjectAlternativeNames;
@property(assign, readonly)uint8_t version;
@property(copy, readonly)OFString* signatureAlgorithm;
@property(copy, readonly)OFDate* issued;
@property(copy, readonly)OFDate* expires;
@property(assign, readonly)int keySize;
@property(copy, readonly)OFString* type;

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
