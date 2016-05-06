#import <ObjFW/OFObject.h>

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/certs.h>

@class OFString;
@class OFDictionary;
@class OFArray;
@class OFNumber;
@class OFDate;
@class OFDataArray;

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
	bool _isCA;
	size_t _maxPathLength;
	OFArray *_keyUsage;
	OFArray *_extendedKeyUsage;
	OFString *_serialNumber;
	OFDataArray *_publicKey;
	OFString *_publicKeyPEM;

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
@property(assign, readonly)bool isCA;
@property(assign, readonly)size_t maxPathLength;
@property(copy, readonly)OFArray* keyUsage;
@property(copy, readonly)OFArray* extendedKeyUsage;
@property(copy, readonly)OFString* serialNumber;
@property(copy, readonly)OFDataArray* publicKey;
@property(copy, readonly)OFString* publicKeyPEM;

+ (instancetype)certificate;
+ (instancetype)certificateWithFile:(OFString *)file;
+ (instancetype)certificateWithFilesAtPath:(OFString *)path;
+ (instancetype)certificateWithX509Struct:(mbedtls_x509_crt *)crt;
- (instancetype)initWithFile:(OFString *)file;
- (instancetype)initWithFilesAtPath:(OFString *)path;
- (instancetype)initWithX509Struct:(mbedtls_x509_crt *)crt;
- (void)parseFilesAtPath:(OFString *)path;
- (void)parseFile:(OFString *)file;
- (bool)hasCommonNameMatchingDomain: (OFString*)domain;
- (bool)hasDNSNameMatchingDomain: (OFString*)domain;
- (bool)hasSRVNameMatchingDomain: (OFString*)domain service: (OFString*)service;

@end
