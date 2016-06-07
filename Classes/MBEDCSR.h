#import <ObjFW/OFObject.h>
#import "macros.h"
#import "X509Object.h"

#include "mbedtls/x509_csr.h"

@class OFString;
@class OFDictionary;
@class OFDataArray;
@class MBEDPKey;


@interface MBEDCSR: X509Object
{
	mbedtls_x509_csr _context;
	uint8_t _version;
	OFDictionary* _subject;
	OFString* _signatureAlgorithm;
	OFString* _keyName;
	size_t _keySize;
@protected
	bool _parsed;

}

@property (assign, readonly)mbedtls_x509_csr *context;

@property (assign, readonly)uint8_t version;

@property (copy, readonly)OFDictionary* subject;

@property (copy, readonly)OFString* signatureAlgorithm;

@property (copy, readonly)OFString* keyName;

@property (assign, readonly)size_t keySize;

+ (instancetype)csrWithDER:(OFDataArray *)der;
+ (instancetype)csrWithPEM:(OFString *)pem;

- (instancetype)initWithDER:(OFDataArray *)der;
- (instancetype)initWithPEM:(OFString *)pem;

- (MBEDPKey *)publicKey;

@end