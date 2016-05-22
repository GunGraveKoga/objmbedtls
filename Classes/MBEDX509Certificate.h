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
@class MBEDPKey;
@class MBEDCRL;

/*!
 * @class MBEDX509Certificate \
 *	  MBEDX509Certificate.h \
 *	  ObjMBEDTLS/MBEDX509Certificate.h
 *
 * @brief X509 certificate with DER & PEM support.
 */

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
	MBEDPKey *_PK;

}

/*!
 * mbedtls certificate handler.
 */
@property(assign, readonly)mbedtls_x509_crt* certificate;

/*!
 * Certificate issuer field.
 */
@property(copy, readonly)OFDictionary* issuer;

/*!
 * Certificate subject field.
 */
@property(copy, readonly)OFDictionary* subject;

/*!
 * List of alternatice certificate`s subject names (dNSName support only).
 */
@property(copy, readonly)OFDictionary* subjectAlternativeNames;

/*!
 * Certificate version.
 */
@property(assign, readonly)uint8_t version;

/*!
 * Signature algorithm description.
 */
@property(copy, readonly)OFString* signatureAlgorithm;

/*!
 * Certificate issued date.
 */
@property(copy, readonly)OFDate* issued;

/*!
 * Certificate expires date.
 */
@property(copy, readonly)OFDate* expires;

/*!
 * Certificate private key size in bits.
 */
@property(assign, readonly)int keySize;

/*!
 * Certificate type.
 */
@property(copy, readonly)OFString* type;

/*!
 * Certificate Basic constraints extension of certificate (The issued certificate is for a Certificate Authority, i.e. an intermediate CA).
 */
@property(assign, readonly)bool isCA;

/*!
 * Max path length.
 */
@property(assign, readonly)size_t maxPathLength;

/*!
 * Key usage.
 */
@property(copy, readonly)OFArray* keyUsage;

/*!
 * Extended key usage.
 */
@property(copy, readonly)OFArray* extendedKeyUsage;

/*!
 * Serial number.
 */
@property(copy, readonly)OFString* serialNumber;

/*!
 * Public key.
 */
@property(copy, readonly)MBEDPKey* PK;

/*!
 * @brief Creates a new, autoreleased initialization MBEDX509Certificate instance.
 *
 * @return A new, autoreleased initialization MBEDX509Certificate instance
 */
+ (instancetype)certificate;

/*!
 * @brief Creates a new, autoreleased initialization MBEDX509Certificate instance.
 *
 * @param file The path to certificate file in DER or PEM format
 * @return A new, autoreleased initialization MBEDX509Certificate instance
 */
+ (instancetype)certificateWithFile:(OFString *)file;


+ (instancetype)certificateWithFilesAtPath:(OFString *)path;


+ (instancetype)certificateWithX509Struct:(mbedtls_x509_crt *)crt;


+ (instancetype)certificatesWithData:(OFDataArray *)data;


+ (instancetype)certificateWithDERData:(OFDataArray *)data;


- (instancetype)initWithFile:(OFString *)file;


- (instancetype)initWithFilesAtPath:(OFString *)path;


- (instancetype)initWithX509Struct:(mbedtls_x509_crt *)crt;


- (instancetype)initWithCertificatesData:(OFDataArray *)data;


- (instancetype)initWithCertificateDERData:(OFDataArray *)data;


- (void)parseFilesAtPath:(OFString *)path;


- (void)parseFile:(OFString *)file;


- (bool)hasCommonNameMatchingDomain: (OFString*)domain;


- (bool)hasDNSNameMatchingDomain: (OFString*)domain;


- (bool)hasSRVNameMatchingDomain: (OFString*)domain service: (OFString*)service;


- (MBEDX509Certificate *)next;

- (bool)isRevoked:(MBEDCRL*)crl;

- (OFDataArray *)DER;

- (OFString *)PEM;

- (OFString *)PEMwithHeader:(OFString *)header bottom:(OFString *)bottom;

@end
