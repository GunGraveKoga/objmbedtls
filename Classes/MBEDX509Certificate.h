#import <ObjFW/OFObject.h>
#import "X509Object.h"
#import "macros.h"

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

OBJMBEDTLS_EXPORT OFString *const kMozillaCARootCertificates;

/*!
 * @class MBEDX509Certificate \
 *	  MBEDX509Certificate.h \
 *	  ObjMBEDTLS/MBEDX509Certificate.h
 *
 * @brief X509 certificate with DER & PEM support.
 */

@interface MBEDX509Certificate: X509Object <X509ObjectsChain>
{
	mbedtls_x509_crt _certificate;
	OFDictionary *_issuer;
	OFDictionary *_subject;
	OFDictionary *_subjectAlternativeNames;
	uint8_t _version;
	OFString *_signatureAlgorithm;
	OFString* _MDAlgorithm;
	OFString* _PKAlgorithm;
	OFDate *_issued;
	OFDate *_expires;
	int _keySize;
	OFString *_type;
	bool _isCA;
	size_t _maxPathLength;
	OFArray *_keyUsage;
	OFArray *_extendedKeyUsage;
	OFString *_serialNumber;
	OFDataArray *_signature;
	
@protected
	bool _parsed;

}

/*!
 * mbedtls certificate handler.
 */
@property(assign, readonly)mbedtls_x509_crt* context;

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
* Internal representation of the MD algorithm of the signature algorithm
*/
@property(copy, readonly)OFString* MDAlgorithm;

/*!
* Internal representation of the Public Key algorithm of the signature algorithm
*/
@property(copy, readonly)OFString* PKAlgorithm;

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


@property(copy, readonly)OFDataArray* signature;

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


+ (instancetype)certificateWithPEM:(OFString *)pem;


+ (instancetype)certificateWithDER:(OFDataArray *)der;


- (instancetype)initWithFile:(OFString *)file;


- (instancetype)initWithFilesAtPath:(OFString *)path;


- (instancetype)initWithDER:(OFDataArray *)der;


- (instancetype)initWithPEM:(OFString *)pem;


- (bool)hasCommonNameMatchingDomain: (OFString*)domain;


- (bool)hasDNSNameMatchingDomain: (OFString*)domain;


- (bool)hasSRVNameMatchingDomain: (OFString*)domain service: (OFString*)service;

- (bool)isRevoked:(MBEDCRL*)crl;

/*!
 * Public key of certificate.
 */
- (MBEDPKey *)publicKey;

#if defined(OF_WINDOWS) || defined(OF_LINUX) || defined(OF_MAC_OS_X)
- (instancetype)initWithSystemCA;

+ (instancetype)certificateWithSystemCA;
#endif

@end
