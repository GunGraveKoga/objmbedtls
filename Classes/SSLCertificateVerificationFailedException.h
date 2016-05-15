#import <ObjFW/OFObject.h>
#import <ObjFW/OFException.h>

@class MBEDX509Certificate;

@interface SSLCertificateVerificationFailedException: OFException
{
	uint32_t _verifyCodes;
	MBEDX509Certificate* _certificate;
}

@property(retain, readonly)MBEDX509Certificate* certificate;
@property(assign, readonly)uint32_t verifyCodes;

- (instancetype)initWithCode:(uint32_t)codes certificate:(MBEDX509Certificate *)crt;
+ (instancetype)exceptionWithCode:(uint32_t)codes certificate:(MBEDX509Certificate *)crt;

@end