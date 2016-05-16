#import <ObjFW/ObjFW.h>
#import "MBEDX509Certificate.h"
#import "SSLCertificateVerificationFailedException.h"

@interface SSLCertificateVerificationFailedException()

@property(retain, readwrite)MBEDX509Certificate* certificate;
@property(assign, readwrite)uint32_t verifyCodes;

@end


@implementation SSLCertificateVerificationFailedException

@synthesize certificate = _certificate;
@synthesize verifyCodes = _verifyCodes;

- (instancetype)initWithCode:(uint32_t)codes certificate:(MBEDX509Certificate *)crt
{
	self = [super init];

	self.verifyCodes = codes;
	self.certificate = crt;

	return self;
}

- (void)dealloc
{
	[_certificate release];
	[super dealloc];
}

+ (instancetype)exceptionWithCode:(uint32_t)codes certificate:(MBEDX509Certificate *)crt
{
	return [[[self alloc] initWithCode:codes certificate:crt] autorelease];
}

- (OFString *)description
{
	OFMutableString* desc = [OFMutableString stringWithUTF8String:"Certificate verification failed: "];

	char buf[4096];

	int ret = mbedtls_x509_crt_verify_info(buf, 1024, "", _verifyCodes);

	if (ret > 0)
		[desc appendUTF8String:buf];
	else
		[desc appendUTF8String:"Unknown!"];

	[desc appendString:@"!"];

	[desc makeImmutable];

	return desc;
}

@end