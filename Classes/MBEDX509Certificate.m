#import <ObjFW/ObjFW.h>
#import "MBEDX509Certificate.h"


@interface MBEDX509Certificate()

@end


@implementation MBEDX509Certificate

@dynamic certificate;

+ (instancetype)certificate
{
	return [[[self alloc] init] autorelease];
}

+ (instancetype)certificateWithFile:(OFString *)file
{
	return [[[self alloc] initWithFile:file] autorelease];
}

+ (instancetype)certificateWithFilesAtPath:(OFString *)path
{
	return [[[self alloc] initWithFilesAtPath:path] autorelease];
}

+ (instancetype)certificateWithX509Struct:(mbedtls_x509_crt *)crt
{
	return [[[self alloc] initWithX509Struct:crt] autorelease];
}

- (instancetype)init
{
	self = [super init];

	mbedtls_x509_crt_init(self.certificate);

	return self;
}

- (void)dealloc
{
	mbedtls_x509_crt_free(self.certificate);
	[super dealloc];
}

- (instancetype)initWithFile:(OFString *)file
{
	self = [self init];

	@try {
		[self parseFile:file];
	}@catch(OFException* e) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}

	return self;
}

- (instancetype)initWithFilesAtPath:(OFString *)path
{
	self = [self init];
	@try {
		[self parseFilesAtPath:path];
	}@catch(OFException* e) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}
	return self;
}

- (instancetype)initWithX509Struct:(mbedtls_x509_crt *)crt
{
	self = [self init];

	memcpy(self.certificate, crt, sizeof(mbedtls_x509_crt));

	return self;
}

- (void)parseFilesAtPath:(OFString *)path
{
	if ( (mbedtls_x509_crt_parse_path(self.certificate, [path UTF8String])) != 0) {
		@throw [OFInvalidArgumentException exception];
	}
}

- (void)parseFile:(OFString *)file
{
	if ( (mbedtls_x509_crt_parse_file(self.certificate, [file UTF8String])) != 0) {
		[self release];
		@throw [OFInvalidArgumentException exception];;
	}
}

- (mbedtls_x509_crt *)certificate
{
	return &_certificate;
}

@end