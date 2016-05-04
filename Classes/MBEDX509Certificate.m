#import <ObjFW/ObjFW.h>
#import "MBEDX509Certificate.h"


@interface MBEDX509Certificate()

@property(copy, readwrite)OFString* issuer;
@property(copy, readwrite)OFString* subject;
@property(copy, readwrite)OFString* subjectAlternativeNames;

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
	void* pool = objc_autoreleasePoolPush();

	memcpy(self.certificate, crt, sizeof(mbedtls_x509_crt));

	size_t bufSize = sizeof(char) * 1024;
	int ret = 0;
	char* buf = (char *)__builtin_alloca(bufSize);
	memset(buf, 0, bufSize);

	ret = mbedtls_x509_dn_gets(buf, bufSize, self.certificate->issuer);
	if (ret > 0)
		self.issuer = [OFString stringWithUTF8String:buf length:ret];
	else {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}

	memset(buf, 0, bufSize);

	ret = mbedtls_x509_dn_gets(buf, bufSize, self.certificate->subject);
	if (ret > 0)
		self.subject = [OFString stringWithUTF8String:buf length:ret];
	else {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}

	memset(buf, 0, bufSize);

	if ((x509_info_subject_alt_name(&buf, &bufSize, self.certificate->subject_alt_names)) != 0) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}

	self.subjectAlternativeNames = [OFString stringWithUTF8String:buf length:bufSize];

	objc_autoreleasePoolPop(pool);

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