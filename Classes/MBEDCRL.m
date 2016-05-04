#import <ObjFW/ObjFW.h>
#import "MBEDCRL.h"

@interface MBEDCRL()

@end

@implementation MBEDCRL

@dynamic context;

+ (instancetype)crl
{
	return [[[self alloc] init] autorelease];
}

- (instancetype)init
{
	self = [super init];

	mbedtls_x509_crl_init(self.context);

	return self;
}

- (void)dealloc
{
	mbedtls_x509_crl_free(self.context);
	[super dealloc];
}

- (mbedtls_x509_crl *)context
{
	return &_context;
}

- (instancetype)initWithFile:(OFString *)file
{
	self = [self init];

	@try {
		[self parseFile:file];
	}@catch(OFException* e) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDCRL class]];
	}
}

- (void)parseFile:(OFString *)file
{
	if ( (mbedtls_x509_crl_parse_file(self.context, [file UTF8String]) ) != 0) {
		@throw [OFInvalidArgumentException exception];
	}
}

@end