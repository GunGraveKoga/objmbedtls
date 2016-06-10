#import <ObjFW/ObjFW.h>
#import "MBEDTLSException.h"
#import "MBEDInitializationFailedException.h"
#import "MBEDEntropy.h"

static MBEDEntropy* __default_entropy = nil;
static OFString* __default_personalization_data = nil;

@interface MBEDEntropy()

@property(copy, readwrite)OFString* personalizationData;

- (void)seed;

@end


@implementation MBEDEntropy

@dynamic entropy;
@dynamic ctr_drbg;
@synthesize personalizationData = _personalizationData;

+ (void)load 
{
	mbedtls_threading_set_alt(objfw_mbedtls_mutex_init, objfw_mbedtls_mutex_free, objfw_mbedtls_mutex_lock, objfw_mbedtls_mutex_unlock);
}

+ (void)initialize
{
	if (self == [MBEDEntropy class]) {
		__default_entropy = [MBEDEntropy new];

		if (nil == __default_personalization_data) {
			OFDate* dt = [[OFDate alloc] initWithTimeIntervalSinceNow:0.0];
			__default_entropy->_personalizationData = [[OFString alloc] initWithFormat:@"%@%p%@", [__default_entropy className], __default_entropy, dt];
			[dt release];

		} else {
			__default_entropy->_personalizationData = [__default_personalization_data copy];
		}

		[__default_entropy seed];
	}
}

- (instancetype)init
{
	self = [super init];

	mbedtls_entropy_init(self.entropy);
	mbedtls_ctr_drbg_init(self.ctr_drbg);

	self.personalizationData = nil;

	return self;
}

- (void)seed
{
	int ret = 0;

	if ((ret = mbedtls_ctr_drbg_seed(self.ctr_drbg, mbedtls_entropy_func, self.entropy, (const unsigned char *)[self.personalizationData UTF8String], [self.personalizationData UTF8StringLength])) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
}

- (void)dealloc
{
	mbedtls_ctr_drbg_free( self.ctr_drbg );
    mbedtls_entropy_free( self.entropy );
    [_personalizationData release];
    [super dealloc];
}

+ (instancetype)defaultEntropy
{
	return __default_entropy;
}

+ (instancetype)entropyWithPersonalization:(OFString *)pers
{
	MBEDEntropy* res = [[self alloc] init];

	res.personalizationData = pers;

	[res seed];

	return [res autorelease];
}

+ (void)setDefaultPersonalization:(OFString *)pers
{
	__default_personalization_data = [pers copy];
}

- (mbedtls_entropy_context *)entropy
{
	return &_entropy;
}
- (mbedtls_ctr_drbg_context *)ctr_drbg
{
	return &_ctr_drbg;
}

@end