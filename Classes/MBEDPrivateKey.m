#import <ObjFW/ObjFW.h>
#import "MBEDPrivateKey.h"

@interface MBEDPrivateKey()

@property(assign, readwrite)mbedtls_pk_type_t type;

@end


@implementation MBEDPrivateKey

@synthesize type = _type;
@dynamic context;

- (instancetype)init
{
	self = [super init];

	mbedtls_pk_init(self.context);
	self.type = MBEDTLS_PK_NONE;

	return self;
}

- (void)dealloc
{
	mbedtls_pk_free(self.context);
	[super dealloc];
}

- (void)parseFile:(OFString *)file password:(OFString *)password
{
	if ( (mbedtls_pk_parse_keyfile(self.context, [file UTF8String], (password == nil) ? NULL : [password UTF8String])) != 0) {
		@throw [OFInvalidArgumentException exception];
	}

	if (self.type != MBEDTLS_PK_NONE) {
		if (!mbedtls_pk_can_do(self.context, self.type)) {
			@throw [OFInvalidArgumentException exception];
		}
	} else {
		self.type = mbedtls_pk_get_type( (const mbedtls_pk_context *)self.context );
	}
}

- (void)parseFile:(OFString *)file password:(OFString *)password tyupe:(mbedtls_pk_type_t)type
{
	self.type = type;
	[self parseFile:file password:password];
}

- (mbedtls_pk_context *)context
{
	return &_context;
}


@end