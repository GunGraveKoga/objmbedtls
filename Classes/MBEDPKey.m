#import <ObjFW/ObjFW.h>
#import "MBEDPKey.h"
#import "macros.h"

@interface MBEDPKey()

@property(assign, readwrite)mbedtls_pk_type_t type;
@property(assign, readwrite)bool isPublic;
- (OFString *)PKEY_publicKeyPEM;
- (OFString *)PKEY_privateKeyPEM;
- (OFDataArray *)PKEY_publicKeyDER;
- (OFDataArray *)PKEY_privateKeyDER;

@end


@implementation MBEDPKey

@synthesize type = _type;
@synthesize isPublic = _isPublic;
@dynamic context;
@dynamic PEM;
@dynamic DER;
@dynamic name;

- (instancetype)init
{
	self = [super init];

	mbedtls_pk_init(self.context);
	self.type = MBEDTLS_PK_NONE;
	self.isPublic = false;
	_DER = nil;
	_PEM = nil;

	return self;
}

- (void)dealloc
{
	mbedtls_pk_free(self.context);
	[_PEM release];
	[_DER release];
	[_name release];
	[super dealloc];
}

- (OFString *)PEM
{
	if (_PEM == nil) {
		if (self.isPublic)
			_PEM = [self PKEY_publicKeyPEM];
		else
			_PEM = [self PKEY_privateKeyPEM];
	}

	return _PEM;
}

- (OFDataArray *)DER
{
	if (_DER == nil) {
		if (self.isPublic)
			_DER = [self PKEY_publicKeyDER];
		else
			_DER = [self PKEY_privateKeyDER];
	}

	return _DER;
}

- (OFString *)name
{
	if (_name == nil) {
		_name = [[OFString alloc] initWithUTF8String:mbedtls_pk_get_name(self.context)];
	}

	return _name;
}

- (void)parsePrivateKeyFile:(OFString *)file password:(OFString *)password
{
	if (file == nil || [file UTF8StringLength] <= 0)
		@throw [OFInvalidArgumentException exception];

	if ((mbedtls_pk_parse_keyfile(self.context, [file UTF8String], (password == nil) ? NULL : [password UTF8String])) != 0) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDPKey class]];
	}

	if (self.isPublic)
		self.isPublic = false;
}

- (void)parsePublicKeyFile:(OFString *)file
{
	if (file == nil || [file UTF8StringLength] <= 0)
		@throw [OFInvalidArgumentException exception];

	if ((mbedtls_pk_parse_public_keyfile(self.context, [file UTF8String])) != 0) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDPKey class]];
	}

	if (!self.isPublic)
		self.isPublic = true;

}

- (void)parseFile:(OFString *)file password:(OFString *)password isPublic:(bool)flag
{
	if (flag)
		[self parsePublicKeyFile:file];
	else
		[self parsePrivateKeyFile:file password:password];



	if (self.type != MBEDTLS_PK_NONE) {
		if (!mbedtls_pk_can_do(self.context, self.type)) {
			@throw [OFInvalidArgumentException exception];
		}
	} else {
		self.type = mbedtls_pk_get_type( (const mbedtls_pk_context *)self.context );
	}
}

- (void)parseFile:(OFString *)file password:(OFString *)password type:(mbedtls_pk_type_t)type isPublic:(bool)flag
{
	self.type = type;
	[self parseFile:file password:password isPublic:flag];
}

- (mbedtls_pk_context *)context
{
	return &_context;
}

- (instancetype)initWithFile:(OFString *)file password:(OFString *)password isPublic:(bool)flag
{
	self = [self init];

	@try {
		[self parseFile:file password:password isPublic:flag];
	} @catch(id e) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDPKey class]];
	}

	return self;
}

- (instancetype)initWithPublicKeyFile:(OFString *)file
{
	self = [self init];

	@try {
		[self parsePublicKeyFile:file];
	} @catch(id e) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDPKey class]];
	}

	return self;
}

- (instancetype)initWithPrivateKeyFile:(OFString *)file password:(OFString *)password
{
	self = [self init];

	@try {
		[self parsePrivateKeyFile:file password:password];
	} @catch(id e) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDPKey class]];
	}

	return self;
}

- (OFString *)PKEY_publicKeyPEM
{
	int ret = 0;
	size_t bufLen = 4 * (PUB_DER_MAX_BYTES / 3);
	unsigned char buf[bufLen];
	memset(buf, 0, bufLen);

	if ((ret = mbedtls_pk_write_pubkey_pem(self.context, buf, bufLen)) != 0)
		return nil;

	return [[OFString alloc] initWithUTF8String:(const char *)buf];
}

- (OFString *)PKEY_privateKeyPEM
{
	int ret = 0;
	size_t bufLen = 4 * (PRV_DER_MAX_BYTES / 3);
	unsigned char buf[bufLen];
	memset(buf, 0, bufLen);

	if ((ret = mbedtls_pk_write_key_pem(self.context, buf, bufLen)) != 0)
		return nil;

	return [[OFString alloc] initWithUTF8String:(const char *)buf];
}

- (OFDataArray *)PKEY_publicKeyDER
{
	int size = 0;
	unsigned char buf[PUB_DER_MAX_BYTES] = {0};
	OFDataArray* bytes;

	if ((size = mbedtls_pk_write_pubkey_der(self.context, buf, PUB_DER_MAX_BYTES)) < 0)
		return nil;

	bytes = [[OFDataArray alloc] initWithItemSize:sizeof(unsigned char)];
	[bytes addItems:(buf + sizeof(buf) - size) count:size];

	return bytes;
}

- (OFDataArray *)PKEY_privateKeyDER
{
	int size = 0;
	unsigned char buf[PRV_DER_MAX_BYTES] = {0};
	OFDataArray* bytes;

	if ((size = mbedtls_pk_write_key_der(self.context, buf, PRV_DER_MAX_BYTES)) < 0)
		return nil;

	bytes = [[OFDataArray alloc] initWithItemSize:sizeof(unsigned char)];
	[bytes addItems:(buf + sizeof(buf) - size) count:size];

	return bytes;
}

- (instancetype)initWithPEM:(OFString *)PEMString password:(OFString *)password isPublic:(bool)flag
{
	self = [self init];
	
	int ret = 0;

	if (flag)
		ret = mbedtls_pk_parse_public_key(self.context, (const unsigned char *)[PEMString UTF8String], [PEMString UTF8StringLength]);
	else
		ret = mbedtls_pk_parse_key(self.context, (const unsigned char *)[PEMString UTF8String], [PEMString UTF8StringLength], (password == nil) ? NULL : (const unsigned char *)[password UTF8String], (password == nil) ? 0 : [password UTF8StringLength]);

	if (ret != 0) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDPKey class]];
	}

	self.isPublic = flag;

	return self;
}

- (instancetype)initWithDER:(OFDataArray *)DERData password:(OFString *)password isPublic:(bool)flag
{
	self = [self init];

	int ret = 0;

	if (flag)
		ret = mbedtls_pk_parse_public_key(self.context, (const unsigned char *)[DERData items], ([DERData itemSize] * [DERData count]));
	else
		ret = mbedtls_pk_parse_key(self.context, (const unsigned char *)[DERData items], ([DERData itemSize] * [DERData count]), (password == nil) ? NULL : (const unsigned char *)[password UTF8String], (password == nil) ? 0 : [password UTF8StringLength]);

	if (ret != 0) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDPKey class]];
	}

	self.isPublic = flag;

	return self;
}

- (instancetype)initWithStruct:(mbedtls_pk_context *)context isPublic:(bool)flag
{
	self = [super init];

	memcpy(self.context, context, sizeof(mbedtls_pk_context));

	self.isPublic = flag;

	return self;
}

+ (instancetype)keyWithPublicKeyFile:(OFString *)file
{
	return [[[self alloc] initWithPublicKeyFile:file] autorelease];
}

+ (instancetype)keyWithPrivateKeyFile:(OFString *)file password:(OFString *)password
{
	return [[[self alloc] initWithPrivateKeyFile:file password:password] autorelease];
}

+ (instancetype)keyWithFile:(OFString *)file password:(OFString *)password isPublic:(bool)flag
{
	return [[[self alloc] initWithFile:file password:password isPublic:flag] autorelease];
}

+ (instancetype)keyWithPEM:(OFString *)PEMString password:(OFString *)password isPublic:(bool)flag
{
	return [[[self alloc] initWithPEM:PEMString password:password isPublic:flag] autorelease];
}

+ (instancetype)keyWithDER:(OFDataArray *)DERData password:(OFString *)password isPublic:(bool)flag
{
	return [[[self alloc] initWithDER:DERData password:password isPublic:flag] autorelease];
}

+ (instancetype)keyWithStruct:(mbedtls_pk_context *)context isPublic:(bool)flag
{
	return [[[self alloc] initWithStruct:context isPublic:flag] autorelease];
}

- (OFString *)description
{
	OFMutableString* desc = [OFMutableString string];

	[desc appendFormat:@"%@", self.name];

	if (self.isPublic)
		[desc appendString:[OFString stringWithUTF8String:" Public"]];
	else
		[desc appendString:[OFString stringWithUTF8String:" Private"]];

	[desc appendString:[OFString stringWithUTF8String:" Key"]];

	[desc makeImmutable];

	return desc;
}

@end