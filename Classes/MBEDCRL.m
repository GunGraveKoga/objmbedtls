#import <ObjFW/ObjFW.h>
#import "MBEDCRL.h"

OFString *const kRCSerialNumber = @"kRCSerialNumber";
OFString *const kRCRevocationDate = @"kRCRevocationDate";

@interface MBEDCRL()

@property(copy, readwrite)OFDictionary* issuer;
@property(copy, readwrite)OFDate* thisUpdate;
@property(copy, readwrite)OFDate* nextUpdate;
@property(assign, readwrite)uint8_t version;
@property(copy, readwrite)OFArray* revokedCertificates;
@property(copy, readwrite)OFString* signatureAlgorithm;

- (void)CRL_fillProperties;
- (OFDictionary *)CRL_dictionaryFromX509Name:(OFString *)name;

@end

@implementation MBEDCRL

@dynamic context;
@synthesize issuer = _issuer;
@synthesize thisUpdate = _thisUpdate;
@synthesize nextUpdate = _nextUpdate;
@synthesize version = _version;
@synthesize revokedCertificates = _revokedCertificates;
@synthesize signatureAlgorithm = _signatureAlgorithm;

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

+ (instancetype)crlWithFile:(OFString *)file
{
	return [[[self alloc] initWithFile:file] autorelease];
}

- (void)parseFile:(OFString *)file
{
	if ( (mbedtls_x509_crl_parse_file(self.context, [file UTF8String]) ) != 0) {
		@throw [OFInvalidArgumentException exception];
	}

	[self CRL_fillProperties];
}

- (OFDictionary *)CRL_dictionaryFromX509Name:(OFString *)name
{
	OFMutableDictionary* dictionary = [OFMutableDictionary dictionary];
	OFArray* names = [name componentsSeparatedByString:[OFString stringWithUTF8String:", "]];

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	for (OFString* dn in names) {
		OFArray* pair = [dn componentsSeparatedByString:[OFString stringWithUTF8String:"="]];

		if ([dictionary objectForKey:[pair objectAtIndex:0]] == nil) {
			[dictionary setObject:[OFList list] forKey:[pair objectAtIndex:0]];
		}

		[[dictionary objectForKey:[pair objectAtIndex:0]] appendObject:[pair objectAtIndex:1]];

		[pool releaseObjects];
	}

	[pool release];

	[dictionary makeImmutable];

	return dictionary;
}

- (void)CRL_fillProperties
{
	void* pool = objc_autoreleasePoolPush();

	size_t bufSize = sizeof(char) * 4096;
	int ret = 0;
	char* buf = (char *)__builtin_alloca(bufSize);
	const mbedtls_x509_crl_entry *entry;
	memset(buf, 0, bufSize);

	self.version = (uint8_t)self.context->version;

	ret = mbedtls_x509_dn_gets(buf, bufSize, &(self.context->issuer));

	if (ret > 0)
		self.issuer = [self CRL_dictionaryFromX509Name:[OFString stringWithUTF8String:buf length:ret]];
	else {
		objc_autoreleasePoolPop(pool);
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDCRL class]];
	}

	memset(buf, 0, bufSize);

	entry = &(self.context->entry);

	OFMutableArray* entries = [OFMutableArray array];
	OFString* dtFormat = [OFString stringWithUTF8String:"%Y-%m-%d %H:%M:%S"];
	

	OFAutoreleasePool* localPool = [OFAutoreleasePool new];

	while (entry != NULL && entry->raw.len != 0) {
		OFMutableDictionary* dict = [OFMutableDictionary dictionary];

		ret = mbedtls_x509_serial_gets(buf, bufSize, &entry->serial);
		if (ret > 0)
			[dict setObject:[OFString stringWithUTF8String:buf length:ret] forKey:kRCSerialNumber];
		else {
			[localPool release];
			objc_autoreleasePoolPop(pool);
			[self release];
			@throw [OFInitializationFailedException exceptionWithClass:[MBEDCRL class]];
		}

		OFString* dtSString = [OFString stringWithFormat:@"%04d-%02d-%02d %02d:%02d:%02d",
			entry->revocation_date.year, entry->revocation_date.mon,
            entry->revocation_date.day,  entry->revocation_date.hour,
            entry->revocation_date.min,  entry->revocation_date.sec
		];

		OFDate* dt = [OFDate dateWithLocalDateString:dtSString format:dtFormat];

		[dict setObject:dt forKey:kRCRevocationDate];

		[dict makeImmutable];

		[entries addObject:dict];

		[localPool releaseObjects];

		entry = entry->next;
		memset(buf, 0, bufSize);
	}

	[localPool release];

	[entries makeImmutable];

	self.revokedCertificates = entries;

	ret = mbedtls_x509_sig_alg_gets( buf, bufSize, &(self.context->sig_oid), self.context->sig_pk, self.context->sig_md, self.context->sig_opts );

	if (ret > 0)
		self.signatureAlgorithm = [OFString stringWithUTF8String:buf length:bufSize];
	else {
		objc_autoreleasePoolPop(pool);
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDCRL class]];
	}

	OFString* dtThis = [OFString stringWithFormat:@"%04d-%02d-%02d %02d:%02d:%02d",
			self.context->this_update.year, self.context->this_update.mon,
            self.context->this_update.day,  self.context->this_update.hour,
            self.context->this_update.min,  self.context->this_update.sec
		];

	OFString* dtNext = [OFString stringWithFormat:@"%04d-%02d-%02d %02d:%02d:%02d",
			self.context->next_update.year, self.context->next_update.mon,
            self.context->next_update.day,  self.context->next_update.hour,
            self.context->next_update.min,  self.context->next_update.sec
		];

	self.thisUpdate = [OFDate dateWithLocalDateString:dtThis format:dtFormat];
	self.nextUpdate = [OFDate dateWithLocalDateString:dtNext format:dtFormat];

	objc_autoreleasePoolPop(pool);
}

@end