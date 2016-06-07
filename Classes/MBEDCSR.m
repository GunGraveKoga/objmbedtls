#import <ObjFW/ObjFW.h>
#import "MBEDTLSException.h"
#import "MBEDInitializationFailedException.h"
#import "MBEDCSR.h"
#import "MBEDPKey.h"
#import "PEM.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CSR_PARSE_C)

#include "mbedtls/oid.h"

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_free       free
#define mbedtls_calloc    calloc
#define mbedtls_snprintf   snprintf
#endif

#endif

@interface MBEDCSR()

@property (assign, readwrite)mbedtls_x509_csr *context;
@property (assign, readwrite)uint8_t version;
@property (copy, readwrite)OFDictionary* subject;
@property (copy, readwrite)OFString* signatureAlgorithm;
@property (copy, readwrite)OFString* keyName;
@property (assign, readwrite)size_t keySize;

- (OFDictionary *)X509_dictionaryFromX509Name:(OFString *)name;
- (void)X509_fillProperties;


@end


@implementation MBEDCSR

@dynamic context;
@synthesize version = _version;
@synthesize subject = _subject;
@synthesize signatureAlgorithm = _signatureAlgorithm;
@synthesize keyName = _keyName;
@synthesize keySize = _keySize;

+ (instancetype)csrWithDER:(OFDataArray *)der
{
	return [[[self alloc] initWithDER:der] autorelease];
}

+ (instancetype)csrWithPEM:(OFString *)pem
{
	return [[[self alloc] initWithPEM:pem] autorelease];
}

- (instancetype)init
{
	self = [super init];

	mbedtls_x509_csr_init(self.context);

	_parsed = false;
	_version = 0;
	_subject = nil;
	_signatureAlgorithm = nil;
	_keyName = nil;
	_keySize = 0;

	return self;
}

- (instancetype)initWithDER:(OFDataArray *)der
{
	self = [self init];

	@try {
		[self parseDER:der];

	}@catch(MBEDTLSException* exc) {
		[self release];

		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCSR class] errorNumber:exc.errNo];

	}@catch(id e){
		[self release];

		@throw [OFInitializationFailedException exceptionWithClass:[MBEDCSR class]];

	}

	return self;
}

- (instancetype)initWithPEM:(OFString *)pem
{
	self = [self init];

	@try {
		[self parsePEM:pem];

	}@catch(MBEDTLSException* exc) {
		[self release];

		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCSR class] errorNumber:exc.errNo];

	}@catch(id e){
		[self release];

		@throw [OFInitializationFailedException exceptionWithClass:[MBEDCSR class]];

	}

	return self;
}

- (void)dealloc
{
	[_subject release];
	[_signatureAlgorithm release];
	[_keyName release];
	mbedtls_x509_csr_free(self.context);

	[super dealloc];
}

- (mbedtls_x509_csr *)context
{
	return &_context;
}

- (OFDataArray *)DER
{
	OFDataArray* der = [OFDataArray dataArrayWithItemSize:sizeof(char)];

	[der addItems: self.context->raw.p count: self.context->raw.len];

	return der;
}

- (OFString *)PEM
{
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	id exception = nil;
	OFString* pem = nil;

	@try {
		OFDataArray* der = [self DER];

		pem = DERtoPEM(der, @"-----BEGIN CERTIFICATE REQUEST-----", @"-----END CERTIFICATE REQUEST-----", 0);

	}@catch(id e) {
		exception = [e retain];
		@throw;

	}@finally {
		if (pem != nil)
			[pem retain];

		[pool release];

		if (exception != nil)
			[exception autorelease];

	}


	return [pem autorelease];
}

- (OFDictionary *)X509_dictionaryFromX509Name:(OFString *)name
{
	OFMutableDictionary* dictionary = [OFMutableDictionary dictionary];
	
	OFMutableArray* names = [OFMutableArray array];

	OFAutoreleasePool* pool = [OFAutoreleasePool new];
	
	size_t len = [name length];
	OFString* field = nil;
	of_range_t tmpRange;

	for (size_t idx = 0; idx < len; idx++) {
		tmpRange = [name rangeOfString:@"," options:0 range:of_range(idx, len - idx)];

		if (tmpRange.location == OF_NOT_FOUND) {
			if (idx == 0) {
				tmpRange = [name rangeOfString:@"=" options:0 range:of_range(idx, len - idx)];

				if (tmpRange.location == OF_NOT_FOUND) {
					[pool release];
					@throw [OFInvalidArgumentException exception];
				}

				[names addObject:[name stringByDeletingEnclosingWhitespaces]];
			}

			field = [name substringWithRange:of_range(idx, len - idx)];

			[names addObject:[field stringByDeletingEnclosingWhitespaces]];

			[pool releaseObjects];

			break;
		}

		tmpRange = [name rangeOfString:@"=" options:0 range:of_range(tmpRange.location, len - tmpRange.location)];

		if (tmpRange.location == OF_NOT_FOUND) {
			field = [name substringWithRange:of_range(idx, len - idx)];

			[names addObject:[field stringByDeletingEnclosingWhitespaces]];

			[pool releaseObjects];

			break;
		}
		
		tmpRange = [name rangeOfString:@" " options:OF_STRING_SEARCH_BACKWARDS range:of_range(idx, tmpRange.location - idx)];

		if (tmpRange.location == OF_NOT_FOUND) {
			[pool release];

			@throw [OFInvalidArgumentException exception];
		}

		field = [name substringWithRange:of_range(idx, tmpRange.location - idx)];

		field = [field stringByDeletingEnclosingWhitespaces];

		if ([field hasSuffix:@","])
			field = [field stringByReplacingOccurrencesOfString:@"," withString:@"" options:OF_STRING_SEARCH_BACKWARDS range:of_range(0, [field length])];

		[names addObject:field];

		[pool releaseObjects];

		idx = tmpRange.location;
	}

	

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

static inline OFString* parse_dn_string(char* buffer, size_t size) {

	OFMutableString* dnString = [OFMutableString string];

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	for (size_t idx = 0; idx < size; idx++) {
		unsigned char ch = (unsigned char)buffer[idx];

		if (ch > 0 && ch < 127)
			[dnString appendFormat:@"%c", ch];
		else
			[dnString appendFormat:@"\\x%x", ch];

		[pool releaseObjects];
	}

	[pool release];

	[dnString makeImmutable];

	return dnString;
}

- (void)X509_fillProperties
{
	void* pool = objc_autoreleasePoolPush();

	size_t bufSize = sizeof(char) * 4096;
	int ret = 0;
	char* buf = (char *)__builtin_alloca(bufSize);
	memset(buf, 0, bufSize);

	self.version = (uint8_t)self.context->version;

	OFString* dnString = nil;

	ret = mbedtls_x509_dn_gets(buf, bufSize, &( self.context->subject));
	if (ret > 0) {

		@try {
			dnString = [OFString stringWithUTF8String:buf length:ret];
		}@catch(id e) {
			dnString = nil;
		}

		if (nil == dnString) {
			dnString = parse_dn_string(buf, (size_t)ret);	
		}

		self.subject = [self X509_dictionaryFromX509Name:dnString];
	}
	else {
		objc_autoreleasePoolPop(pool);
		[self release];
		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCSR class] errorNumber:ret];
	}

	memset(buf, 0, bufSize);

	ret = mbedtls_x509_sig_alg_gets(buf, bufSize, &( self.context->sig_oid),  self.context->sig_pk,  self.context->sig_md,  self.context->sig_opts);

	if (ret > 0)
		self.signatureAlgorithm = [OFString stringWithUTF8String:buf length:ret];
	else {
		objc_autoreleasePoolPop(pool);
		[self release];
		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCSR class] errorNumber:ret];
	}

	memset(buf, 0, bufSize);

	self.keySize = (size_t)mbedtls_pk_get_bitlen( &( self.context->pk) );

	self.keyName = [OFString stringWithUTF8String:mbedtls_pk_get_name(&(self.context->pk))];

	objc_autoreleasePoolPop(pool);

	_parsed = true;
}

- (OFString *)description
{
	OFMutableString *ret = [OFMutableString string];

	void* pool = objc_autoreleasePoolPush();

	[ret appendUTF8String:"X509 CSR\n"];
	[ret appendFormat: @"Version: v%d\n\n", self.version];

	[ret appendUTF8String:"Subject: "];

	bool firstValue = true;
	bool firstKey = true;

	for (OFString* key in [self.subject allKeys]) {
		firstValue = true;

		if (!firstKey)
			[ret appendUTF8String:", "];

		@autoreleasepool {
			for (OFString* value in [self.subject objectForKey:key]) {
				if (!firstValue)
					[ret appendUTF8String:", "];

				[ret appendFormat:@"%@=%@", key, value];

				if (firstValue)
					firstValue = false;
			}
		}

		if (firstKey)
			firstKey = false;
	}
	[ret appendUTF8String:"\n\n"];

	[ret appendFormat: @"Signature Algorithm: %@\n\n", self.signatureAlgorithm];

	[ret appendFormat:@"%@ key size: %zu bits\n\n", self.keyName, self.keySize];

	objc_autoreleasePoolPop(pool);

	[ret makeImmutable];

	return ret;
}

- (void)parseDER:(OFDataArray *)der
{
	int ret = 0;

	if ((ret = mbedtls_x509_csr_parse_der(self.context, [der items], [der count])) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];

	if (!_parsed)
		[self X509_fillProperties];
}

- (void)parsePEMorDER:(OFDataArray *)data password:(_Nullable OFString *)password
{
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	OFArray* tokens = @[
			kPEMString_X509_CSR_Old,
			kPEMString_X509_CSR
		];

	bool parsed = false;

	@try {
		id last_exception = nil;

		for (OFString* token in tokens) {
			void* loop_pool = objc_autoreleasePoolPush();

			@try {
				[self parsePEMorDER:data header:[OFString stringWithFormat:@"-----BEGIN %@-----", token] footer:[OFString stringWithFormat:@"-----END %@-----", token] password:password];

			} @catch(MBEDTLSException* exc) {

				if (exc.errNo == MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
					continue;

				last_exception = [[MBEDTLSException alloc] initWithObject:self errorNumber:exc.errNo];

				@throw last_exception;

			} @catch(OFException* e) {

				last_exception = [e retain];

				@throw;

			}@finally {

				objc_autoreleasePoolPop(loop_pool);

				if (last_exception != nil)
					[last_exception autorelease];

			}

			parsed = true;
			objc_autoreleasePoolPop(loop_pool);
			
			break;
		}

	}@catch (id e) {
		[e retain];

		[pool release];

		@throw [e autorelease];
	}

	[pool release];

	if (!parsed)
		@throw [OFInvalidArgumentException exception];
}

- (MBEDPKey *)publicKey
{
	unsigned char der[PUB_DER_MAX_BYTES];
	OFDataArray* bytes;
	int ret = 0;
	MBEDPKey* pub;

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	if ((ret = mbedtls_pk_write_pubkey_der(&(self.context->pk), der, sizeof(der))) <= 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];

	bytes = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];

	[bytes addItems:(der + sizeof(der) - ret) count:ret];

	pub = [[MBEDPKey alloc] initWithDER:bytes password:nil isPublic:true];

	[pool release];

	return [pub autorelease];
}

- (void)parseFilesAtPath:(OFString *)path
{
	[self doesNotRecognizeSelector:@selector(parseFilesAtPath:)];
}

@end