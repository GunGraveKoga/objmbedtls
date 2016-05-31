#import <ObjFW/ObjFW.h>
#import "MBEDPKey.h"
#import "PEM.h"
#import "MBEDTLSException.h"
#import "MBEDInitializationFailedException.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PK_PARSE_C)

#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PKCS5_C)
#include "mbedtls/pkcs5.h"
#endif

#if defined(MBEDTLS_PKCS12_C)
#include "mbedtls/pkcs12.h"
#endif

#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

@interface MBEDPKey()

@property(assign, readwrite)mbedtls_pk_type_t type;
@property(assign, readwrite)bool isPublic;
- (OFDataArray *)PKEY_publicKeyDER;
- (OFDataArray *)PKEY_privateKeyDER;

@end


@implementation MBEDPKey

@synthesize type = _type;
@synthesize isPublic = _isPublic;
@dynamic context;
@dynamic name;

- (instancetype)init
{
	self = [super init];

	mbedtls_pk_init(self.context);
	self.type = MBEDTLS_PK_NONE;
	self.isPublic = false;

	return self;
}

- (void)dealloc
{
	mbedtls_pk_free(self.context);
	[_name release];
	[super dealloc];
}

- (OFString *)PEM
{
	if (!self.isPublic && (self.type != MBEDTLS_PK_RSA || self.type != MBEDTLS_PK_ECKEY))
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE];

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	OFDataArray* DER = [self DER];

	OFString* PEM = nil;
	OFString* header = nil;
	OFString* footer = nil;

	if (self.isPublic) {
		header = [OFString stringWithUTF8String:"-----BEGIN PUBLIC KEY-----"];
		footer = [OFString stringWithUTF8String:"-----END PUBLIC KEY-----"];

	}
	else if (self.type == MBEDTLS_PK_RSA) {
		header = [OFString stringWithUTF8String:"-----BEGIN RSA PRIVATE KEY-----"];
		footer = [OFString stringWithUTF8String:"-----END RSA PRIVATE KEY-----"];

	} else if (self.type == MBEDTLS_PK_ECKEY) {
		header = [OFString stringWithUTF8String:"-----BEGIN EC PRIVATE KEY-----"];
		footer = [OFString stringWithUTF8String:"-----END EC PRIVATE KEY-----"];

	}

	PEM = DERtoPEM(DER, header, footer, 0);

	[PEM retain];

	[pool release];

	return [PEM autorelease];
}

- (OFDataArray *)DER
{
	if (self.isPublic)
		return [self PKEY_publicKeyDER];
	else
		return [self PKEY_privateKeyDER];

	return nil;
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
	[self parseFile:file password:password];
}

- (void)parsePublicKeyFile:(OFString *)file
{
	[self parseFile:file];

}

- (void)parseFilesAtPath:(OFString *)path
{
	OF_UNRECOGNIZED_SELECTOR
}

- (mbedtls_pk_context *)context
{
	return &_context;
}


- (instancetype)initWithPublicKeyFile:(OFString *)file
{
	self = [self init];

	@try {
		[self parsePublicKeyFile:file];

	}@catch(MBEDTLSException* exc) {
		[self release];

		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDPKey class] errorNumber:exc.errNo];

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

	}@catch(MBEDTLSException* exc) {
		[self release];

		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDPKey class] errorNumber:exc.errNo];

	} @catch(id e) {
		[self release];

		@throw [OFInitializationFailedException exceptionWithClass:[MBEDPKey class]];
	}

	return self;
}


- (OFDataArray *)PKEY_publicKeyDER
{
	int size = 0;
	unsigned char buf[PUB_DER_MAX_BYTES] = {0};
	OFDataArray* bytes;

	if ((size = mbedtls_pk_write_pubkey_der(self.context, buf, PUB_DER_MAX_BYTES)) <= 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:size];

	bytes = [[OFDataArray alloc] initWithItemSize:sizeof(unsigned char)];
	[bytes addItems:(buf + sizeof(buf) - size) count:size];

	return [bytes autorelease];
}

- (OFDataArray *)PKEY_privateKeyDER
{
	int size = 0;
	unsigned char buf[PRV_DER_MAX_BYTES] = {0};
	OFDataArray* bytes;

	if ((size = mbedtls_pk_write_key_der(self.context, buf, PRV_DER_MAX_BYTES)) <= 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:size];

	bytes = [[OFDataArray alloc] initWithItemSize:sizeof(unsigned char)];
	[bytes addItems:(buf + sizeof(buf) - size) count:size];

	return [bytes autorelease];
}

- (void)parseDER:(OFDataArray *)der
{
	int ret = 0;

	if (self.isPublic) {
		unsigned char *p;

		p = (unsigned char *)[der items];

		if ((ret = mbedtls_pk_parse_subpubkey(&p, [der lastItem], self.context)) != 0) {
			mbedtls_pk_free(self.context);

			@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
		}

		return;

	} else {
		[self parseDER:der password:nil];
	}
}

- (void)parseDER:(OFDataArray *)der password:(OFString *)password
{
	if (self.isPublic)
		@throw [OFInvalidArgumentException exception];

	int ret = 0;
	
	if ((ret = mbedtls_pk_parse_key(self.context, [der items], [der count], (const unsigned char *)((password == nil) ? NULL : [password UTF8String]), ((password == nil) ? 0 : [password UTF8StringLength]))) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
}

- (void)parsePEMorDER:(OFDataArray *)data password:(_Nullable OFString *)password
{
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	OFArray* tokens = @[
			#if defined(MBEDTLS_RSA_C)
			kPEMString_RSA,
			#endif
			#if defined(MBEDTLS_ECP_C)
			kPEMString_EC_Privatekey,
			#endif
			kPEMString_PKCS8INF,
			kPEMString_PKCS8,
			kPEMString_PublicKey
		];

	bool parsed = false;

	id last_exception = nil;

	@try {

		for (OFString* token in tokens) {

			void* loop_pool = objc_autoreleasePoolPush();

			if ([token isEqual:kPEMString_PublicKey]) {
				if (hasHeader(data, [OFString stringWithFormat:@"-----BEGIN %@-----", token])) {
					self.isPublic = true;
				}
			}

			@try {
				[self parsePEMorDER:data header:[OFString stringWithFormat:@"-----BEGIN %@-----", token] footer:[OFString stringWithFormat:@"-----END %@-----", token] password: self.isPublic ? nil : password];

			}@catch (MBEDTLSException* exc) {

				if (exc.errNo == MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
					continue;

				if (exc.errNo == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH)
					last_exception = [[MBEDTLSException alloc] initWithObject:self errorNumber:MBEDTLS_ERR_PK_PASSWORD_MISMATCH];
				else if (exc.errNo == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED)
					last_exception = [[MBEDTLSException alloc] initWithObject:self errorNumber:MBEDTLS_ERR_PK_PASSWORD_REQUIRED];
				else
					last_exception = [[MBEDTLSException alloc] initWithObject:self errorNumber:exc.errNo];

				@throw;

			}@catch (id e) {

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

	}@catch(id e) {
		[e retain];
		[pool release];

		@throw [e autorelease];
	}

	[pool release];

	if (!parsed)
		@throw [OFInvalidArgumentException exception];
}

- (instancetype)initWithPEM:(OFString *)pem password:(OFString *)password isPublic:(bool)flag
{
	self = [self init];

	OFAutoreleasePool* pool = nil;
	
	@try {

		if (pem == nil || [pem UTF8StringLength] <= 0)
			@throw [OFInvalidArgumentException exception];

		if (flag)
			[self parsePEM:pem];
		else {
			pool = [OFAutoreleasePool new];
	
			OFDataArray* data = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];

			[data addItems:[pem UTF8String] count:[pem UTF8StringLength]];

			[self parsePEMorDER:data password:password];

			[pool release];
		}

	}@catch(MBEDTLSException* exc) {
		[self release];

		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDPKey class] errorNumber:exc.errNo];

	}@catch(id e) {
		[self release];

		@throw [OFInitializationFailedException exceptionWithClass:[MBEDPKey class]];

	}@finally {
		if (pool == nil)
			[pool release];
	}

	return self;
}

- (instancetype)initWithDER:(OFDataArray *)der password:(OFString *)password isPublic:(bool)flag
{
	self = [self init];

	id exception = nil;

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	@try {

		if (der == nil || [der count] <= 0)
			@throw [OFInvalidArgumentException exception];

		if (flag) {
			[self parseDER:der];
			self.isPublic = flag;
		}
		else
			[self parseDER:der password:password];

	}@catch(MBEDTLSException* exc) {
		[self release];
		exception = [[MBEDInitializationFailedException alloc] initWithClass:[MBEDPKey class] errorNumber:exc.errNo];

		@throw;

	}@catch(id e) {
		[self release];
		exception = [[OFInitializationFailedException alloc] initWithClass:[MBEDPKey class]];

		@throw;

	}@finally {
		[pool release];

		if (exception != nil)
			[exception autorelease];

	}

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

+ (instancetype)keyWithPEM:(OFString *)pem password:(OFString *)password isPublic:(bool)flag
{
	return [[[self alloc] initWithPEM:pem password:password isPublic:flag] autorelease];
}

+ (instancetype)keyWithDER:(OFDataArray *)der password:(OFString *)password isPublic:(bool)flag
{
	return [[[self alloc] initWithDER:der password:password isPublic:flag] autorelease];
}

+ (instancetype)key
{
	return [[[self alloc] init] autorelease];
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