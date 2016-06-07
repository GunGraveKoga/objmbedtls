#import <ObjFW/ObjFW.h>
#import "MBEDPKey.h"
#import "PEM.h"
#import "MBEDTLSException.h"
#import "MBEDInitializationFailedException.h"
#import "MBEDEntropy.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PK_PARSE_C)

#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include "mbedtls/bignum.h"

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
@property(assign, readwrite)MBEDEntropy* entropy;
@property(assign, readwrite)bool isPublic;
- (OFDataArray *)PKEY_publicKeyDER;
- (OFDataArray *)PKEY_privateKeyDER;
- (void)PKEY_parsePublicKeyDER:(OFDataArray *)pub;
- (void)PKEY_parsePrivateKeyDER:(OFDataArray *)prv password:(OFString *)password;

@end


@implementation MBEDPKey

@synthesize type = _type;
@synthesize isPublic = _isPublic;
@synthesize entropy = _entropy;
@dynamic context;
@dynamic name;
@dynamic bitlen;

- (instancetype)init
{
	self = [super init];

	void* pool = objc_autoreleasePoolPush();
	
	mbedtls_pk_init(self.context);

	self.type = MBEDTLS_PK_NONE;
	self.isPublic = false;
	_bitlen = 0;

	bool random_generated = false;
	int lasterror = 0;

	@try {
		
		self.entropy = [MBEDEntropy defaultEntropy];

		random_generated = true;

	}@catch (id e) {
		of_log(@"%@", e);

		if ([e isKindOfClass:[MBEDTLSException class]])
			lasterror = ((MBEDTLSException *)e).errNo;

	} @finally {
		objc_autoreleasePoolPop(pool);

	}

	if (!random_generated) {
		[self release];

		if (lasterror != 0)
			@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDPKey class] errorNumber:lasterror];

		@throw [OFInitializationFailedException exceptionWithClass:[MBEDPKey class]];
	}


	return self;
}

- (void)dealloc
{
	mbedtls_pk_free(self.context);
	self.entropy = nil;
	[_name release];
	[super dealloc];
}

- (OFString *)PEM
{
	if (!self.isPublic && (self.type != MBEDTLS_PK_RSA || self.type != MBEDTLS_PK_ECKEY))
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE];

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	OFString* PEM = nil;
	OFString* header = nil;
	OFString* footer = nil;
	id exception = nil;

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

	@try {
		OFDataArray* DER = [self DER];
		PEM = DERtoPEM(DER, header, footer, 0);

	}@catch(id e) {
		exception = [e retain];
		@throw;

	}@finally {
		if (PEM != nil)
			[PEM retain];

		[pool release];

		if (exception != nil)
			[exception autorelease];

	}

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

- (mbedtls_pk_context *)context
{
	return &_context;
}

- (size_t)bitlen
{
	return mbedtls_pk_get_bitlen(self.context);
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

- (void)PKEY_parsePublicKeyDER:(OFDataArray *)pub
{
	int ret = 0;

	unsigned char* p = [pub items];

	if ((ret =  mbedtls_pk_parse_subpubkey(&p, p + [pub count], self.context)) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];

}

- (void)PKEY_parsePrivateKeyDER:(OFDataArray *)prv password:(OFString *)password
{
	int ret = 0;
	
	if ((ret = mbedtls_pk_parse_key(self.context, [prv items], [prv count], (const unsigned char *)((password == nil) ? NULL : [password UTF8String]), ((password == nil) ? 0 : [password UTF8StringLength]))) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
}

- (void)parseDER:(OFDataArray *)der
{
	id exception = nil;

	OFAutoreleasePool* pool = [OFAutoreleasePool new];
	
	@try {
		[self PKEY_parsePublicKeyDER:der];
		self.isPublic = true;

		return;

	} @catch (MBEDTLSException* exc) {
		self.isPublic = false;
		mbedtls_pk_free(self.context);

	}@catch (id e) {
		exception = [e retain];
		@throw;

	}@finally {
		[pool release];

		if (exception != nil)
			[exception autorelease];
	}

	[self PKEY_parsePrivateKeyDER:der password:nil];


}

- (void)parseDER:(OFDataArray *)der password:(OFString *)password
{
	self.isPublic = false;

	[self PKEY_parsePrivateKeyDER:der password:password];
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
		}
		else
			[self parseDER:der password:password];

	}@catch(MBEDTLSException* exc) {
		[self release];
		exception = [[MBEDInitializationFailedException alloc] initWithClass:[MBEDPKey class] errorNumber:exc.errNo];

		@throw exception;

	}@catch(id e) {
		[self release];
		exception = [[OFInitializationFailedException alloc] initWithClass:[MBEDPKey class]];

		@throw exception;

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

	[desc appendFormat:@"%zu bit %@", self.bitlen, self.name];

	if (self.isPublic)
		[desc appendUTF8String:" Public"];
	else
		[desc appendUTF8String:" Private"];

	[desc appendUTF8String:" Key"];

	[desc makeImmutable];

	return desc;
}

- (OFDataArray *)makeSignatureForHash:(const uint8_t *)hash hashType:(mbedtls_md_type_t)algorithm
{
	unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    int ret = 0;
    size_t olen = 0;

   if (self.context->pk_info == NULL)
   	@throw [OFInvalidArgumentException exception];


    if ((ret =  mbedtls_pk_sign(self.context, algorithm, hash, 0, buf, &olen, mbedtls_ctr_drbg_random, self.entropy.ctr_drbg)) != 0)
    	@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];

    OFDataArray* sign = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];
    [sign addItems:buf count:olen];

    return sign;
}

- (bool)verifySignature:(OFDataArray *)signature ofHash:(const uint8_t *)hash hashType:(mbedtls_md_type_t)algorithm
{
	int ret = 0;

	if ((ret = mbedtls_pk_verify(self.context, algorithm, hash, 0, [signature items], [signature count])) != 0)
		return false;

	return true;
}

- (MBEDPKey *)publicKey
{
	if (self.isPublic)
		@throw [OFNotImplementedException exceptionWithSelector:@selector(publicKey) object:self];

	unsigned char der[PUB_DER_MAX_BYTES];
	OFDataArray* bytes;
	int ret = 0;
	MBEDPKey* pub;

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	if ((ret = mbedtls_pk_write_pubkey_der(self.context, der, sizeof(der))) <= 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];

	bytes = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];

	[bytes addItems:(der + sizeof(der) - ret) count:ret];

	pub = [[MBEDPKey alloc] initWithDER:bytes password:nil isPublic:true];

	[pool release];

	return [pub autorelease];
}

+ (bool)publicKey:(MBEDPKey *)pub matchesPrivateKey:(MBEDPKey *)prv
{
	if (mbedtls_pk_check_pair(pub.context, prv.context) == 0)
		return true;

	return false;
}

- (void)parseFilesAtPath:(OFString *)path
{
	[self doesNotRecognizeSelector:@selector(parseFilesAtPath:)];
}

@end