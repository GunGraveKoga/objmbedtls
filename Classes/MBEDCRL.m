#import <ObjFW/ObjFW.h>
#import "MBEDCRL.h"
#import "MBEDTLSException.h"
#import "MBEDInitializationFailedException.h"
#import "PEM.h"

#include <mbedtls/pem.h>
#include <mbedtls/base64.h>

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
	_parsed = false;

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

	}@catch(MBEDTLSException* exc) {
		[self release];
		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCRL class] errorNumber:exc.errNo];

	}@catch(id e) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDCRL class]];

	}

	return self;
}

- (instancetype)initWithFilesAtPath:(OFString *)path
{
	self = [super init];

	@try {
		[self parseFilesAtPath:path];

	}@catch(MBEDTLSException* exc) {
		[self release];
		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCRL class] errorNumber:exc.errNo];

	}@catch(id e) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDCRL class]];
	}

	return self;
}

+ (instancetype)crlWithFile:(OFString *)file
{
	return [[[self alloc] initWithFile:file] autorelease];
}


+ (instancetype)crlWithPEM:(OFString *)pem
{
	return [[[self alloc] initWithPEM:pem] autorelease];
}

+ (instancetype)crlWithDER:(OFDataArray *)der
{
	return [[[self alloc] initWithDER:der] autorelease];
}

+ (instancetype)crlWithFilesAtPath:(OFString *)path
{
	return [[[self alloc] initWithFilesAtPath:path] autorelease];
}

- (instancetype)initWithPEM:(OFString *)pem
{
	self = [self init];

	if ([pem UTF8StringLength] <= 0) {
		[self release];
		@throw [OFInvalidArgumentException exception];
	}

	@try {
		[self parsePEM:pem];

	}@catch(MBEDTLSException* exc) {
		[self release];
		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCRL class] errorNumber:exc.errNo];

	}@catch(id e) {
		[self release];

		@throw [OFInitializationFailedException exceptionWithClass:[MBEDCRL class]];
	}

	return self;
}

- (instancetype)initWithDER:(OFDataArray *)der
{
	self = [self init];

	if ([der count] <= 0) {
		[self release];

		@throw [OFInvalidArgumentException exception];
	}

	@try {
		[self parseDER:der];

	}@catch(MBEDTLSException* exc) {
		[self release];
		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCRL class] errorNumber:exc.errNo];

	}@catch(id e) {
		[self release];

		@throw [OFInitializationFailedException exceptionWithClass:[MBEDCRL class]];
	}

	return self;
}

- (OFDictionary *)CRL_dictionaryFromX509Name:(OFString *)name
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

	OFString* dnString = nil;

	if (ret > 0) {

		@try {
			dnString = [OFString stringWithUTF8String:buf length:ret];
		}@catch(id e) {
			dnString = nil;
		}

		if (nil == dnString) {
			dnString = parse_dn_string(buf, (size_t)ret);	
		}

		self.issuer = [self CRL_dictionaryFromX509Name:dnString];
	}
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

	_parsed = true;
}

#if defined(OF_WINDOWS) || defined(OF_LINUX) || defined(OF_MAC_OS_X)
- (instancetype)initWithSystemCRL
{
	self = [self init];
	
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

#if defined(OF_WINDOWS)

	HCERTSTORE hStore = CertOpenSystemStore(0, "CA");
	OFDataArray* DER = nil;
	
	 for ( PCCRL_CONTEXT pCrlCtx = CertEnumCRLsInStore(hStore, NULL);

       pCrlCtx != NULL;
       pCrlCtx = CertEnumCRLsInStore(hStore, pCrlCtx) )

 	{
	
 		bool isPKCS7 = (bool)((pCrlCtx->dwCertEncodingType & PKCS_7_ASN_ENCODING) == PKCS_7_ASN_ENCODING);

 		if (!isPKCS7) {

 			DER = [OFDataArray dataArrayWithItemSize:sizeof(char)];

			[DER addItems:(const void *)pCrlCtx->pbCrlEncoded count:(size_t)pCrlCtx->cbCrlEncoded];

			@try {
				[self parseDER:DER];
			} @catch(id e) {}

			[pool releaseObjects];

			DER = nil;
			
 		}
   

 	}

 	CertCloseStore(hStore, 0);

#elif defined(OF_LINUX)

#elif defined(OF_MAC_OS_X)

#endif

 	[pool release];

 	return self;
}

+ (instancetype)crlWithSystemCRL
{
	return [[[self alloc] initWithSystemCRL] autorelease];
}
#endif

- (void)parseDER:(OFDataArray *)der
{
	int ret = 0;

	if ((ret = mbedtls_x509_crl_parse_der(self.context, (const unsigned char *)[der items], ([der count] * [der itemSize]))) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];

	if (!_parsed)
		[self CRL_fillProperties];

}

- (X509Object *)next
{
	static mbedtls_x509_crl *crl = NULL;

	if (crl == NULL)
		crl = self.context;

	while (crl->version != 0 && crl->next != NULL) {
		crl = crl->next;

		OFDataArray* DER = [[OFDataArray alloc] initWithItemSize:sizeof(unsigned char)];

        [DER addItems:crl->raw.p count:crl->raw.len];

		X509Object* obj = [[MBEDCRL alloc] initWithDER:DER];

		[DER release];

        return [obj autorelease];
	}

	crl = NULL;

	return nil;

}

- (size_t)count
{
	mbedtls_x509_crl *crl = self.context;
	size_t idx = 0;

	if (crl->version != 0)
		idx++;
	else
		return 0;

	while (crl->next != NULL) {
		crl = crl->next;
		idx++;

	}

	return idx;

}

- (OFDataArray *)DER
{
	OFDataArray* der = [OFDataArray dataArrayWithItemSize:sizeof(char)];

	[der addItems:self.context->raw.p count:self.context->raw.len];

	return der;
}

- (OFString *)PEM
{
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	id exception = nil;
	OFString* pem = nil;

	@try {
		OFDataArray* der = [self DER];
		pem = DERtoPEM(der, @"-----BEGIN X509 CRL-----", @"-----END X509 CRL-----", 0);

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


- (OFString *)description
{
	OFMutableString* desc = [OFMutableString string];
	[desc appendUTF8String:"x509 CRL\n"];
	[desc appendFormat:@"Version: v%d\n\n", self.version];

	[desc appendFormat:@"ThisUpdate: %@\n\n", self.thisUpdate];
	[desc appendFormat:@"NextUpdate: %@\n\n", self.nextUpdate];

	[desc appendFormat:@"Signature Algorithm: %@\n\n", self.signatureAlgorithm];

	bool firstValue = true;
	bool firstKey = true;
	[desc appendUTF8String:"Issuer: "];

	for (OFString* key in [self.issuer allKeys]) {

		firstValue = true;

		if (!firstKey)
			[desc appendString:[OFString stringWithUTF8String:", "]];

		@autoreleasepool {

			for (OFString* value in [self.issuer objectForKey:key]) {
				if (!firstValue)
					[desc appendString:[OFString stringWithUTF8String:", "]];

				[desc appendFormat:@"%@=%@", key, value];

				if (firstValue)
					firstValue = false;
			}
		}

		if (firstKey)
			firstKey = false;


	}

	[desc appendUTF8String:"\n\n"];

	[desc appendUTF8String:"Revoced Certificates:\n\n"];

	size_t idx = 1;

	for (OFDictionary* entry in self.revokedCertificates) {

		@autoreleasepool {

			[desc appendFormat:@" %zu:\n", idx];
			[desc appendFormat:@"\tSerial Number: %@\n", [entry objectForKey:kRCSerialNumber]];
			[desc appendFormat:@"\tRevocation Date: %@\n", [[entry objectForKey:kRCRevocationDate] localDateStringWithFormat:@"%Y-%m-%d %H:%M:%S"]];
			[desc appendUTF8String:"\n\n"];
		}

		idx++;
	}

	[desc makeImmutable];

	return desc;
}

- (void)parsePEMorDER:(OFDataArray *)data password:(_Nullable OFString *)password
{
	
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	OFArray* tokens = @[
			kPEMString_X509_CRL
		];

	bool parsed = false;
	id last_exception = nil;

	@try {

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

	} @catch (id e) {
		[e retain];
		[pool release];

		@throw [e autorelease];
	}

	
	[pool release];

	if (!parsed)
		@throw [OFInvalidArgumentException exception];

}

@end