#import <ObjFW/ObjFW.h>
#import "MBEDCRL.h"
#import "MBEDTLSException.h"
#import "MBEDInitializationFailedException.h"

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
	}@catch(id e) {
		[self release];

		if ([e isKindOfClass:[MBEDTLSException class]]) {
			@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCRL class] errorNumber:((MBEDTLSException *)e).errNo];
		}

		@throw [OFInitializationFailedException exceptionWithClass:[MBEDCRL class]];
	}

	[self CRL_fillProperties];

	return self;
}

+ (instancetype)crlWithFile:(OFString *)file
{
	return [[[self alloc] initWithFile:file] autorelease];
}

+ (instancetype)crlWithCRLStruct:(mbedtls_x509_crl *)crl
{
	return [[[self alloc] initWithCRLStruct:crl] autorelease];
}

- (instancetype)initWithCRLStruct:(mbedtls_x509_crl *)crl
{
	self = [self init];

	int ret = 0;

	if ((ret = mbedtls_x509_crl_parse_der(self.context, crl->raw.p, crl->raw.len)) != 0) {
		[self release];

		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCRL class] errorNumber:ret];
	}

	[self CRL_fillProperties];

	return self;

}

+ (instancetype)crlWithPEMString:(OFString *)string
{
	return [[[self alloc] initWithPEMString:string] autorelease];
}

+ (instancetype)crlWithPEMorDERData:(OFDataArray *)data
{
	return [[[self alloc] initWithPEMorDERData:data] autorelease];
}

- (instancetype)initWithPEMString:(OFString *)string
{
	self = [self init];

	int ret = 0;

	if ((ret = mbedtls_x509_crl_parse(self.context, (const unsigned char *)[string UTF8String], [string UTF8StringLength])) != 0) {
		[self release];

		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCRL class] errorNumber:ret];
	}

	[self CRL_fillProperties];

	return self;
}

- (instancetype)initWithPEMorDERData:(OFDataArray *)data
{
	self = [self init];

	int ret = 0;

	if ((ret = mbedtls_x509_crl_parse(self.context, (const unsigned char *)[data items], ([data count] * [data itemSize]))) != 0) {
		[self release];

		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDCRL class] errorNumber:ret];
	}

	[self CRL_fillProperties];

	return self;
}

- (void)parseFile:(OFString *)file
{
	OFFileManager* filemanager = [OFFileManager defaultManager];

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	if (![filemanager fileExistsAtPath:file]) {

		[pool release];

		@throw [OFInvalidArgumentException exception];
	}

	OFDataArray* data = [OFDataArray dataArrayWithContentsOfFile:file];

	if ([data count] == 0 || [data lastItem] == NULL) {
		[pool release];
		@throw [OFInvalidArgumentException exception];
	}

	if (*((char *)[data lastItem]) == '\0' && strstr( (const char *)[data items], "-----BEGIN X509 CRL-----" ) != NULL) {
		@try {
			[self parsePEM:[OFString stringWithUTF8String:(const char *)[data items] length:(size_t)[data count]]];

		}@catch(id e) {
			[pool release];

			@throw e;
		}

		[pool release];

		return;
	}

	@try {
		[self parseDER:data];

	} @catch(id e) {

		[pool release];

		@throw e;
	}

	[pool release];
}

- (OFDictionary *)CRL_dictionaryFromX509Name:(OFString *)name
{
	/*OFMutableDictionary* dictionary = [OFMutableDictionary dictionary];
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

	return dictionary;*/

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

 	[self CRL_fillProperties];

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

}

- (void)parsePEM:(OFString *)pem
{
	int ret = 0;

	if ((ret = mbedtls_x509_crl_parse(self.context, (const unsigned char *)[pem UTF8String], [pem UTF8StringLength])) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];

}

- (MBEDCRL *)next
{
	static mbedtls_x509_crl *crl = NULL;

	if (crl == NULL)
		crl = self.context;

	while (crl->version != 0 && crl->next != NULL) {
		crl = crl->next;

		return [MBEDCRL crlWithCRLStruct:crl];
	}

	crl = NULL;

	return nil;

}

- (OFDataArray *)DER
{
	OFDataArray* der = [OFDataArray dataArrayWithItemSize:sizeof(char)];

	[der addItems:self.context->raw.p count:self.context->raw.len];

	return der;
}

- (OFString *)PEM
{
	return [self PEMWithHeader:@"-----BEGIN X509 CRL-----" bottom:@"-----END X509 CRL-----"];
}

- (OFString *)PEMWithHeader:(OFString *)header bottom:(OFString *)bottom
{
	OFMutableString* pem = [OFMutableString string];

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	OFDataArray* der = [self DER];

	[pem appendFormat:@"%@\r\n%@\r\n%@\r\n", header, [der stringByBase64Encoding], bottom];

	[pool release];

	[pem makeImmutable];

	return pem;

}

- (OFString *)description
{
	OFMutableString* desc = [OFMutableString string];

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

@end