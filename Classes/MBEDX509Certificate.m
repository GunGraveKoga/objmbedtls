#import <ObjFW/ObjFW.h>
#import "macros.h"
#import "MBEDX509Certificate.h"
#import "MBEDPKey.h"
#import "MBEDCRL.h"
#import "MBEDTLSException.h"
#import "MBEDInitializationFailedException.h"

#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/pem.h>
#include <mbedtls/base64.h>

@interface MBEDX509Certificate()

@property(copy, readwrite)OFDictionary* issuer;
@property(copy, readwrite)OFDictionary* subject;
@property(copy, readwrite)OFDictionary* subjectAlternativeNames;
@property(assign, readwrite)uint8_t version;
@property(copy, readwrite)OFString* signatureAlgorithm;
@property(copy, readwrite)OFDate* issued;
@property(copy, readwrite)OFDate* expires;
@property(assign, readwrite)int keySize;
@property(copy, readwrite)OFString* type;
@property(assign, readwrite)bool isCA;
@property(assign, readwrite)size_t maxPathLength;
@property(copy, readwrite)OFArray* keyUsage;
@property(copy, readwrite)OFArray* extendedKeyUsage;
@property(copy, readwrite)OFString* serialNumber;


- (OFDictionary *)X509_dictionaryFromX509Name:(OFString *)name;
- (OFDictionary *)X509_dictionaryFromX509AltNames:(OFString *)names;
- (OFArray *)X509_arrayFromX509KeyUsageString:(OFString *)string;
- (void)X509_fillProperties;
- (bool)X509_isAssertedDomain: (OFString*)asserted equalDomain: (OFString*)domain;

@end


@implementation MBEDX509Certificate

static OFString* objmbedtls_x509_info_subject_alt_name(const mbedtls_x509_sequence *subject_alt_name ) {


    const mbedtls_x509_sequence *cur = subject_alt_name;
    OFDataArray* bytes = [OFDataArray dataArrayWithItemSize:sizeof(char)];
    
    const char *sep = "";
    size_t sep_len = 0;

    while( cur != NULL )
    {	
        [bytes addItems:sep count:sep_len];
        [bytes addItems:cur->buf.p count:cur->buf.len];

        sep = ", ";
        sep_len = 2;

        cur = cur->next;
    }
    
    return [OFString stringWithUTF8String:(char *)[bytes items] length:([bytes count] * [bytes itemSize])];
}

static OFString* objmbedtls_x509_info_cert_type(unsigned char ns_cert_type ) {

	OFDataArray* bytes = [OFDataArray dataArrayWithItemSize:sizeof(char)];

#define PRINT_ITEM(i)                           \
    {                                           \
    	[bytes addItems:sep count:strlen(sep)];	\
    	[bytes addItems:i count:strlen(i)];	\
        sep = ", ";                             \
    }

#define CERT_TYPE(type,name)                    \
    if( ns_cert_type & type )                   \
        PRINT_ITEM( name );

	const char *sep = "";

    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT,         "SSL Client" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,         "SSL Server" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_EMAIL,              "Email" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING,     "Object Signing" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_RESERVED,           "Reserved" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_SSL_CA,             "SSL CA" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA,           "Email CA" );
    CERT_TYPE( MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA,  "Object Signing CA" );


#undef CERT_TYPE

    return [OFString stringWithUTF8String:[bytes items] length:([bytes count] * [bytes itemSize])];
}

#define KEY_USAGE(code,name)    \
    if( key_usage & code )      \
        PRINT_ITEM( name );

static OFString* objmbedtls_x509_info_key_usage(unsigned int key_usage )
{
    OFDataArray* bytes = [OFDataArray dataArrayWithItemSize:sizeof(char)];
    const char *sep = "";

    KEY_USAGE( MBEDTLS_X509_KU_DIGITAL_SIGNATURE,    "Digital Signature" );
    KEY_USAGE( MBEDTLS_X509_KU_NON_REPUDIATION,      "Non Repudiation" );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_ENCIPHERMENT,     "Key Encipherment" );
    KEY_USAGE( MBEDTLS_X509_KU_DATA_ENCIPHERMENT,    "Data Encipherment" );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_AGREEMENT,        "Key Agreement" );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_CERT_SIGN,        "Key Cert Sign" );
    KEY_USAGE( MBEDTLS_X509_KU_CRL_SIGN,             "CRL Sign" );
    KEY_USAGE( MBEDTLS_X509_KU_ENCIPHER_ONLY,        "Encipher Only" );
    KEY_USAGE( MBEDTLS_X509_KU_DECIPHER_ONLY,        "Decipher Only" );

    return [OFString stringWithUTF8String:[bytes items] length:([bytes count] * [bytes itemSize])];
}

#undef PRINT_ITEM
#undef KEY_USAGE

static OFString* objmbedtls_x509_info_ext_key_usage(const mbedtls_x509_sequence *extended_key_usage )
{
    const char *desc;
    OFDataArray* bytes = [OFDataArray dataArrayWithItemSize:sizeof(char)];
    const mbedtls_x509_sequence *cur = extended_key_usage;
    const char *sep = "";

    while( cur != NULL )
    {
        if( mbedtls_oid_get_extended_key_usage( &cur->buf, &desc ) != 0 )
            desc = "???";
        [bytes addItems:sep count:strlen(sep)];
        [bytes addItems:desc count:strlen(desc)];

        sep = ", ";

        cur = cur->next;
    }

    return [OFString stringWithUTF8String:[bytes items] length:([bytes count] * [bytes itemSize])];
}

@dynamic certificate;
@synthesize issuer = _issuer;
@synthesize subject = _subject;
@synthesize subjectAlternativeNames = _subjectAlternativeNames;
@synthesize version = _version;
@synthesize signatureAlgorithm = _signatureAlgorithm;
@synthesize issued = _issued;
@synthesize expires = _expires;
@synthesize keySize = _keySize;
@synthesize type = _type;
@synthesize isCA = _isCA;
@synthesize maxPathLength = _maxPathLength;
@synthesize keyUsage = _keyUsage;
@synthesize extendedKeyUsage = _extendedKeyUsage;
@synthesize serialNumber = _serialNumber;
@dynamic PK;

+ (instancetype)certificate
{
	return [[[self alloc] init] autorelease];
}

+ (instancetype)certificateWithFile:(OFString *)file
{
	return [[[self alloc] initWithFile:file] autorelease];
}

+ (instancetype)certificateWithFilesAtPath:(OFString *)path
{
	return [[[self alloc] initWithFilesAtPath:path] autorelease];
}

+ (instancetype)certificateWithX509Struct:(mbedtls_x509_crt *)crt
{
	return [[[self alloc] initWithX509Struct:crt] autorelease];
}

+ (instancetype)certificateWithPEMString:(OFString *)string
{
	return [[[self alloc] initWithCertificatePEMString:string] autorelease];
}

+ (instancetype)certificateWithPEMorDERData:(OFDataArray *)data
{
	return [[[self alloc] initWithCertificatePEMorDERData:data] autorelease];
}

- (instancetype)init
{
	self = [super init];

	mbedtls_x509_crt_init(self.certificate);

	_isCA = false;
	_maxPathLength = 0;
	_version = 0;
	_PK = nil;

	return self;
}

- (void)dealloc
{
	[_issuer release];
	[_subject release];
	[_subjectAlternativeNames release];
	[_signatureAlgorithm release];
	[_issued release];
	[_expires release];
	[_type release];
	[_keyUsage release];
	[_extendedKeyUsage release];
	[_serialNumber release];
	[_PK release];
	mbedtls_x509_crt_free(self.certificate);

	[super dealloc];
}

- (instancetype)initWithFile:(OFString *)file
{
	self = [self init];

	@try {
		[self parseFile:file];
	}@catch(id e) {
		[self release];

		if ([e isKindOfClass:[MBEDTLSException class]]) {
			@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDX509Certificate class] errorNumber:((MBEDTLSException *)e).errNo];
		}

		@throw e;
	}

	[self X509_fillProperties];

	return self;
}

- (instancetype)initWithFilesAtPath:(OFString *)path
{
	self = [self init];
	@try {
		[self parseFilesAtPath:path];
	}@catch(id e) {
		[self release];

		if ([e isKindOfClass:[MBEDTLSException class]]) {
			@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDX509Certificate class] errorNumber:((MBEDTLSException *)e).errNo];
		}

		@throw e;
	}

	[self X509_fillProperties];

	return self;
}

- (instancetype)initWithX509Struct:(mbedtls_x509_crt *)crt
{

	self = [self init];

	if (crt == NULL) {
		[self release];
		@throw [OFInvalidArgumentException exception];
	}

	int ret = 0;

	if ((ret = mbedtls_x509_crt_parse_der(self.certificate, crt->raw.p, crt->raw.len)) != 0) {
		[self release];
		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDX509Certificate class] errorNumber:ret];
	}

	[self X509_fillProperties];

	return self;
}

- (instancetype)initWithCertificatePEMString:(OFString *)string
{
	self = [self init];

	if ([string UTF8StringLength] <= 0) {
		[self release];
		@throw [OFInvalidArgumentException exception];
	}

	@try {
		[self parsePEM:string];

	}@catch(id e) {
		[self release];

		if ([e isKindOfClass:[MBEDTLSException class]]) {
			@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDX509Certificate class] errorNumber:((MBEDTLSException *)e).errNo];
		}

		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}

	[self X509_fillProperties];

	return self;
}
- (instancetype)initWithCertificatePEMorDERData:(OFDataArray *)data
{
	self = [self init];

	if ([data count] <= 0) {
		[self release];
		@throw [OFInvalidArgumentException exception];
	}

	int ret = 0;

	if (strstr( (const char *)[data items], "-----BEGIN CERTIFICATE-----" ) != NULL) {
		if (*((char *)[data lastItem]) != '\0')
			[data addItems:"" count:1];
	}

	if ((ret = mbedtls_x509_crt_parse(self.certificate, (const unsigned char *)[data items], ([data count] * [data itemSize]))) != 0) {
		[self release];
		@throw [MBEDInitializationFailedException exceptionWithClass:[MBEDX509Certificate class] errorNumber:ret];
	}

	[self X509_fillProperties];

	return self;
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

- (OFDictionary *)X509_dictionaryFromX509AltNames:(OFString *)names
{
	OFMutableDictionary* dictionary = [OFMutableDictionary dictionary];
	OFArray* namesArray = [names componentsSeparatedByString:[OFString stringWithUTF8String:", "]];
	OFString* dNSName = [OFString stringWithUTF8String:"dNSName"];

	OFAutoreleasePool* pool = [OFAutoreleasePool new];
	
	for (OFString* name in namesArray) {
		
		if ([dictionary objectForKey:dNSName] == nil) {
			[dictionary setObject:[OFMutableArray array] forKey:dNSName];
		}

		[[dictionary objectForKey:dNSName] addObject:name];

		[pool releaseObjects];
	}
	[[dictionary objectForKey:dNSName] makeImmutable];

	[pool release];

	[dictionary makeImmutable];

	return dictionary;
}

- (OFArray *)X509_arrayFromX509KeyUsageString:(OFString *)string
{
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	OFMutableArray* array = [OFMutableArray arrayWithArray:[string componentsSeparatedByString:[OFString stringWithUTF8String:", "]]];

	[array retain];

	[pool release];

	[array makeImmutable];

	return [array autorelease];

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

	ret = mbedtls_x509_serial_gets(buf, bufSize, &(self.certificate->serial));
	if (ret > 0)
		self.serialNumber = [OFString stringWithUTF8String:buf length:ret];
	else {
		objc_autoreleasePoolPop(pool);
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}

	memset(buf, 0, bufSize);

	OFString* dnString = nil;

	ret = mbedtls_x509_dn_gets(buf, bufSize, &(self.certificate->issuer));
	if (ret > 0) {

		@try {
			dnString = [OFString stringWithUTF8String:buf length:ret];
		}@catch(id e) {
			dnString = nil;
		}

		if (nil == dnString) {
			dnString = parse_dn_string(buf, (size_t)ret);	
		}

		self.issuer = [self X509_dictionaryFromX509Name:dnString];
	}
	else {
		objc_autoreleasePoolPop(pool);
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}

	memset(buf, 0, bufSize);

	ret = mbedtls_x509_dn_gets(buf, bufSize, &(self.certificate->subject));
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
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}
	if (self.certificate->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME)
		self.subjectAlternativeNames = [self X509_dictionaryFromX509AltNames:objmbedtls_x509_info_subject_alt_name(&(self.certificate->subject_alt_names))];

	self.version = (uint8_t)self.certificate->version;

	memset(buf, 0, bufSize);

	ret = mbedtls_x509_sig_alg_gets(buf, bufSize, &(self.certificate->sig_oid), self.certificate->sig_pk, self.certificate->sig_md, self.certificate->sig_opts);

	if (ret > 0)
		self.signatureAlgorithm = [OFString stringWithUTF8String:buf length:ret];
	else {
		objc_autoreleasePoolPop(pool);
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}

	OFString* dtFormat = [OFString stringWithUTF8String:"%Y-%m-%d %H:%M:%S"];
	OFString* dtSString = [OFString stringWithFormat:@"%04d-%02d-%02d %02d:%02d:%02d",
			self.certificate->valid_from.year, self.certificate->valid_from.mon,
            self.certificate->valid_from.day,  self.certificate->valid_from.hour,
            self.certificate->valid_from.min,  self.certificate->valid_from.sec
		];
	OFString* dtEString = [OFString stringWithFormat:@"%04d-%02d-%02d %02d:%02d:%02d",
			self.certificate->valid_to.year, self.certificate->valid_to.mon,
            self.certificate->valid_to.day,  self.certificate->valid_to.hour,
            self.certificate->valid_to.min,  self.certificate->valid_to.sec
		];

	self.issued = [OFDate dateWithLocalDateString:dtSString format:dtFormat];

	self.expires = [OFDate dateWithLocalDateString:dtEString format:dtFormat];

	self.keySize = (int)mbedtls_pk_get_bitlen( &(self.certificate->pk) );

	if( self.certificate->ext_types & MBEDTLS_X509_EXT_NS_CERT_TYPE )
		self.type = objmbedtls_x509_info_cert_type(self.certificate->ns_cert_type);

	if( self.certificate->ext_types & MBEDTLS_X509_EXT_KEY_USAGE )
		self.keyUsage = [self X509_arrayFromX509KeyUsageString:objmbedtls_x509_info_key_usage(self.certificate->key_usage)];

	if( self.certificate->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE )
		self.extendedKeyUsage = [self X509_arrayFromX509KeyUsageString:objmbedtls_x509_info_ext_key_usage(&(self.certificate->ext_key_usage))];

	if( self.certificate->ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS ) {
		self.isCA = self.certificate->ca_istrue ? true : false;

		if (self.certificate->max_pathlen > 0)
			self.maxPathLength = (size_t)(self.certificate->max_pathlen - 1);
	}


	objc_autoreleasePoolPop(pool);
}

- (void)parseFilesAtPath:(OFString *)path
{
	OFFileManager* filemanager = [OFFileManager defaultManager];

	if ([filemanager directoryExistsAtPath:path]) {

		OFAutoreleasePool* pool = [OFAutoreleasePool new];

		size_t count = 0;
		for (OFString* subPath in [filemanager contentsOfDirectoryAtPath:path]) {

			if ([filemanager fileExistsAtPath:subPath]) {

				@try {
					[self parseFile:subPath];

					count++;

				} @catch(id e) {}
			}

			[pool releaseObjects];

			continue;
		}

		[pool release];

		if (count <= 0) {

			@throw [OFInvalidArgumentException exception];
		}

		return;
	}

	@throw [OFInvalidArgumentException exception];
}

- (void)parseFile:(OFString *)file
{
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	OFDataArray* data = [OFDataArray dataArrayWithContentsOfFile:file];
	
	if ([data count] == 0 || [data lastItem] == NULL) {
		[pool release];
		@throw [OFInvalidArgumentException exception];
	}

	if (strstr( (const char *)[data items], "-----BEGIN CERTIFICATE-----" ) != NULL) {
		
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

	return;

}

- (bool)hasCommonNameMatchingDomain: (OFString*)domain
{
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	OFList* CNs = [self.subject objectForKey:[OFString stringWithUTF8String:"CN"]];

	for (OFString* name in CNs) {
		if ([self X509_isAssertedDomain:name equalDomain:domain]) {
			[pool release];
			return true;
		}
	}

	[pool release];
	return false;
}

- (bool)hasDNSNameMatchingDomain: (OFString*)domain
{
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	OFList* assertedNames = [self.subjectAlternativeNames objectForKey:[OFString stringWithUTF8String:"dNSName"]];

	for (OFString* name in assertedNames) {
		if ([self X509_isAssertedDomain:name equalDomain:domain]) {
			[pool release];
			return true;
		}
	}

	[pool release];
	return false;
}

- (bool)X509_isAssertedDomain: (OFString*)asserted equalDomain: (OFString*)domain
{
	/*
	 * In accordance with RFC 6125 this only allows a wildcard as the
	 * left-most label and matches only the left-most label with it.
	 * E.g. *.example.com matches foo.example.com,
	 * but not foo.bar.example.com
	 */

	size_t firstValueDot;

	if ([asserted caseInsensitiveCompare: domain] == OF_ORDERED_SAME)
		return true;

	if (![asserted hasPrefix: @"*."])
		return false;

	asserted = [asserted substringWithRange:of_range(2, [asserted length] - 2)];

	firstValueDot = [domain rangeOfString: @"."].location;
	if (firstValueDot == OF_NOT_FOUND)
		return false;

	domain = [domain substringWithRange:of_range(firstValueDot + 1, [domain length] - firstValueDot - 1)];

	if (![asserted caseInsensitiveCompare: domain])
		return true;

	return false;
}

- (bool)hasSRVNameMatchingDomain: (OFString*)domain service: (OFString*)service
{
	@throw [OFNotImplementedException exceptionWithSelector:@selector(hasSRVNameMatchingDomain:service:) object:self];
	/*
	size_t serviceLength;
	OFString *name;
	OFAutoreleasePool *pool = [[OFAutoreleasePool alloc] init];
	OFDictionary *SANs = [self subjectAlternativeName];
	OFList *assertedNames = [[SANs objectForKey: @"otherName"]
				     objectForKey: OID_SRVName];
	OFEnumerator *enumerator = [assertedNames objectEnumerator];

	if (![service hasPrefix: @"_"])
		service = [service stringByPrependingString: @"_"];

	service = [service stringByAppendingString: @"."];
	serviceLength = [service length];

	while ((name = [enumerator nextObject]) != nil) {
		if ([name hasPrefix: service]) {
			OFString *asserted;
			asserted = [name substringWithRange: of_range(
			    serviceLength, [name length] - serviceLength)];
			if ([self X509_isAssertedDomain: asserted
					    equalDomain: domain]) {
				[pool release];
				return true;
			}
		}
	}

	[pool release];
	return false;
	*/
}

- (MBEDX509Certificate *)next
{
	static mbedtls_x509_crt *crt = NULL; 
	static mbedtls_x509_crt *prev = NULL;

	if (crt == NULL)
		crt = self.certificate;

	while( crt->version != 0 && crt->next != NULL )
    {
        prev = crt;
        crt = crt->next;

        return [MBEDX509Certificate certificateWithX509Struct:crt];
    }

    crt = NULL;
    prev = NULL;

	return nil;
}

- (bool)isRevoked:(MBEDCRL*)crl
{
	return (bool)mbedtls_x509_crt_is_revoked(self.certificate, crl.context);
}

- (OFDataArray *)DER
{
	OFDataArray* der = [OFDataArray dataArrayWithItemSize:sizeof(char)];

	[der addItems:self.certificate->raw.p count:self.certificate->raw.len];

	return der;
}

- (OFString *)PEM
{
	return [self PEMwithHeader:@"-----BEGIN CERTIFICATE-----\n" bottom:@"-----END CERTIFICATE-----\n"];
}

- (OFString *)PEMwithHeader:(OFString *)header bottom:(OFString *)bottom
{
	int ret = 0;
	size_t bufLen = 0;

	size_t olen = 0;

	unsigned char* buffer = NULL;

	mbedtls_pem_write_buffer([header UTF8String], [bottom UTF8String], self.certificate->raw.p, self.certificate->raw.len, NULL, 0, &bufLen);

	buffer = (unsigned char*)__builtin_alloca(sizeof(unsigned char) * (bufLen + 1));

	if (buffer == NULL)
		@throw [OFOutOfMemoryException exceptionWithRequestedSize:bufLen];

	if ((ret = mbedtls_pem_write_buffer([header UTF8String], [bottom UTF8String], self.certificate->raw.p, self.certificate->raw.len, buffer, bufLen + 1, &olen)) != 0) {

		if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
			of_log(@"%zu %zu", bufLen, olen);
		}

		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
	}
		

	return [OFString stringWithUTF8String:(const char *)buffer length:olen];
}

- (mbedtls_x509_crt *)certificate
{
	return &_certificate;
}

- (MBEDPKey *)PK
{
	if (_PK == nil) {
		_PK = [[MBEDPKey alloc] initWithStruct:&(self.certificate->pk) isPublic:true];
	}

	return _PK;
}

#if defined(OF_WINDOWS) || defined(OF_LINUX) || defined(OF_MAC_OS_X)
- (instancetype)initWithSystemCA
{
	self = [self init];
	
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

#if defined(OF_WINDOWS)

	HCERTSTORE hStore = CertOpenSystemStore(0, "CA");
	OFDataArray* DER = nil;

	for ( PCCERT_CONTEXT pCertCtx = CertEnumCertificatesInStore(hStore, NULL);

       pCertCtx != NULL;

       pCertCtx = CertEnumCertificatesInStore(hStore, pCertCtx) )
 	{
		bool isPKCS7 = (bool)((pCertCtx->dwCertEncodingType & PKCS_7_ASN_ENCODING) == PKCS_7_ASN_ENCODING);
		bool isCertificate = (bool)((pCertCtx->dwCertEncodingType & X509_ASN_ENCODING) == X509_ASN_ENCODING);

		if (isPKCS7 || isCertificate ) {
			
			DER = [OFDataArray dataArrayWithItemSize:sizeof(char)];

			[DER addItems:(const void *)pCertCtx->pbCertEncoded count:(size_t)pCertCtx->cbCertEncoded];

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

 	[self X509_fillProperties];

 	return self;
}

+ (instancetype)certificateWithSystemCA
{
	return [[[self alloc] initWithSystemCA] autorelease];
}
#endif

- (void)parseDER:(OFDataArray *)der
{
	int ret = 0;

	if ((ret = mbedtls_x509_crt_parse_der(self.certificate, (const unsigned char *)[der items], ([der itemSize] * [der count]))) != 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];
}

- (void)parsePEM:(OFString *)pem
{
	int ret = 0;

	size_t buflen = [pem UTF8StringLength];

	if (((unsigned char *)[pem UTF8String])[buflen - 1] != '\0')
		buflen += 1;

	unsigned char* buf = (unsigned char*)__builtin_alloca(sizeof(unsigned char) * buflen);

	if (buf == NULL)
		@throw [OFOutOfMemoryException exceptionWithRequestedSize:buflen];

	memset(buf, 0, buflen);
	memcpy(buf, [pem UTF8String], [pem UTF8StringLength]);
	buf[buflen-1] = '\0';

	ret = mbedtls_x509_crt_parse(self.certificate, buf, buflen);

	if (ret < 0)
		@throw [MBEDTLSException exceptionWithObject:self errorNumber:ret];

	if (ret > 0)
		of_log(@"Parsed %d certificates", ret);
}

- (OFString*)description
{
	OFMutableString *ret = [OFMutableString string];
	[ret appendUTF8String:"X509 CRT\n"];
	[ret appendFormat: @"Version: v%d\n\n", self.version];
	if (self.type != nil)
		[ret appendFormat: @"Type: %@\n\n", self.type];

	[ret appendFormat: @"Serial Number: %@\n\n", self.serialNumber];
	bool firstValue = true;
	bool firstKey = true;
	[ret appendString:[OFString stringWithUTF8String:"Issuer: "]];

	for (OFString* key in [self.issuer allKeys]) {
		firstValue = true;

		if (!firstKey)
			[ret appendString:[OFString stringWithUTF8String:", "]];

		@autoreleasepool {
			for (OFString* value in [self.issuer objectForKey:key]) {
				if (!firstValue)
					[ret appendString:[OFString stringWithUTF8String:", "]];

				[ret appendFormat:@"%@=%@", key, value];

				if (firstValue)
					firstValue = false;
			}
		}

		if (firstKey)
			firstKey = false;
	}
	[ret appendString:[OFString stringWithUTF8String:"\n\n"]];
	[ret appendString:[OFString stringWithUTF8String:"Subject: "]];
	firstKey = true;
	for (OFString* key in [self.subject allKeys]) {
		firstValue = true;

		if (!firstKey)
			[ret appendString:[OFString stringWithUTF8String:", "]];

		@autoreleasepool {
			for (OFString* value in [self.subject objectForKey:key]) {
				if (!firstValue)
					[ret appendString:[OFString stringWithUTF8String:", "]];

				[ret appendFormat:@"%@=%@", key, value];

				if (firstValue)
					firstValue = false;
			}
		}

		if (firstKey)
			firstKey = false;
	}
	[ret appendString:[OFString stringWithUTF8String:"\n\n"]];
	[ret appendString:[OFString stringWithUTF8String:"SANs: "]];
	for (OFString* key in [self.subjectAlternativeNames allKeys]) {
		firstValue = true;
		@autoreleasepool {
			for (OFString* value in [self.subjectAlternativeNames objectForKey:key]) {
				if (!firstValue)
					[ret appendString:[OFString stringWithUTF8String:", "]];

				[ret appendString:value];

				if (firstValue)
					firstValue = false;
			}
		}
	}
	[ret appendString:[OFString stringWithUTF8String:"\n\n"]];
	[ret appendFormat: @"Issued on: %@\n\n", [self.issued localDateStringWithFormat:@"%Y-%m-%d %H:%M:%S"]];
	[ret appendFormat: @"Expires on: %@\n\n", [self.expires localDateStringWithFormat:@"%Y-%m-%d %H:%M:%S"]];
	[ret appendFormat: @"Signature Algorithm: %@\n\n", self.signatureAlgorithm];
	
	char key_size_str[256];
	size_t key_size_str_len = (size_t)(sizeof(key_size_str) * sizeof(char));
	memset(key_size_str, 0, key_size_str_len);

	if ((mbedtls_x509_key_size_helper( key_size_str, key_size_str_len, mbedtls_pk_get_name( &(self.certificate->pk) ))) != 0) {
		[ret appendFormat: @"Key Size: %d bits", self.keySize];
	} else {
		[ret appendFormat: @"%s: %d bits", key_size_str, self.keySize];
	}

	[ret appendString: @"\n\n"];

	[ret appendFormat: @"Basic constraints: %@", (self.isCA ? @"Yes" : @"No")];
	if (self.maxPathLength > 0)
		[ret appendFormat: @", max_pathlen=%zu", self.maxPathLength];

	if (self.keyUsage) {
		[ret appendString: @"\n\n"];
		[ret appendFormat: @"Key Usage: %@", self.keyUsage];
	}

	if (self.extendedKeyUsage) {
		[ret appendString: @"\n\n"];
		[ret appendFormat: @"Extended Key Usage: %@", self.extendedKeyUsage];
	}
	
	[ret makeImmutable];
	return ret;
}

@end