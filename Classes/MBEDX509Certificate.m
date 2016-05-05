#import <ObjFW/ObjFW.h>
#import "MBEDX509Certificate.h"


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


- (OFDictionary *)X509_dictionaryFromX509Name:(OFString *)name;
- (OFDictionary *)X509_dictionaryFromX509AltNames:(OFString *)names;
- (void)X509_fillProperties;

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

#undef PRINT_ITEM
#undef CERT_TYPE

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

- (instancetype)init
{
	self = [super init];

	mbedtls_x509_crt_init(self.certificate);

	return self;
}

- (void)dealloc
{
	mbedtls_x509_crt_free(self.certificate);
	[_issuer release];
	[_subject release];
	[_subjectAlternativeNames release];
	[super dealloc];
}

- (instancetype)initWithFile:(OFString *)file
{
	self = [self init];

	@try {
		[self parseFile:file];
	}@catch(OFException* e) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}

	return self;
}

- (instancetype)initWithFilesAtPath:(OFString *)path
{
	self = [self init];
	@try {
		[self parseFilesAtPath:path];
	}@catch(OFException* e) {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}
	return self;
}

- (instancetype)initWithX509Struct:(mbedtls_x509_crt *)crt
{
	self = [self init];

	memcpy(self.certificate, crt, sizeof(mbedtls_x509_crt));

	[self X509_fillProperties];

	return self;
}

- (OFDictionary *)X509_dictionaryFromX509Name:(OFString *)name
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

- (OFDictionary *)X509_dictionaryFromX509AltNames:(OFString *)names
{
	OFMutableDictionary* dictionary = [OFMutableDictionary dictionary];
	OFArray* namesArray = [names componentsSeparatedByString:[OFString stringWithUTF8String:", "]];
	OFString* dNSName = [OFString stringWithUTF8String:"dNSName"];

	OFAutoreleasePool* pool = [OFAutoreleasePool new];
	
	for (OFString* name in namesArray) {
		
		if ([dictionary objectForKey:dNSName] == nil) {
			[dictionary setObject:[OFList list] forKey:dNSName];
		}

		[[dictionary objectForKey:dNSName] appendObject:name];

		[pool releaseObjects];
	}

	[pool release];

	[dictionary makeImmutable];

	return dictionary;
}

- (void)X509_fillProperties
{
	void* pool = objc_autoreleasePoolPush();

	size_t bufSize = sizeof(char) * 4096;
	int ret = 0;
	char* buf = (char *)__builtin_alloca(bufSize);
	memset(buf, 0, bufSize);

	ret = mbedtls_x509_dn_gets(buf, bufSize, &(self.certificate->issuer));
	if (ret > 0)
		self.issuer = [self X509_dictionaryFromX509Name:[OFString stringWithUTF8String:buf length:ret]];
	else {
		[self release];
		@throw [OFInitializationFailedException exceptionWithClass:[MBEDX509Certificate class]];
	}

	memset(buf, 0, bufSize);

	ret = mbedtls_x509_dn_gets(buf, bufSize, &(self.certificate->subject));
	if (ret > 0)
		self.subject = [self X509_dictionaryFromX509Name:[OFString stringWithUTF8String:buf length:ret]];
	else {
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
		;

	if( self.certificate->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE )
		;

	objc_autoreleasePoolPop(pool);
}

- (void)parseFilesAtPath:(OFString *)path
{
	if ( (mbedtls_x509_crt_parse_path(self.certificate, [path UTF8String])) != 0) {
		@throw [OFInvalidArgumentException exception];
	}
	[self X509_fillProperties];
}

- (void)parseFile:(OFString *)file
{
	if ( (mbedtls_x509_crt_parse_file(self.certificate, [file UTF8String])) != 0) {
		[self release];
		@throw [OFInvalidArgumentException exception];;
	}
	[self X509_fillProperties];
}

- (mbedtls_x509_crt *)certificate
{
	return &_certificate;
}

- (OFString*)description
{
	OFMutableString *ret = [OFMutableString string];

	[ret appendFormat: @"Version: v%d\n\n", self.version];
	if (self.type != nil)
		[ret appendFormat: @"Type: %@\n\n", self.type];
	[ret appendFormat: @"Issuer: %@\n\n", self.issuer];
	[ret appendFormat: @"Subject: %@\n\n", self.subject];
	[ret appendFormat: @"SANs: %@\n\n", self.subjectAlternativeNames];
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

	[ret makeImmutable];
	return ret;
}

@end