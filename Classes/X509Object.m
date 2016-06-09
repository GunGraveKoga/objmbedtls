#import <ObjFW/ObjFW.h>
#import "X509Object.h"
#import "PEM.h"
#import "MBEDTLSException.h"

#include <mbedtls/pem.h>

@implementation X509Object

@dynamic PEM;
@dynamic DER;

- (void)parseDER:(OFDataArray *)der
{
	OF_UNRECOGNIZED_SELECTOR
}

- (void)parseDER:(OFDataArray *)der password:(OFString *)password
{
	OF_UNRECOGNIZED_SELECTOR
}

- (void)parseFile:(OFString *)fileName
{
	[self parseFile:fileName password:nil];
}

- (void)parseFilesAtPath:(OFString *)path
{
	id exception = nil;

	OFFileManager* fmgr = [OFFileManager defaultManager];

	if ([fmgr directoryExistsAtPath:path]) {

		OFAutoreleasePool* pool = [OFAutoreleasePool new];

		@try {

			if ([[fmgr contentsOfDirectoryAtPath:path] count] <= 2) {

				[pool release];

				return;
			}

			for (OFString* file in [fmgr contentsOfDirectoryAtPath:path]) {
				@autoreleasepool {

					if ([file isEqual:@"."] || [file isEqual:@".."])
						continue;

					[self parseFile:file];
				}
			}

		} @catch(OFException* e) {
			exception = [e retain];

			@throw;

		} @finally {
			[pool release];
			[exception autorelease];
		}

		return;

	} 
	
	@throw [OFInvalidArgumentException exception];
}

- (void)parsePEMorDER:(OFDataArray *)data header:(OFString *)header footer:(OFString *)footer password:(_Nullable OFString *)password
{
	id exception = nil;

	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	@try {

		if (!isPEM(data)) {
			if (password == nil)
				[self parseDER:data];
			else
				[self parseDER:data password:password];
			
		} else if (hasHeader(data, header) && hasFooter(data, footer)) {
			
			OFArray* DERs;
			
			DERs = PEMtoDER([OFString stringWithUTF8String:(const char *)[data items] length:[data count]], header, footer, password);

			for (OFDataArray* der in DERs) {
				if (password == nil)
					[self parseDER:der];
				else
					[self parseDER:der password:password];
			}

		} else {
			@throw [MBEDTLSException exceptionWithObject:self errorNumber:MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT];
		}


	} @catch (MBEDTLSException* exc) {

		if (exc.sourceObject == nil) {
			exception = [[MBEDTLSException alloc] initWithObject:self errorNumber:exc.errNo];

			@throw exception;

		} else {
			exception = [exc retain];

			@throw;
		}

	} @catch (id e) {
		exception = [e retain];

		@throw;

	}@finally {
		[pool release];

		if (exception != nil)
			[exception autorelease];
	}
}

- (void)parsePEM:(OFString *)pem
{
	[self parsePEM:pem password:nil];
}

- (void)parsePEM:(OFString *)pem password:(OFString *)password
{
	id exception = nil;

	OFAutoreleasePool* pool = [OFAutoreleasePool new];
	
	OFDataArray* data = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];

	[data addItems:[pem UTF8String] count:[pem UTF8StringLength]];

	@try {

		[self parsePEMorDER:data password:password];

	} @catch (id e) {

		exception = [e retain];

		@throw;

	}@finally{
		[pool release];

		if (exception != nil)
			[exception autorelease];
	}

}

- (void)parsePEMorDER:(OFDataArray *)data password:(_Nullable OFString *)password
{
	OF_UNRECOGNIZED_SELECTOR
}

- (void)parseFile:(OFString *)fileName password:(OFString*)password
{
	OFDataArray* data = nil;
	@try {

		data = [[OFDataArray alloc] initWithContentsOfFile:fileName];

		[self parsePEMorDER:data password:password];

		[data release];

	}@catch(id e) {
		if (data != nil)
			[data release];

		@throw e;

	}

}

@end