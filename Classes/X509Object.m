#import <ObjFW/ObjFW.h>
#import "X509Object.h"
#import "PEM.h"

@implementation X509Object

@dynamic PEM;
@dynamic DER;

- (void)parseDER:(OFDataArray *)der
{
	OF_UNRECOGNIZED_SELECTOR
}

- (void)parseFile:(OFString *)fileName
{
	OF_UNRECOGNIZED_SELECTOR
}

- (void)parseFilesAtPath:(OFString *)path
{
	OFFileManager* fmgr = [OFFileManager defaultManager];

	

	if ([fmgr directoryExistsAtPath:path]) {

		OFAutoreleasePool* pool = [OFAutoreleasePool new];

		@try {

			if ([[fmgr contentsOfDirectoryAtPath:path] count] <= 3) {

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
			[e retain];
			[pool release];

			@throw [e autorelease];
		}

		return;

	} 
	
	@throw [OFInvalidArgumentException exception];
}

- (void)parsePEMorDER:(OFDataArray *)data header:(OFString *)header footer:(OFString *)footer password:(_Nullable OFString *)password
{
	OFAutoreleasePool* pool = [OFAutoreleasePool new];

	@try {

		if (!isPEM(data)) {
			[self parseDER:data];

			[pool release];

			return;
		}
		
		if (hasHeader(data, header) && hasFooter(data, footer)) {
			
			OFArray* DERs;
			
			DERs = PEMtoDER([OFString stringWithUTF8String:(const char *)[data items] length:[data count]], header, footer, password);

			for (OFDataArray* der in DERs) {
				@autoreleasepool {
					
					[self parseDER:der];

				}
			}

		} else {
			@throw [OFInvalidArgumentException exception];
		}


	} @catch (id e) {
		[e retain];
		[pool release];

		@throw [e autorelease];
	}

	[pool release];
}

- (void)parsePEM:(OFString *)pem
{
	OFAutoreleasePool* pool = [OFAutoreleasePool new];
	
	OFDataArray* data = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];

	[data addItems:[pem UTF8String] count:[pem UTF8StringLength]];

	@try {

		[self parsePEMorDER:data password:nil];

	} @catch (id e) {

		[e retain];
		[pool release];

		@throw e;

	}

	[pool release];
}

- (void)parsePEMorDER:(OFDataArray *)data password:(_Nullable OFString *)password
{
	OF_UNRECOGNIZED_SELECTOR
}

@end