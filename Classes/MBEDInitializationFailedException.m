#import <ObjFW/ObjFW.h>
#import "MBEDInitializationFailedException.h"

#include <mbedtls/error.h>

@interface MBEDInitializationFailedException()

@property (readwrite, assign) Class inClass;

@end

@implementation MBEDInitializationFailedException

- (instancetype)initWithClass:(Class)class_ errorNumber:(int)error
{
	self = [super init];

	self.inClass = class_;
	_errNo = error;

	return self;
}

+ (instancetype)exceptionWithClass:(Class)class_ errorNumber:(int)error
{
	return [[[self alloc] initWithClass:class_ errorNumber:error] autorelease];
}

- (OFString*)description
{
	return [OFString stringWithFormat:
	    @"Initialization failed for or in class %@! (%@)", _inClass, [self errorDescription]];
}

@end