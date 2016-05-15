#import <ObjFW/ObjFW.h>
#import "MBEDTLSException.h"

#include <mbedtls/error.h>

@interface MBEDTLSException()

@property (assign, readwrite)int errNo;
@property (retain, readwrite)id sourceObject;

@end

@implementation MBEDTLSException

- (instancetype)init
{
	self = [super init];

	self.sourceObject = nil;
	self.errNo = 0;

	return self;
}

- (instancetype)initWithObject:(id)object errorNumber:(int)errNo
{
	self = [super init];

	self.sourceObject = object;
	self.errNo = errNo;

	return self;
}

+ (instancetype)exceptionWithObject:(id)object errorNumber:(int)errNo
{
	return [[[self alloc] initWithObject:object errorNumber:errNo] autorelease];
}

- (OFString *)description
{

	char buffer[4096] = {0};

	mbedtls_strerror( _errNo, buffer, sizeof(buffer) );

	return [OFString stringWithFormat:@"An exception occurred in object %@: %s", self.sourceObject, buffer];
}

@end