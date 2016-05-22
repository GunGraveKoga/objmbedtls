#import <ObjFW/OFObject.h>
#import <ObjFW/OFException.h>
#import "MBEDTLSException.h"


@interface MBEDInitializationFailedException: MBEDTLSException
{
	Class _inClass;
}

@property (readonly, assign) Class inClass;

- (instancetype)initWithClass:(Class)class_ errorNumber:(int)error;
+ (instancetype)exceptionWithClass:(Class)class_ errorNumber:(int)error;

@end