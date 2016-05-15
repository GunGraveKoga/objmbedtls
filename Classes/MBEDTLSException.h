#import <ObjFW/OFObject.h>
#import <ObjFW/OFException.h>


@interface MBEDTLSException: OFException
{
	int _errNo;
	id _sourceObject;

}

@property (assign, readonly)int errNo;
@property (retain, readonly)id sourceObject;

- (instancetype)initWithObject:(id)object errorNumber:(int)errNo;
+ (instancetype)exceptionWithObject:(id)object errorNumber:(int)errNo;

@end