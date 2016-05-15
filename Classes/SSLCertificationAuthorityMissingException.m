#import <ObjFW/ObjFW.h>
#import "MBEDSSLSocket.h"
#import "SSLCertificationAuthorityMissingException.h"

@interface SSLCertificationAuthorityMissingException()

@property(retain, readwrite)MBEDSSLSocket* socket;

@end


@implementation SSLCertificationAuthorityMissingException

@synthesize socket = _socket;

- (instancetype)initWithSocket:(MBEDSSLSocket *)socket
{
	self = [super init];

	self.socket = socket;

	return self;
}

+ (instancetype)exceptionWithSocket:(MBEDSSLSocket *)socket
{
	return [[[self alloc] initWithSocket:socket] autorelease];
}

@end