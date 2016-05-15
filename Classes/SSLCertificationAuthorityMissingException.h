#import <ObjFW/OFObject.h>
#import <ObjFW/OFException.h>

@class MBEDSSLSocket;

@interface SSLCertificationAuthorityMissingException: OFException
{
    MBEDSSLSocket* _socket;
}

@property(retain, readonly)MBEDSSLSocket* socket;

- (instancetype)initWithSocket:(MBEDSSLSocket *)socket;
+ (instancetype)exceptionWithSocket:(MBEDSSLSocket *)socket;

@end