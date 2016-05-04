#import <ObjFW/ObjFW.h>
#import "MBEDSSLSocket.h"
#import "MBEDCRL.h"
#import "MBEDX509Certificate.h"
#import "MBEDPrivateKey.h"
#import "MBEDSSL.h"

static unsigned long
get_thread_id(void)
{
	return (unsigned long)(uintptr_t)[OFThread currentThread];
}

@interface Test: OFObject<OFApplicationDelegate>
{

}
- (void)applicationDidFinishLaunching;
@end

OF_APPLICATION_DELEGATE(Test)

@implementation Test

- (void)applicationDidFinishLaunching
{
	MBEDSSLSocket* socket = [MBEDSSLSocket socket];
	socket.certificateVerificationEnabled = false;
	[socket connectToHost:@"google.com" port:443];
	[socket writeLine:@"GET / HTTP/1.0\r\n"];

	while (!socket.isAtEndOfStream) {
		OFString* l = [socket readLine];
		of_log(@"%@", l);
	}
}

@end