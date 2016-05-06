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
	bool connected = true;
	@try {
		[socket connectToHost:@"173.194.222.139" port:443]; //exception expected
	}@catch (id e) {
		of_log(@"%@", e);
		connected = false;
	}

	if (connected) {
		[socket writeLine:@"GET / HTTP/1.0\r\n"];

		while (!socket.isAtEndOfStream) {
			OFString* l = [socket readLine];
			of_log(@"%@", l);
		}
	}

	connected = true;
	socket.certificateVerificationEnabled = false;
	@try {
		[socket connectToHost:@"173.194.222.139" port:443]; //exception not expected
	}@catch(id e) {
		of_log(@"Not expected exception - %@", e);
		connected = false;
	}
	if (connected) {
		[socket writeLine:@"GET / HTTP/1.0\r\n"];

		while (!socket.isAtEndOfStream) {
			OFString* l = [socket readLine];
			of_log(@"%@", l);
		}

		[socket close];
	}


	connected = true;
	socket.certificateVerificationEnabled = true;

	@try {
		[socket connectToHost:@"google.com" port:443]; //exception not expected
	}@catch(id e) {
		of_log(@"Not expected exception - %@", e);
		connected = false;
	}
	if (connected) {

		[socket writeLine:@"GET / HTTP/1.0\r\n"];

		while (!socket.isAtEndOfStream) {
			OFString* l = [socket readLine];
			of_log(@"%@", l);
		}
		
		[socket close];
	}

	OFTCPSocket* sk = [OFTCPSocket socket];

	of_log(@"Not SSL test");
	[sk connectToHost:@"google.com" port:443];
	[sk writeLine:@"GET / HTTP/1.0\r\n"];

		while (!sk.isAtEndOfStream) {
			OFString* l = [sk readLine];
			of_log(@"%@", l);
		}
	[sk close];
}

@end