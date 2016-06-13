#import <ObjFW/ObjFW.h>
#import <WinBacktrace.h>
#import "MBEDSSLSocket.h"
#import "MBEDSSLConfig.h"
#import "MBEDCRL.h"
#import "MBEDX509Certificate.h"
#import "MBEDPKey.h"
#import "MBEDSSL.h"


@interface Test: OFObject<OFApplicationDelegate>
{

}
- (void)applicationDidFinishLaunching;
@end

OF_APPLICATION_DELEGATE(Test)

@implementation Test

- (void)applicationDidFinishLaunching
{
	WinBacktrace* plugin = [OFPlugin pluginFromFile:@"WinBacktrace"];
	
	of_log(@"Verification exception:\n\n");
	bool connected = true;
	MBEDSSLSocket* socket = [MBEDSSLSocket socket];
	//socket.sslVersion = OBJMBED_SSLVERSION_TLSv1_2;
	//socket.certificateProfile = kNextDefaultProfile;
	socket.CA = [MBEDX509Certificate certificateWithFile:@"./GIAG2.crt"];
	of_log(@"%@", socket.CA);
	//socket.sslVersion = OBJMBED_SSLVERSION_TLSv1_2;

	@try {
		[socket connectToHost:@"173.194.222.139" port:443]; //exception expected
	}@catch (id e) {
		of_log(@"Expected exception - %@", e);
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
	socket.certificateVerificationEnabled = false;
	of_log(@"Internal verification:\n\n");
	@try {
		[socket connectToHost:@"173.194.222.139" port:443]; //exception not expected
	}@catch(id e) {
		of_log(@"Expected exception - %@", e);
		connected = false;
	}
	if (connected) {
		of_log(@"Key: %@", socket.peerCertificate);
		of_log(@"Key: %@", socket.peerCertificate.publicKey);
		of_log(@"DER: %@", socket.peerCertificate.publicKey.DER);
		of_log(@"PEM: \n%@", socket.peerCertificate.publicKey.PEM);
		of_log(@"Next %@", [socket.peerCertificate next]);
		[socket writeLine:@"GET / HTTP/1.0\r\n"];

		while (!socket.isAtEndOfStream) {
			OFString* l = [socket readLine];
			of_log(@"%@", l);
		}

		[socket close];
	}

	
	connected = true;
	socket.certificateVerificationEnabled = true;
	of_log(@"Verification passed:\n\n");
	@try {
		[socket connectToHost:@"google.com" port:443]; //exception not expected
	}@catch(id e) {
		of_log(@"Not expected exception - %@", e);	
		[e printDebugBacktrace];
		connected = false;
	}
	if (connected) {
		of_log(@"Key: %@", socket.peerCertificate.publicKey);
		of_log(@"DER: %@", socket.peerCertificate.publicKey.DER);
		of_log(@"PEM: \n%@", socket.peerCertificate.publicKey.PEM);
		of_log(@"Next %@", [socket.peerCertificate next]);

		[socket writeLine:@"GET / HTTP/1.0\r\n"];

		while (!socket.isAtEndOfStream) {
			OFString* l = [socket readLine];
			of_log(@"%@", l);
		}
		
		[socket close];
	}

	connected = true;
	socket.certificateVerificationEnabled = false;
	of_log(@"Internal verification passed:\n\n");
	@try {
		[socket connectToHost:@"google.com" port:443]; //exception not expected
	}@catch(id e) {
		of_log(@"Not expected exception - %@", e);	
		[e printDebugBacktrace];
		connected = false;
	}
	if (connected) {
		of_log(@"Key: %@", socket.peerCertificate.publicKey);
		of_log(@"DER: %@", socket.peerCertificate.publicKey.DER);
		of_log(@"PEM: \n%@", socket.peerCertificate.publicKey.PEM);
		of_log(@"Next %@", [socket.peerCertificate next]);

		[socket writeLine:@"GET / HTTP/1.0\r\n"];

		while (!socket.isAtEndOfStream) {
			OFString* l = [socket readLine];
			of_log(@"%@", l);
		}
		
		[socket close];
	}

	of_log(@"SSL less connection:\n\n");
	OFTCPSocket* sk = [OFTCPSocket socket];

	of_log(@"Not SSL test");
	[sk connectToHost:@"google.com" port:443];
	[sk writeLine:@"GET / HTTP/1.0\r\n"];

		while (!sk.isAtEndOfStream) {
			OFString* l = [sk readLine];
			of_log(@"%@", l);
		}
	[sk close];

	of_log(@"Start TLS with connected socket:\n\n");

	[sk connectToHost:@"google.com" port:443];

	MBEDSSLSocket* sks = [[[MBEDSSLSocket alloc] initWithSocket:sk] autorelease];

	[sk close]; //Closing original socket to check socket duplication

	sks.certificateAuthorityFile = @"./GIAG2.crt";

	[sks startTLSWithExpectedHost:@"google.com"];

	[sks writeLine:@"GET / HTTP/1.0\r\n"];

	while (!sks.isAtEndOfStream) {
		OFString* l = [sks readLine];
		of_log(@"%@", l);
	}
	[sks close];

	
	of_log(@"Async connect:\n\n");
	
	MBEDSSLSocket* con = [MBEDSSLSocket socket];
	con.certificateAuthorityFile = @"./GIAG2.crt";
	con.sslVersion = OBJMBED_SSLVERSION_TLSv1;

	__block bool async_end = false;

	[con asyncConnectToHost:@"google.com" port:443 block:^(OFTCPSocket *socket, OFException *_Nullable exception){

		if (exception != nil) {
			of_log(@"Async connect exception: %@", exception);
			//[exception printDebugBacktrace];
			return;
		}
		of_log(@"Async connection");

		MBEDSSLSocket* sock = (MBEDSSLSocket*)socket;
		
		[sock writeLine:@"GET / HTTP/1.0\r\n"];

		while (!sock.isAtEndOfStream) {
			OFString* l = [sock readLine];
			of_log(@"%@", l);
		}
		[sock close];

		async_end = true;
		of_log(@"End async");

	}];

	[OFTimer scheduledTimerWithTimeInterval:0.5 repeats:true block:^(OFTimer *timer){
		of_log(@"check");
		if (async_end)
			[OFApplication terminate];

		return;
	}];
}

@end