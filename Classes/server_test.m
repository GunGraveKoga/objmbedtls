#import <ObjFW/ObjFW.h>
#import "MBEDSSLSocket.h"
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
	//OFTCPSocket* srv = [OFTCPSocket socket];
	MBEDSSLSocket* srv = [MBEDSSLSocket socket];

	OFDataArray* srv_crt = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];
	OFDataArray* srv_cas = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];
	OFDataArray* srv_key = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];

	[srv_crt addItems:mbedtls_test_srv_crt count:mbedtls_test_srv_crt_len];
	[srv_cas addItems: mbedtls_test_cas_pem count:mbedtls_test_cas_pem_len];
	[srv_key addItems:mbedtls_test_srv_key count:mbedtls_test_srv_key_len];

	srv.CA = [MBEDX509Certificate certificatesWithData:srv_cas];
	srv.PK = [MBEDPKey keyWithPEM:[OFString stringWithUTF8String:[srv_key items] length:([srv_key count] * [srv_key itemSize])] password:nil isPublic:false];
	srv.ownCertificate = [MBEDX509Certificate certificatesWithData:srv_crt];
	srv.sslVersion = OBJMBED_SSLVERSION_TLSv1;

	[srv bindToHost:@"0.0.0.0" port:9999];
	[srv listen];

	[srv asyncAcceptWithBlock:^bool(OFTCPSocket *socket, OFTCPSocket *acceptedSocket, OFException *_Nullable exception){
		if (exception) {
			of_log(@"%@", exception);
			return true;
		}

		of_log(@"Connection accepted %@ %d", acceptedSocket, [acceptedSocket fileDescriptorForReading]);

		MBEDSSLSocket* sclient = (MBEDSSLSocket *)acceptedSocket;//[[[MBEDSSLSocket alloc] initWithAcceptedSocket:acceptedSocket] autorelease];

		//sclient.CA = [MBEDX509Certificate certificatesWithData:srv_cas];
		//sclient.PK = [MBEDPKey keyWithPEM:[OFString stringWithUTF8String:[srv_key items] length:([srv_key count] * [srv_key itemSize])] password:nil isPublic:false];
		//sclient.ownCertificate = [MBEDX509Certificate certificatesWithData:srv_crt];
		//sclient.sslVersion = OBJMBED_SSLVERSION_TLSv1;
		//[sclient startTLSWithExpectedHost:nil];

		[sclient asyncReadLineWithBlock:^bool(OFStream *stream, OFString *_Nullable line, OFException *_Nullable exception){
			if (exception) {
				of_log(@"%@", exception);
				return false;
			}

			

			if (line) {
				of_log(@"Client sent data %@", stream);
				of_log(@"%@", line);

				if ([line length] == 0) {
					MBEDSSLSocket* sock = (MBEDSSLSocket *)stream;
					[sock writeFormat:@"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<h2>mbed TLS Test Server</h2>\r\n<p>Successful connection using: %@</p>\r\n", sock.SSL.cipherSuite];
					return false;
				}
			}
			
			return true;
		}];

		return true;

	}];
}

@end