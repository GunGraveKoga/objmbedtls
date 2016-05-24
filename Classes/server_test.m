#import <ObjFW/ObjFW.h>
#import "MBEDSSLSocket.h"
#import "MBEDCRL.h"
#import "MBEDX509Certificate.h"
#import "MBEDPKey.h"
#import "MBEDSSL.h"
#import "SSLAcceptFailedException.h"

#import <WinBacktrace.h>

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
 	
 	MBEDX509Certificate* CA = [MBEDX509Certificate certificateWithSystemCA];
 	size_t idx = 0;
 	while(true) {
 		MBEDX509Certificate* n = [CA next];

 		if (n == nil)
 			break;
 		@try {
 			of_log(@"%@", n);
 		}@catch(id e){}
 		idx++;
 	}

 	of_log(@"Total %zu certificates", idx+1);

 	MBEDCRL* CRL = [MBEDCRL crlWithSystemCRL];

 	of_log(@"CRL: %@", CRL);

 	idx = 0;

 	while(true) {
 		MBEDCRL* n = [CRL next];

 		if (n == nil)
 			break;
 		@try {
 			of_log(@"%@", n);
 		}@catch(id e){}
 		idx++;
 	}

 	of_log(@"Total CRL`s %zu", idx+1);

 	OFString* crlpem = [CRL PEM];

 	of_log(@"CRL PEM: %@", crlpem);

 	MBEDCRL* crl = [MBEDCRL crlWithPEMString:crlpem];

	MBEDSSLSocket* srv = [MBEDSSLSocket socket];

	OFString* srv_crt = [OFString stringWithUTF8String:(const char *)mbedtls_test_srv_crt length:(size_t)mbedtls_test_srv_crt_len];
	OFString* srv_cas = [OFString stringWithUTF8String:(const char *)mbedtls_test_cas_pem length:(size_t)mbedtls_test_cas_pem_len];
	OFDataArray* srv_key = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];

	[srv_key addItems:mbedtls_test_srv_key count:mbedtls_test_srv_key_len];

	srv.CA = [MBEDX509Certificate certificateWithPEMString:srv_cas];
	srv.PK = [MBEDPKey keyWithPEM:[OFString stringWithUTF8String:[srv_key items] length:([srv_key count] * [srv_key itemSize])] password:nil isPublic:false];
	srv.ownCertificate = [MBEDX509Certificate certificateWithPEMString:srv_crt];
	srv.sslVersion = OBJMBED_SSLVERSION_TLSv1;
	srv.requestClientCertificatesEnabled = true;
	
	[srv bindToHost:@"0.0.0.0" port:9999];
	[srv listen];

	[srv asyncAcceptWithBlock:^bool(OFTCPSocket *socket, OFTCPSocket *acceptedSocket, OFException *_Nullable exception){
		if (exception) {
			if ([exception isKindOfClass:[OFAcceptFailedException class]] || [exception isKindOfClass:[SSLAcceptFailedException class]])
				of_log(@"%@ %@ %d", exception, ((OFAcceptFailedException*)exception).socket, [((OFAcceptFailedException*)exception).socket fileDescriptorForReading]);
			else
				of_log(@"%@", exception);
			return true;
		}

		of_log(@"Connection accepted %@ %d", acceptedSocket, [acceptedSocket fileDescriptorForReading]);

		MBEDSSLSocket* sclient = (MBEDSSLSocket *)acceptedSocket;

		of_log(@"Client certificate:\n\n%@", sclient.peerCertificate);

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