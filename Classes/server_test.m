#import <ObjFW/ObjFW.h>
#import "MBEDSSLSocket.h"
#import "MBEDCRL.h"
#import "MBEDX509Certificate.h"
#import "MBEDPKey.h"
#import "MBEDSSL.h"
#import "SSLAcceptFailedException.h"
#import "PEM.h"

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
 		MBEDX509Certificate* n = (MBEDX509Certificate*)[CA next];

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
 		MBEDCRL* n = (MBEDCRL*)[CRL next];

 		if (n == nil)
 			break;
 		@try {
 			of_log(@"%@", n);
 		}@catch(id e){}
 		idx++;
 	}

 	of_log(@"Total CRL`s %zu", idx+1);

 	OFArray* DERs = PEMtoDER([OFString stringWithUTF8String:(const char *)mbedtls_test_srv_crt length:(size_t)mbedtls_test_srv_crt_len], @"-----BEGIN CERTIFICATE-----", @"-----END CERTIFICATE-----", nil);

 	MBEDX509Certificate* dercert = [MBEDX509Certificate certificateWithDER:DERs[0]];

 	of_log(@"%@", dercert);
 	OFString* pem1 = [OFString stringWithUTF8String:(const char *)mbedtls_test_srv_crt length:(size_t)mbedtls_test_srv_crt_len];
 	OFString* pem2 = DERtoPEM([dercert DER], @"-----BEGIN CERTIFICATE-----", @"-----END CERTIFICATE-----", 0);
 	of_log(@"%@", pem1);
 	of_log(@"%@", pem2);

 	of_log(@"%@", [pem1 isEqual:pem2] ? @"Yes" : @"No");

 	dercert = [MBEDX509Certificate certificateWithPEM:pem2];

 	of_log(@"%@", dercert);

 	OFArray* PDERs = PEMtoDER([OFString stringWithUTF8String:(const char *)mbedtls_test_ca_key length:mbedtls_test_ca_key_len], @"-----BEGIN RSA PRIVATE KEY-----", @"-----END RSA PRIVATE KEY-----", @"PolarSSLTest");

 	MBEDPKey* CAKey = [MBEDPKey keyWithDER:PDERs[0] password:@"PolarSSLTest" isPublic:false];

 	of_log(@"%@", CAKey);

 	OFString* crlpem = [CRL PEM];

 	of_log(@"CRL PEM: %@", crlpem);

 	MBEDCRL* crl = [MBEDCRL crlWithPEM:crlpem];

 	of_log(@"%@", crl);

 	OFString* b64 = @"MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUx\nGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkds\nb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNV\nBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYD\nVQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDa\nDuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavpxy0Sy6sc\nTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlb\nKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNP\nc1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrX\ngzT/LCrBbBlDSgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\nHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUF\nAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOzyj1hTdNGCbM+w6Dj\nY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyG\nj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhH\nhm4qxFYxldBniYUr+WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveC\nX4XSQRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==";

 	b64 = [b64 stringByReplacingOccurrencesOfString:@"\n" withString:@""];

 	//OFDataArray* d64 = [OFDataArray dataArrayWithBase64EncodedString:b64];

 	MBEDX509Certificate* crtb64 = nil;

 	@try {
 		crtb64 = [MBEDX509Certificate certificateWithPEM:[OFString stringWithFormat:@"-----BEGIN MY CERTIFICATE-----\n%@\n-----END MY CERTIFICATE-----", b64]];

 	}@catch(id e) {
 		of_log(@"%@", e);
 	}

 	of_log(@"From BASE64 DATA\n%@", crtb64);

	of_log(@"%@", b64);

 	//MBEDX509Certificate* cert = [MBEDX509Certificate certificateWithFile:@"./test.pem"];
 	//of_log(@"%@", cert);
 	OFString* certpem = [OFString stringWithContentsOfFile:@"./certificate.pem"];
 	OFDataArray* dt = [OFDataArray dataArrayWithContentsOfFile:@"./certificate.pem"];

 	MBEDX509Certificate* cert = [MBEDX509Certificate certificateWithPEM:[OFString stringWithUTF8String:(const char *)[dt items] length:[dt count]]];
 	of_log(@"Data %@", cert);
 	cert = [MBEDX509Certificate certificateWithPEM:certpem];
 	of_log(@"String %@", cert);
 	cert = [MBEDX509Certificate certificateWithFile:@"./test.pem"];
 	of_log(@"File %@", cert);


 	crl = [MBEDCRL crlWithFile:@"./crl.pem"];
 	of_log(@"File %@", crl);
 	crlpem = [OFString stringWithContentsOfFile:@"./crl.pem"];
 	crl = [MBEDCRL crlWithPEM:crlpem];
 	of_log(@"String %@", crl);
 	dt = [OFDataArray dataArrayWithContentsOfFile:@"./crl.pem"];
 	crl = [MBEDCRL crlWithPEM:[OFString stringWithUTF8String:(const char *)[dt items] length:[dt count]]];
 	of_log(@"Data %@", crl);

 	MBEDPKey* key = [MBEDPKey keyWithPEM:[OFString stringWithUTF8String:(const char *)mbedtls_test_ca_key length:mbedtls_test_ca_key_len] password:@"PolarSSLTest" isPublic:false];

 	of_log(@"Key from PEM %@", key);

 	OFDataArray* keyder = key.DER;

 	[keyder writeToFile:@"exmpl.der"];

 	OFString* testhash = @"HiHi";

 	OFDataArray* sign = [key makeSignatureForHash:[[testhash SHA256Hash] UTF8String] hashType:MBEDTLS_MD_SHA256];

 	of_log(@"Sign: %@", sign);

 	[sign writeToFile:@"test.sig"];

 	if ([key verifySignature:sign ofHash:[[testhash SHA256Hash] UTF8String] hashType:MBEDTLS_MD_SHA256])
 		of_log(@"Valid!");

 	MBEDPKey* pub = [key publicKey];

 	of_log(@"Pub: %@", pub);

 	if ([MBEDPKey publicKey:pub matchesPrivateKey:key])
 		of_log(@"Pub matches prv");

	MBEDSSLSocket* srv = [MBEDSSLSocket socket];

	OFString* srv_crt = [OFString stringWithUTF8String:(const char *)mbedtls_test_srv_crt length:(size_t)mbedtls_test_srv_crt_len];
	OFString* srv_cas = [OFString stringWithUTF8String:(const char *)mbedtls_test_cas_pem length:(size_t)mbedtls_test_cas_pem_len];
	OFDataArray* srv_key = [OFDataArray dataArrayWithItemSize:sizeof(unsigned char)];

	[srv_key addItems:mbedtls_test_srv_key count:mbedtls_test_srv_key_len];

	srv.CA = [MBEDX509Certificate certificateWithPEM:srv_cas];
	srv.PK = [MBEDPKey keyWithPEM:[OFString stringWithUTF8String:[srv_key items] length:([srv_key count] * [srv_key itemSize])] password:nil isPublic:false];
	srv.ownCertificate = [MBEDX509Certificate certificateWithPEM:srv_crt];
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