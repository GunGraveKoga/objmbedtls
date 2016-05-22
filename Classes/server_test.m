#import <ObjFW/ObjFW.h>
#import "MBEDSSLSocket.h"
#import "MBEDCRL.h"
#import "MBEDX509Certificate.h"
#import "MBEDPKey.h"
#import "MBEDSSL.h"
#import "SSLAcceptFailedException.h"

#import <WinBacktrace.h>

typedef enum  {
  None,
  Certificate,
  PKCS7,
  X509CRL
} OutputType;

const char* GetTypeName(OutputType type)
{

  switch (type)
  {

  case Certificate:
    return "CERTIFICATE";

  case PKCS7:
    return "PKCS7";

  case X509CRL:
    return "X509 CRL";

  case None:
    return NULL;

  default:
    break;

  }

  return NULL;
}


bool IsPKCS7(DWORD encodeType)

{
  return ((encodeType & PKCS_7_ASN_ENCODING) == PKCS_7_ASN_ENCODING);

}

void DisplayPEM(OutputType outputType, BYTE const* pData, DWORD cbLength)

{
 char const* type = GetTypeName(outputType);

 if ( type == NULL ) return;

	/*OFMutableString* crt = [OFMutableString string];
	OFDataArray* dt = [OFDataArray dataArrayWithItemSize:sizeof(char)];
	[crt appendFormat:@"-----BEGIN %s-----", type];
	
	[crt appendString:[dt stringByBase64Encoding]];
	[crt appendFormat:@"-----END %s-----", type];
	[crt makeImmutable];*/
	static OFMutableString* pem = nil;

	if (!pem)
		pem = [OFMutableString string];

	MBEDX509Certificate* crt = nil;

	OFDataArray* dt = [OFDataArray dataArrayWithItemSize:sizeof(char)];
	[dt addItems:(const void *)pData count:(size_t)cbLength];
	@try {

		crt = [MBEDX509Certificate certificateWithDERData:dt];

		of_log(@"DateS %@", [crt.issued localDateStringWithFormat:@"%Y-%m-%d %H:%M:%S"]);
		@try {
			of_log(@"DateE %@", [crt.expires localDateStringWithFormat:@"%Y-%m-%d %H:%M:%S"]);
		}@catch(id e) {
			of_log(@"%04d %02d %02d", [crt.expires localYear], [crt.expires localDayOfMonth], [crt.expires localMonthOfYear]);
		}
		of_log(@"%@", [OFDate distantFuture]);

		of_log(@"%@", crt);
		of_log(@"%@", [crt PEM]);
	}@catch (OFException* e) {
		of_log(@"%@", e);
		[e printDebugBacktrace];
		crt = nil;
	}

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
	WinBacktrace* plugin = [OFPlugin pluginFromFile:@"WinBacktrace"];

	HCERTSTORE hStore = CertOpenSystemStore(0, "CA");

	for ( PCCERT_CONTEXT pCertCtx = CertEnumCertificatesInStore(hStore, NULL);

       pCertCtx != NULL;

       pCertCtx = CertEnumCertificatesInStore(hStore, pCertCtx) )
 {
	@autoreleasepool {
		OutputType outputType = IsPKCS7(pCertCtx->dwCertEncodingType) ? PKCS7 : Certificate;

   		DisplayPEM(outputType, pCertCtx->pbCertEncoded, pCertCtx->cbCertEncoded);
	}
   
 }


 for ( PCCRL_CONTEXT pCrlCtx = CertEnumCRLsInStore(hStore, NULL);

       pCrlCtx != NULL;
       pCrlCtx = CertEnumCRLsInStore(hStore, pCrlCtx) )

 {
	@autoreleasepool {
		OutputType outputType = IsPKCS7(pCrlCtx->dwCertEncodingType) ? PKCS7 : X509CRL;

   		DisplayPEM(outputType, pCrlCtx->pbCrlEncoded, pCrlCtx->cbCrlEncoded);
	} 	
   

 }

 CertCloseStore(hStore, 0);

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