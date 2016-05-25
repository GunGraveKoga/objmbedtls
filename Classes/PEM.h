#import <ObjFW/OFObject.h>
#import "macros.h"

@class OFString;
@class OFArray;
@class OFDataArray;

OBJMBEDTLS_EXPORT OFString *const kPEMString_X509_CRT_Old;
OBJMBEDTLS_EXPORT OFString *const kPEMString_X509_CRT;
OBJMBEDTLS_EXPORT OFString *const kPEMString_X509_CRT_Pair;
OBJMBEDTLS_EXPORT OFString *const kPEMString_X509_CRT_Trusted;
OBJMBEDTLS_EXPORT OFString *const kPEMString_X509_CSR_Old;
OBJMBEDTLS_EXPORT OFString *const kPEMString_X509_CSR;
OBJMBEDTLS_EXPORT OFString *const kPEMString_X509_CRL;
OBJMBEDTLS_EXPORT OFString *const kPEMString_EVP_PrivateKey;
OBJMBEDTLS_EXPORT OFString *const kPEMString_PublicKey;
OBJMBEDTLS_EXPORT OFString *const kPEMString_RSA;
OBJMBEDTLS_EXPORT OFString *const kPEMString_RSA_Public;
OBJMBEDTLS_EXPORT OFString *const kPEMString_DSA;
OBJMBEDTLS_EXPORT OFString *const kPEMString_DSA_Public;
OBJMBEDTLS_EXPORT OFString *const kPEMString_PKCS7;
OBJMBEDTLS_EXPORT OFString *const kPEMString_PKCS7_Signed;
OBJMBEDTLS_EXPORT OFString *const kPEMString_PKCS8;
OBJMBEDTLS_EXPORT OFString *const kPEMString_PKCS8INF;
OBJMBEDTLS_EXPORT OFString *const kPEMString_DH_Params;
OBJMBEDTLS_EXPORT OFString *const kPEMString_SSL_Session;
OBJMBEDTLS_EXPORT OFString *const kPEMString_DSA_Params;
OBJMBEDTLS_EXPORT OFString *const kPEMString_ECDSA_Public;
OBJMBEDTLS_EXPORT OFString *const kPEMString_EC_Parameters;
OBJMBEDTLS_EXPORT OFString *const kPEMString_EC_Privatekey;
OBJMBEDTLS_EXPORT OFString *const kPEMString_Parameters;
OBJMBEDTLS_EXPORT OFString *const kPEMString_CMS;

OFArray* PEMtoDER(OFString *pem, OFString *header, OFString *footer, _Nullable OFString *password);

bool isPEM(OFDataArray* buffer);

bool hasHeader(OFDataArray* buffer, OFString* header);
bool hasFooter(OFDataArray* buffer, OFString* footer);

OFString* DERtoPEM(OFDataArray *der, OFString* header, OFString* footer, size_t line_length);