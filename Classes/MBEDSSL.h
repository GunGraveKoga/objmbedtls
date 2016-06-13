#import <ObjFW/OFObject.h>
#import <ObjFW/OFTLSSocket.h>

#import "macros.h"

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

@class OFString;
@class MBEDSSLConfig;
@class MBEDSSLSocket;




@interface MBEDSSL: OFObject
{
    mbedtls_ssl_context _ssl;
    bool _configured;
    OFString* _cipherSuite;
}

@property(assign, readonly)mbedtls_ssl_context* context;
@property(copy, readonly)OFString* cipherSuite;

+ (instancetype)ssl;
+ (instancetype)sslWithConfig:(MBEDSSLConfig *)config;

- (instancetype)initWithConfig:(MBEDSSLConfig *)config;


- (void)setBinaryIO:(MBEDSSLSocket *)socket;
- (void)setHostName:(OFString *)host;
- (void)handshake;
- (uint32_t)peerCertificateVerified;
- (const mbedtls_x509_crt *)peerCertificate;
- (void)writeBuffer:(const void*)buffer length:(size_t)length;
- (ssize_t)readIntoBuffer:(void*)buffer length:(size_t)length;
- (void)notifyPeerToClose;
- (void)resetSession;
- (size_t)bytesAvailable;
- (void)sendWarning:(unsigned char)message;
- (void)sendFatal:(unsigned char)message;
- (void)sendMessage:(unsigned char)message level:(unsigned char)level;

@end
