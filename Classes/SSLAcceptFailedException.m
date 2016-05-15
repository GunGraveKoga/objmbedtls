#import <ObjFW/ObjFW.h>
#import "SSLAcceptFailedException.h"

#include <mbedtls/error.h>

@implementation SSLAcceptFailedException

- (OFString *)description
{
	char buffer[4096] = {0};

	mbedtls_strerror( _errNo, buffer, sizeof(buffer) );

	return [OFString stringWithFormat:@"Failed to accept connection in socket of class %@: %s", [_socket class], (const char *)buffer];
}

@end