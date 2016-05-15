#import <ObjFW/ObjFW.h>
#import "SSLConnectionFailedException.h"

#include <mbedtls/error.h>

@implementation SSLConnectionFailedException

- (OFString *)description
{
	if (_errNo != 0) {

		char buffer[4096] = {0};

		mbedtls_strerror( _errNo, buffer, sizeof(buffer) );

		return [OFString stringWithFormat:
		    @"A connection to %@ on port %" @PRIu16 @" could not be "
		    @"established in socket of type %@: %s",
		    _host, _port, [_socket class], (const char*)buffer];
	}
	else
		return [OFString stringWithFormat:
		    @"A connection to %@ on port %" @PRIu16 @" could not be "
		    @"established in socket of type %@!",
		    _host, _port, [_socket class]];
}

@end