#import <ObjFW/ObjFW.h>
#import "SSLWriteFailedException.h"

#include <mbedtls/error.h>

@implementation SSLWriteFailedException

- (OFString *)description
{
	if (_errNo != 0) {
		char buffer[4096] = {0};

		mbedtls_strerror( _errNo, buffer, sizeof(buffer) );

		return [OFString stringWithFormat:
		    @"Failed to read or write %zu bytes from / to an object of "
		    @"type %@: %s",
		    _requestedLength, [_object class], (const char*)buffer];
	}
	else
		return [OFString stringWithFormat:
		    @"Failed to read or write %zu bytes from / to an object of "
		    @"type %@!",
		    _requestedLength, [_object class]];
}

@end