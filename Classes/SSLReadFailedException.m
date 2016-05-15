#import <ObjFW/ObjFW.h>
#import "SSLReadFailedException.h"

#include <mbedtls/error.h>


@implementation SSLReadFailedException

- (OFString *)description
{
	if (_errNo != 0) {
		char buffer[4096] = {0};

		mbedtls_strerror( _errNo, buffer, sizeof(buffer) );

		return [OFString stringWithFormat:
		    @"Failed to read %zu bytes from an object of type %@: %@",
		    _requestedLength, [_object class], (const char*)buffer];
	}
	else
		return [OFString stringWithFormat:
		    @"Failed to read %zu bytes from an object of type %@!",
		    _requestedLength, [_object class]];
}

@end