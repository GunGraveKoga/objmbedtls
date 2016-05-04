#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_THREADING_C)
#import <ObjFW/ObjFW.h>

#include "mbedtls/threading_alt.h"
#define MBEDTLS_ERR_THREADING_FEATURE_UNAVAILABLE         -0x001A  /**< The selected feature is not available. */
#define MBEDTLS_ERR_THREADING_BAD_INPUT_DATA              -0x001C  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_THREADING_MUTEX_ERROR                 -0x001E  /**< Locking / unlocking / free failed with error code. */



void objfw_mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex_) {
	@try {
		mutex_->mutex = [OFMutex new];
	}@catch(OFException* e) {
		mutex_->is_valid = false;
		mutex_->mutex = nil;
	}
	mutex_->is_valid = true;
	return;

}

void objfw_mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex_) {
	mutex_->is_valid = false;
	[mutex_->mutex release];
	mutex_->mutex = nil;
	return;
}

int objfw_mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex_) {
	if (mutex_->is_valid) {
		if (mutex_->mutex != nil) {
			@try {
				[mutex_->mutex lock];
			}@catch(OFException* e) {
				return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
			}

			return(0);
		}
	}
	return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );
}

int objfw_mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex_) {
	if (mutex_->is_valid) {
		if (mutex_->mutex != nil) {
			@try {
				[mutex_->mutex unlock];
			}@catch(OFException* e) {
				return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
			}

			return(0);
		}
	}
	return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );
}

#endif