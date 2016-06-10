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
	if( mutex_ == NULL )
        return;

    mutex_->is_valid = of_mutex_new(&(mutex_->mutex));

}

void objfw_mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex_) {
	if( mutex_ == NULL )
        return;

    (void)of_mutex_free(&(mutex_->mutex));
}

int objfw_mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex_) {
	if( mutex_ == NULL || ! mutex_->is_valid )
        return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );

    if (!of_mutex_lock(&(mutex_->mutex)))
    	return MBEDTLS_ERR_THREADING_MUTEX_ERROR;

    return 0;
}

int objfw_mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex_) {
	if( mutex_ == NULL || ! mutex_->is_valid )
        return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );

    if (!of_mutex_unlock(&(mutex_->mutex)))
    	return MBEDTLS_ERR_THREADING_MUTEX_ERROR;

    return 0;
}

#endif