#ifndef MBEDTLS_THREADING_ALT_H
#define MBEDTLS_THREADING_ALT_H

#import <ObjFW/threading.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    of_mutex_t mutex;
    bool is_valid;
} mbedtls_threading_mutex_t;

void objfw_mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex_);
void objfw_mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex_);
int objfw_mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex_);
int objfw_mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex_);

#ifdef __cplusplus
}
#endif

#endif /*BEDTLS_THREADING_ALT_H*/