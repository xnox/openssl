/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/opensslconf.h>
#include "crypto/rand_pool.h"
#include "prov/seeding.h"

#ifdef OPENSSL_RAND_SEED_JITTER
#include <jitterentropy.h>

static size_t get_jitter_random_value(unsigned char *buf, size_t len);

/*
 * Acquire entropy from jitterentropy library
 *
 * Returns the total entropy count, if it exceeds the requested
 * entropy count. Otherwise, returns an entropy count of 0.
 */
size_t ossl_prov_acquire_entropy_from_jitter(RAND_POOL *pool)
{
    size_t bytes_needed;
    unsigned char *buffer;

    bytes_needed = ossl_rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
    if (bytes_needed > 0) {
        buffer = ossl_rand_pool_add_begin(pool, bytes_needed);

        if (buffer != NULL) {
            if (get_jitter_random_value(buffer, bytes_needed) == bytes_needed) {
                ossl_rand_pool_add_end(pool, bytes_needed, 8 * bytes_needed);
            } else {
                ossl_rand_pool_add_end(pool, 0, 0);
            }
        }
    }

    return ossl_rand_pool_entropy_available(pool);
}

/* Obtain random bytes from the jitter library */
static size_t get_jitter_random_value(unsigned char *buf, size_t len)
{
    struct rand_data *jitter_ec = NULL;
    ssize_t result = 0;

    jitter_ec = jent_entropy_collector_alloc(0, JENT_FORCE_FIPS);
    if (jitter_ec == NULL) {
        return 0;
    }

    // Use the _safe API variant with built-in retries, until failure
    result = jent_read_entropy_safe(&jitter_ec, (char *) buf, len);

    // Success
    if (result == len) {
        jent_entropy_collector_free(jitter_ec);
        return len;
    }

    // On failure jitter_ec may have been freed already prior to
    // v3.5.0 see bffd1569483ccbea23b29e6d63dc74b9235b002e
    if (jitter_ec && jent_version() >= 3050000) {
        jent_entropy_collector_free(jitter_ec);
    }

    // Catastrophic failure, maybe should abort here
    return 0;
}

#else
NON_EMPTY_TRANSLATION_UNIT
#endif
