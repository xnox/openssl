/*
 * Copyright 2011-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "prov/seeding.h"
#include <jitterentropy.h>
#define JITTER_MAX_NUM_TRIES 3

/* Obtain random bytes from the jitter library */
size_t get_jitter_random_value(unsigned char *buf, size_t len)
{
    struct rand_data *jitter_ec = NULL;
    ssize_t result = 0;
    size_t num_tries;

    jitter_ec = jent_entropy_collector_alloc(0, JENT_FORCE_FIPS);
    if (jitter_ec == NULL) {
        return 0;
    }

    for (num_tries = 0; num_tries < JITTER_MAX_NUM_TRIES; num_tries++) {
      // Do not use _safe API variant with built-in retries, until
      // failure because it reseeds the entropy source which is not
      // certifyable
      result = jent_read_entropy(jitter_ec, (char *) buf, len);

      // Success
      if (result == len) {
          jent_entropy_collector_free(jitter_ec);
          return len;
      }
    }

    jent_entropy_collector_free(jitter_ec);

    // Catastrophic failure, maybe should abort here
    return 0;
}
