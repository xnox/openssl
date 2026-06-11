/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/err.h>

/*
 * Demonstration / regression example for CVE-2026-42770.
 *
 * When EVP_PKEY_derive_set_peer() is called with a DHX (X9.42) peer key, the
 * subgroup membership check (Y^q == 1 mod p) is performed using the *peer's*
 * own q value rather than the local key's q, and the domain-parameter match
 * historically never compared q at all.
 *
 * A malicious peer can therefore present an X9.42 key carrying the victim's
 * genuine p and g, but a forged small subgroup order q' = r (a small prime
 * factor of the cofactor (p-1)/q) together with a public value Y of order r.
 * Such a key passes the membership check (Y^r == 1) and, before the fix, also
 * passed the parameter match because q was ignored. The shared secret then
 * takes only r distinct values, leaking priv mod r; repeating over the small
 * prime factors of the cofactor and combining via CRT recovers the victim's
 * private key (Lim-Lee / small-subgroup confinement).
 *
 * The fix makes EVP_PKEY_derive_set_peer() reject a peer whose q does not
 * match the victim key's q.
 *
 * This program uses only public, non-deprecated APIs (EVP_PKEY_fromdata,
 * EVP_PKEY_derive_set_peer, OSSL_PARAM_BLD, BN_hex2bn). It links against the
 * shared libcrypto and therefore exercises the runtime library, e.g.:
 *
 *    LD_LIBRARY_PATH=../.. ./dhx_subgroup_check
 *
 * It exits 0 when the malicious peer is rejected (library is fixed), 1 if the
 * peer is accepted (library is vulnerable), and 2 when the configuration does
 * not allow the X9.42 DHX test keys to be imported at all - in which case the
 * vulnerability is neither demonstrable nor exploitable (see below).
 *
 * The CVE also affects the FIPS modules, so the example can be run under the
 * FIPS provider, e.g.:
 *
 *    ../../util/wrap.pl -fips ./dhx_subgroup_check
 *
 * For that to reach the vulnerable code path the victim key must be
 * FIPS-approved, so the parameters below use FIPS-compliant sizes: p is
 * exactly 2048 bits and q is exactly 256 bits. They were generated so that
 * p - 1 = q * cofactor with the cofactor divisible by the small prime r = 11.
 * G generates the legitimate order-q subgroup; the rogue public value has
 * order r and is therefore NOT in that subgroup.
 */

static const char *dhx_p_hex =
    "a032f8120e4ff8f1f4424e294c83dd666db028af52e43fff4207b55ffcf11874"
    "a92f74255c0de4d00782be6c1b0ce7d1bcdac61256c4ce6c6f6783f28844e11a"
    "d5b57656cd1bce116967a751c78bb87af2a3add1749623d2ec879179b5057ed3"
    "0c04173a48d44865225c541cc16ad7df2af54a44e0c9e4e7ad85aa67727fe93f"
    "10031b93bf5a72935ba764f613d95ce3997c0cd7bbbe9bb4deebef3cadd8adef"
    "404112252c43ed1a59d4c53b595e6cb5b148b5e190bb1ffedfe43a13e932750f"
    "54ec60428ee3e26db2c8a64f0cb3ce685461c4faceaba40d5f8e0860266aaf28"
    "c31fd42224cf30082a486eb78efcb19abe8e25d5cf38cd7f54786d735e7eb6e5";
static const char *dhx_q_hex =
    "a4d4672cf3497e5dabb2214f6c7687124eb9c1987dfef34aacb9db5b65944d8d";
static const char *dhx_g_hex =
    "10069c5e03b39ed2d9bbb53818e304afd39f0d5e12e2cf11f6607fafaf663272"
    "aea81f6e50ecca6baec7ef74711f73f1da010ea98f93ea358bdefb787ae86de1"
    "92598f3cca64de3e693096ea2c12cb837d6910cb1003be6be4be3667725eff7d"
    "19b23591486551751cab636f47d77ab23b42c504ac5ca622dab9b9309f942372"
    "7c939d99b5c26e583884a9a8e5ca1791b750e088edab7aa347450e8cdd1127bd"
    "f8d4bc80cbaa25e73dc0ff2301852a4b7eb761f3bb8a4d6a6539810ca75fb5bf"
    "098e3abca0355e2e33a62905b5e4ee3f023fcac09bbb33557abf8edeb6a2c480"
    "697d28dd211a0c283f4c53846a3f793fedf9e80af357b31b24b12c6978d1b6e0";
static const char *dhx_priv_hex =
    "212df1b8ecbb6f762f30a5efcc6a2e25ac5daf87a1fe10068b9eedd4d8769927";
static const char *dhx_pub_hex =
    "79edde96ee024998571d526cb95ec7e8f702cf8fbb0afb76358752c411bf92da"
    "8fdabe5c0f0b157395809f5c8741c3be36a5d9666144c369dc0a5cdfe2ea3843"
    "0083e5c5a65163b35299295441980b020a724125efe17e09cc8c70b5a2b36318"
    "77e6b439d2a421abdb7c1adae51716ce62bb5ae8eb13876dc4605a46547554b6"
    "6621c8d4f5909ae91a8fae2fac9c3f7b65c3a0bc581f5518eb7b59b36e4e51dd"
    "40b2f7da8788c6ea31bc2dcaf8dc0bf79a31130c7027832c5fd5f3395b5019b1"
    "77d736739da396e0dcf96da759a6cfbef95c0eb7d8409ab731cea15b719b18c7"
    "858a7830c931fc9f186a46a98cbe92021d30e4b3f672bfaf631a5defbb2215d5";
/* Forged subgroup order q' = r = 11 */
static const char *dhx_rogue_q_hex = "0b";
/* Malicious peer public value of order r */
static const char *dhx_rogue_pub_hex =
    "97747445488e6756ec5102328e603be1708233ba92f7edd226246f34df7e94db"
    "1d2fa4c8bd09d2e20b43db2c7f71703ad732f530e1d6e07ab0f0ae598d8d2c86"
    "41b11c3c25116c796677e6d855ce067556a10ff48d0262cffc494efa5692bcc0"
    "51cb271ff4db1f08b85960188752f4d9db71a4428ca6d287a8ec6cf6bef4f8fc"
    "d6a7bd80585067ae080ded21c07f8ef432c18ff135d0f00ced592ffbd9bdc833"
    "cce3bb7cc04ec47401fbc84c734d209077bbdf8dc9255ab3976dde87edb954a2"
    "b657e991d90766c5a7ce4fd031b6903afb3425fbc632465a3773fda9ad19d859"
    "5013eafc4f50fd68e440247b24bae434b1f9c874422510d0bcbfdaddc4578939";

/*
 * Build a DHX EVP_PKEY from raw domain parameters and key values using only
 * the public fromdata interface. If priv_hex is NULL only a public key is
 * imported. Returns NULL on failure.
 */
static EVP_PKEY *make_dhx_key(const char *p_hex, const char *q_hex,
                              const char *g_hex, const char *priv_hex,
                              const char *pub_hex)
{
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL;
    int selection = EVP_PKEY_PUBLIC_KEY;

    if (BN_hex2bn(&p, p_hex) == 0
            || BN_hex2bn(&q, q_hex) == 0
            || BN_hex2bn(&g, g_hex) == 0
            || BN_hex2bn(&pub, pub_hex) == 0)
        goto err;
    if (priv_hex != NULL) {
        if (BN_hex2bn(&priv, priv_hex) == 0)
            goto err;
        selection = EVP_PKEY_KEYPAIR;
    }

    if ((bld = OSSL_PARAM_BLD_new()) == NULL
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p)
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q)
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, pub))
        goto err;
    if (priv != NULL
            && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv))
        goto err;
    if ((params = OSSL_PARAM_BLD_to_param(bld)) == NULL)
        goto err;

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL)) == NULL
            || EVP_PKEY_fromdata_init(ctx) <= 0
            || EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

 err:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(priv);
    BN_free(pub);
    return pkey;
}

/*
 * Initialise a derive operation for |local| and run set_peer(|peer|).
 *
 * Returns the EVP_PKEY_derive_set_peer() result (> 0 accepted, <= 0 rejected).
 * If the operation could not even be initialised - which under the FIPS
 * provider happens when the local key is not FIPS-approved, before any peer
 * processing - *init_failed is set to 1 and the return value is meaningless.
 */
static int try_set_peer(EVP_PKEY *local, EVP_PKEY *peer, int *init_failed)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, local, NULL);
    int ret = 0;

    *init_failed = 1;
    if (ctx != NULL && EVP_PKEY_derive_init(ctx) > 0) {
        *init_failed = 0;
        ret = EVP_PKEY_derive_set_peer(ctx, peer);
    }
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int main(void)
{
    int exitcode = 1;
    EVP_PKEY *local = NULL, *good_peer = NULL, *rogue_peer = NULL;
    int good_ret, rogue_ret, init_failed;

    printf("OpenSSL runtime: %s\n", OpenSSL_version(OPENSSL_VERSION));
    fflush(stdout);

    /* Victim's private key with the genuine domain parameters (p, q, g). */
    local = make_dhx_key(dhx_p_hex, dhx_q_hex, dhx_g_hex, dhx_priv_hex,
                         dhx_pub_hex);
    /* A legitimate peer sharing the exact same domain parameters. */
    good_peer = make_dhx_key(dhx_p_hex, dhx_q_hex, dhx_g_hex, NULL,
                             dhx_pub_hex);
    /* Malicious peer: same p and g, but forged q' = r and Y of order r. */
    rogue_peer = make_dhx_key(dhx_p_hex, dhx_rogue_q_hex, dhx_g_hex, NULL,
                              dhx_rogue_pub_hex);

    if (local == NULL || good_peer == NULL || rogue_peer == NULL) {
        /*
         * The attack requires an X9.42 (FIPS 186-4) DHX key with explicit,
         * non-safe-prime FFC domain parameters. Some configurations refuse to
         * import such keys - in particular a FIPS module built with
         * no-fips186-4-ffc only accepts named safe-prime groups (see
         * ossl_dh_is_named_safe_prime_group() in crypto/dh/dh_backend.c).
         * In that case the precondition for CVE-2026-42770 cannot even be
         * established, so the issue is not demonstrable (and not exploitable)
         * here. Report this as "not applicable" rather than pass/fail.
         */
        fprintf(stderr, "Could not import the X9.42 DHX test keys.\n"
                "This build/provider does not allow non-safe-prime FFC "
                "(X9.42 / FIPS 186-4) DH parameters\n(e.g. a FIPS module built "
                "with no-fips186-4-ffc). The CVE-2026-42770 precondition "
                "cannot be\nestablished in this configuration, so the issue is "
                "not demonstrable here.\n");
        ERR_print_errors_fp(stderr);
        exitcode = 2;
        goto end;
    }

    /* Control: a legitimate same-parameter peer must be accepted. */
    good_ret = try_set_peer(local, good_peer, &init_failed);
    if (init_failed) {
        fprintf(stderr, "EVP_PKEY_derive_init() failed for the local key: it "
                "was rejected before any peer processing.\nUnder the FIPS "
                "provider this happens when the key is not FIPS-approved "
                "(e.g. p < 2048 bits); it is unrelated to CVE-2026-42770.\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    printf("legitimate peer (q == victim q): set_peer returned %d -> %s\n",
           good_ret, good_ret > 0 ? "accepted" : "REJECTED");
    if (good_ret <= 0) {
        fprintf(stderr, "Unexpected: legitimate peer was rejected\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /* The malicious peer must be rejected by a fixed library. */
    rogue_ret = try_set_peer(local, rogue_peer, &init_failed);
    if (init_failed) {
        fprintf(stderr, "EVP_PKEY_derive_init() failed for the local key\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    printf("malicious  peer (q' = 11)      : set_peer returned %d -> %s\n",
           rogue_ret, rogue_ret > 0 ? "ACCEPTED" : "rejected");

    if (rogue_ret > 0) {
        printf("\nVULNERABLE: EVP_PKEY_derive_set_peer() accepted a DHX peer "
               "with a forged subgroup order q (CVE-2026-42770).\n");
        exitcode = 1;
    } else {
        /* Clear the expected error queue entry from the rejection. */
        ERR_clear_error();
        printf("\nFIXED: the malicious DHX peer was correctly rejected "
               "(CVE-2026-42770).\n");
        exitcode = 0;
    }

 end:
    EVP_PKEY_free(rogue_peer);
    EVP_PKEY_free(good_peer);
    EVP_PKEY_free(local);
    return exitcode;
}
