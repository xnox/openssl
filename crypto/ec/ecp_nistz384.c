/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * NIST P-384 acceleration, modelled on ecp_nistz256.c (Gueron-Krasnov).
 *
 * The field arithmetic is provided in assembly (ecp_nistz384-*.pl) operating
 * on 6-limb (384-bit) values in the Montgomery domain.  Point arithmetic and
 * windowed/fixed-base scalar multiplication are implemented here in C over
 * those primitives.  Only the scalar-multiplication entry point (mul) and
 * have_precompute_mult are overridden relative to the generic Montgomery
 * method; everything else delegates to the generic implementation.
 */

#include <string.h>

#include "internal/cryptlib.h"
#include "crypto/bn.h"
#include "ec_local.h"
#include "internal/refcount.h"

#if BN_BITS2 != 64
# error "ecp_nistz384 requires a 64-bit BN_ULONG"
#endif

#define P384_LIMBS 6

typedef struct {
    BN_ULONG X[P384_LIMBS];
    BN_ULONG Y[P384_LIMBS];
    BN_ULONG Z[P384_LIMBS];
} P384_POINT;

typedef struct {
    BN_ULONG X[P384_LIMBS];
    BN_ULONG Y[P384_LIMBS];
} P384_POINT_AFFINE;

/* Functions implemented in assembly (ecp_nistz384-x86_64.pl / -armv8.pl) */
void ecp_nistz384_add(BN_ULONG r[P384_LIMBS], const BN_ULONG a[P384_LIMBS],
                      const BN_ULONG b[P384_LIMBS]);
void ecp_nistz384_sub(BN_ULONG r[P384_LIMBS], const BN_ULONG a[P384_LIMBS],
                      const BN_ULONG b[P384_LIMBS]);
void ecp_nistz384_neg(BN_ULONG r[P384_LIMBS], const BN_ULONG a[P384_LIMBS]);
void ecp_nistz384_mul_by_2(BN_ULONG r[P384_LIMBS], const BN_ULONG a[P384_LIMBS]);
void ecp_nistz384_mul_by_3(BN_ULONG r[P384_LIMBS], const BN_ULONG a[P384_LIMBS]);
void ecp_nistz384_div_by_2(BN_ULONG r[P384_LIMBS], const BN_ULONG a[P384_LIMBS]);
void ecp_nistz384_mul_mont(BN_ULONG r[P384_LIMBS], const BN_ULONG a[P384_LIMBS],
                           const BN_ULONG b[P384_LIMBS]);
void ecp_nistz384_sqr_mont(BN_ULONG r[P384_LIMBS], const BN_ULONG a[P384_LIMBS]);
void ecp_nistz384_from_mont(BN_ULONG r[P384_LIMBS], const BN_ULONG a[P384_LIMBS]);
void ecp_nistz384_to_mont(BN_ULONG r[P384_LIMBS], const BN_ULONG a[P384_LIMBS]);

/* One in the Montgomery domain (2^384 mod p) */
static const BN_ULONG ONE[P384_LIMBS] = {
    0xffffffff00000001ULL, 0x00000000ffffffffULL, 0x0000000000000001ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL
};

/* Precomputed multiples of the standard generator (ecp_nistz384_table.c) */
extern const P384_POINT_AFFINE ecp_nistz384_precomputed[55][64];

static BN_ULONG is_zero(BN_ULONG in)
{
    in |= (0 - in);
    in = ~in;
    in >>= BN_BITS2 - 1;
    return in;
}

static BN_ULONG is_equal(const BN_ULONG a[P384_LIMBS], const BN_ULONG b[P384_LIMBS])
{
    BN_ULONG res = a[0] ^ b[0];
    res |= a[1] ^ b[1];
    res |= a[2] ^ b[2];
    res |= a[3] ^ b[3];
    res |= a[4] ^ b[4];
    res |= a[5] ^ b[5];
    return is_zero(res);
}

static void copy_conditional(BN_ULONG dst[P384_LIMBS],
                             const BN_ULONG src[P384_LIMBS], BN_ULONG move)
{
    BN_ULONG mask1 = 0 - move;
    BN_ULONG mask2 = ~mask1;
    int i;

    for (i = 0; i < P384_LIMBS; i++)
        dst[i] = (src[i] & mask1) ^ (dst[i] & mask2);
}

static unsigned int _booth_recode_w5(unsigned int in)
{
    unsigned int s, d;

    s = ~((in >> 5) - 1);
    d = (1 << 6) - in - 1;
    d = (d & s) | (in & ~s);
    d = (d >> 1) + (d & 1);
    return (d << 1) + (s & 1);
}

static unsigned int _booth_recode_w7(unsigned int in)
{
    unsigned int s, d;

    s = ~((in >> 7) - 1);
    d = (1 << 8) - in - 1;
    d = (d & s) | (in & ~s);
    d = (d >> 1) + (d & 1);
    return (d << 1) + (s & 1);
}

/* constant-time gather of a Jacobian point: idx 0 => infinity */
static void gather_w5(P384_POINT *out, const P384_POINT tbl[16], int idx)
{
    int i, k;

    memset(out, 0, sizeof(*out));
    for (i = 1; i <= 16; i++) {
        BN_ULONG mask = 0 - is_zero((BN_ULONG)(idx ^ i));

        for (k = 0; k < P384_LIMBS; k++) {
            out->X[k] |= tbl[i - 1].X[k] & mask;
            out->Y[k] |= tbl[i - 1].Y[k] & mask;
            out->Z[k] |= tbl[i - 1].Z[k] & mask;
        }
    }
}

/* constant-time gather of an affine point: idx 0 => (0,0) */
static void gather_w7(P384_POINT_AFFINE *out, const P384_POINT_AFFINE tbl[64],
                      int idx)
{
    int i, k;

    memset(out, 0, sizeof(*out));
    for (i = 1; i <= 64; i++) {
        BN_ULONG mask = 0 - is_zero((BN_ULONG)(idx ^ i));

        for (k = 0; k < P384_LIMBS; k++) {
            out->X[k] |= tbl[i - 1].X[k] & mask;
            out->Y[k] |= tbl[i - 1].Y[k] & mask;
        }
    }
}

/* Point double: r = 2*a */
static void ecp_nistz384_point_double(P384_POINT *r, const P384_POINT *a)
{
    BN_ULONG S[P384_LIMBS], M[P384_LIMBS], Zsqr[P384_LIMBS], tmp0[P384_LIMBS];
    const BN_ULONG *in_x = a->X, *in_y = a->Y, *in_z = a->Z;
    BN_ULONG *res_x = r->X, *res_y = r->Y, *res_z = r->Z;

    ecp_nistz384_mul_by_2(S, in_y);
    ecp_nistz384_sqr_mont(Zsqr, in_z);
    ecp_nistz384_sqr_mont(S, S);
    ecp_nistz384_mul_mont(res_z, in_z, in_y);
    ecp_nistz384_mul_by_2(res_z, res_z);
    ecp_nistz384_add(M, in_x, Zsqr);
    ecp_nistz384_sub(Zsqr, in_x, Zsqr);
    ecp_nistz384_sqr_mont(res_y, S);
    ecp_nistz384_div_by_2(res_y, res_y);
    ecp_nistz384_mul_mont(M, M, Zsqr);
    ecp_nistz384_mul_by_3(M, M);
    ecp_nistz384_mul_mont(S, S, in_x);
    ecp_nistz384_mul_by_2(tmp0, S);
    ecp_nistz384_sqr_mont(res_x, M);
    ecp_nistz384_sub(res_x, res_x, tmp0);
    ecp_nistz384_sub(S, S, res_x);
    ecp_nistz384_mul_mont(S, S, M);
    ecp_nistz384_sub(res_y, S, res_y);
}

/* Point addition: r = a+b */
static void ecp_nistz384_point_add(P384_POINT *r,
                                   const P384_POINT *a, const P384_POINT *b)
{
    BN_ULONG U2[P384_LIMBS], S2[P384_LIMBS], U1[P384_LIMBS], S1[P384_LIMBS];
    BN_ULONG Z1sqr[P384_LIMBS], Z2sqr[P384_LIMBS], H[P384_LIMBS], R[P384_LIMBS];
    BN_ULONG Hsqr[P384_LIMBS], Rsqr[P384_LIMBS], Hcub[P384_LIMBS];
    BN_ULONG res_x[P384_LIMBS], res_y[P384_LIMBS], res_z[P384_LIMBS];
    BN_ULONG in1infty, in2infty;
    const BN_ULONG *in1_x = a->X, *in1_y = a->Y, *in1_z = a->Z;
    const BN_ULONG *in2_x = b->X, *in2_y = b->Y, *in2_z = b->Z;

    in1infty = in1_z[0] | in1_z[1] | in1_z[2] | in1_z[3] | in1_z[4] | in1_z[5];
    in2infty = in2_z[0] | in2_z[1] | in2_z[2] | in2_z[3] | in2_z[4] | in2_z[5];
    in1infty = is_zero(in1infty);
    in2infty = is_zero(in2infty);

    ecp_nistz384_sqr_mont(Z2sqr, in2_z);
    ecp_nistz384_sqr_mont(Z1sqr, in1_z);
    ecp_nistz384_mul_mont(S1, Z2sqr, in2_z);
    ecp_nistz384_mul_mont(S2, Z1sqr, in1_z);
    ecp_nistz384_mul_mont(S1, S1, in1_y);
    ecp_nistz384_mul_mont(S2, S2, in2_y);
    ecp_nistz384_sub(R, S2, S1);
    ecp_nistz384_mul_mont(U1, in1_x, Z2sqr);
    ecp_nistz384_mul_mont(U2, in2_x, Z1sqr);
    ecp_nistz384_sub(H, U2, U1);

    if (is_equal(U1, U2) & ~in1infty & ~in2infty & is_equal(S1, S2)) {
        ecp_nistz384_point_double(r, a);
        return;
    }

    ecp_nistz384_sqr_mont(Rsqr, R);
    ecp_nistz384_mul_mont(res_z, H, in1_z);
    ecp_nistz384_sqr_mont(Hsqr, H);
    ecp_nistz384_mul_mont(res_z, res_z, in2_z);
    ecp_nistz384_mul_mont(Hcub, Hsqr, H);
    ecp_nistz384_mul_mont(U2, U1, Hsqr);
    ecp_nistz384_mul_by_2(Hsqr, U2);
    ecp_nistz384_sub(res_x, Rsqr, Hsqr);
    ecp_nistz384_sub(res_x, res_x, Hcub);
    ecp_nistz384_sub(res_y, U2, res_x);
    ecp_nistz384_mul_mont(S2, S1, Hcub);
    ecp_nistz384_mul_mont(res_y, R, res_y);
    ecp_nistz384_sub(res_y, res_y, S2);

    copy_conditional(res_x, in2_x, in1infty);
    copy_conditional(res_y, in2_y, in1infty);
    copy_conditional(res_z, in2_z, in1infty);
    copy_conditional(res_x, in1_x, in2infty);
    copy_conditional(res_y, in1_y, in2infty);
    copy_conditional(res_z, in1_z, in2infty);

    memcpy(r->X, res_x, sizeof(res_x));
    memcpy(r->Y, res_y, sizeof(res_y));
    memcpy(r->Z, res_z, sizeof(res_z));
}

/* Point addition with affine b: r = a+b */
static void ecp_nistz384_point_add_affine(P384_POINT *r, const P384_POINT *a,
                                          const P384_POINT_AFFINE *b)
{
    BN_ULONG U2[P384_LIMBS], S2[P384_LIMBS], Z1sqr[P384_LIMBS];
    BN_ULONG H[P384_LIMBS], R[P384_LIMBS], Hsqr[P384_LIMBS];
    BN_ULONG Rsqr[P384_LIMBS], Hcub[P384_LIMBS];
    BN_ULONG res_x[P384_LIMBS], res_y[P384_LIMBS], res_z[P384_LIMBS];
    BN_ULONG in1infty, in2infty;
    const BN_ULONG *in1_x = a->X, *in1_y = a->Y, *in1_z = a->Z;
    const BN_ULONG *in2_x = b->X, *in2_y = b->Y;

    in1infty = in1_z[0] | in1_z[1] | in1_z[2] | in1_z[3] | in1_z[4] | in1_z[5];
    in2infty = in2_x[0] | in2_x[1] | in2_x[2] | in2_x[3] | in2_x[4] | in2_x[5] |
               in2_y[0] | in2_y[1] | in2_y[2] | in2_y[3] | in2_y[4] | in2_y[5];
    in1infty = is_zero(in1infty);
    in2infty = is_zero(in2infty);

    ecp_nistz384_sqr_mont(Z1sqr, in1_z);
    ecp_nistz384_mul_mont(U2, in2_x, Z1sqr);
    ecp_nistz384_sub(H, U2, in1_x);
    ecp_nistz384_mul_mont(S2, Z1sqr, in1_z);
    ecp_nistz384_mul_mont(res_z, H, in1_z);
    ecp_nistz384_mul_mont(S2, S2, in2_y);
    ecp_nistz384_sub(R, S2, in1_y);
    ecp_nistz384_sqr_mont(Hsqr, H);
    ecp_nistz384_sqr_mont(Rsqr, R);
    ecp_nistz384_mul_mont(Hcub, Hsqr, H);
    ecp_nistz384_mul_mont(U2, in1_x, Hsqr);
    ecp_nistz384_mul_by_2(Hsqr, U2);
    ecp_nistz384_sub(res_x, Rsqr, Hsqr);
    ecp_nistz384_sub(res_x, res_x, Hcub);
    ecp_nistz384_sub(H, U2, res_x);
    ecp_nistz384_mul_mont(S2, in1_y, Hcub);
    ecp_nistz384_mul_mont(H, H, R);
    ecp_nistz384_sub(res_y, H, S2);

    copy_conditional(res_x, in2_x, in1infty);
    copy_conditional(res_x, in1_x, in2infty);
    copy_conditional(res_y, in2_y, in1infty);
    copy_conditional(res_y, in1_y, in2infty);
    copy_conditional(res_z, ONE, in1infty);
    copy_conditional(res_z, in1_z, in2infty);

    memcpy(r->X, res_x, sizeof(res_x));
    memcpy(r->Y, res_y, sizeof(res_y));
    memcpy(r->Z, res_z, sizeof(res_z));
}

/* r = scalar * point (variable base), window 5, constant time. */
static void ecp_nistz384_windowed_mul(P384_POINT *r, const P384_POINT *point,
                                      const unsigned char p_str[56])
{
    P384_POINT table[16], t0, t1;
    const unsigned int mask = (1 << 6) - 1;
    unsigned int wvalue;
    int idx;

    table[0] = *point;
    ecp_nistz384_point_double(&table[1],  &table[0]);
    ecp_nistz384_point_add   (&table[2],  &table[1], point);
    ecp_nistz384_point_double(&table[3],  &table[1]);
    ecp_nistz384_point_add   (&table[4],  &table[3], point);
    ecp_nistz384_point_double(&table[5],  &table[2]);
    ecp_nistz384_point_add   (&table[6],  &table[5], point);
    ecp_nistz384_point_double(&table[7],  &table[3]);
    ecp_nistz384_point_add   (&table[8],  &table[7], point);
    ecp_nistz384_point_double(&table[9],  &table[4]);
    ecp_nistz384_point_add   (&table[10], &table[9], point);
    ecp_nistz384_point_double(&table[11], &table[5]);
    ecp_nistz384_point_add   (&table[12], &table[11], point);
    ecp_nistz384_point_double(&table[13], &table[6]);
    ecp_nistz384_point_add   (&table[14], &table[13], point);
    ecp_nistz384_point_double(&table[15], &table[7]);

    idx = 385;
    wvalue = p_str[(idx - 1) / 8];
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    wvalue = _booth_recode_w5(wvalue);
    gather_w5(&t0, table, wvalue >> 1);
    ecp_nistz384_neg(t1.Y, t0.Y);
    copy_conditional(t0.Y, t1.Y, wvalue & 1);
    *r = t0;

    while (idx >= 5) {
        if (idx != 385) {
            unsigned int off = (idx - 1) / 8;

            wvalue = p_str[off] | p_str[off + 1] << 8;
            wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
            wvalue = _booth_recode_w5(wvalue);
            gather_w5(&t0, table, wvalue >> 1);
            ecp_nistz384_neg(t1.Y, t0.Y);
            copy_conditional(t0.Y, t1.Y, wvalue & 1);
            ecp_nistz384_point_add(r, r, &t0);
        }
        idx -= 5;
        ecp_nistz384_point_double(r, r);
        ecp_nistz384_point_double(r, r);
        ecp_nistz384_point_double(r, r);
        ecp_nistz384_point_double(r, r);
        ecp_nistz384_point_double(r, r);
    }

    wvalue = p_str[0];
    wvalue = (wvalue << 1) & mask;
    wvalue = _booth_recode_w5(wvalue);
    gather_w5(&t0, table, wvalue >> 1);
    ecp_nistz384_neg(t1.Y, t0.Y);
    copy_conditional(t0.Y, t1.Y, wvalue & 1);
    ecp_nistz384_point_add(r, r, &t0);
}

/* r = scalar * G (fixed base), window 7, constant time. */
static void ecp_nistz384_fixed_mul(P384_POINT *r, const unsigned char p_str[56])
{
    const unsigned int mask = (1 << 8) - 1;
    unsigned int wvalue, idx = 0;
    P384_POINT_AFFINE t;
    BN_ULONG negY[P384_LIMBS], infty;
    int i, k;

    wvalue = (p_str[0] << 1) & mask;
    idx += 7;
    wvalue = _booth_recode_w7(wvalue);
    gather_w7(&t, ecp_nistz384_precomputed[0], wvalue >> 1);
    ecp_nistz384_neg(negY, t.Y);
    copy_conditional(t.Y, negY, wvalue & 1);
    memcpy(r->X, t.X, sizeof(t.X));
    memcpy(r->Y, t.Y, sizeof(t.Y));
    infty = 0;
    for (k = 0; k < P384_LIMBS; k++)
        infty |= t.X[k] | t.Y[k];
    infty = ~(0 - is_zero(infty));
    for (k = 0; k < P384_LIMBS; k++)
        r->Z[k] = ONE[k] & infty;

    for (i = 1; i < 55; i++) {
        unsigned int off = (idx - 1) / 8;

        wvalue = p_str[off] | p_str[off + 1] << 8;
        wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
        idx += 7;
        wvalue = _booth_recode_w7(wvalue);
        gather_w7(&t, ecp_nistz384_precomputed[i], wvalue >> 1);
        ecp_nistz384_neg(negY, t.Y);
        copy_conditional(t.Y, negY, wvalue & 1);
        ecp_nistz384_point_add_affine(r, r, &t);
    }
}

static int ecp_nistz384_bignum_to_field_elem(BN_ULONG out[P384_LIMBS],
                                              const BIGNUM *in)
{
    return bn_copy_words(out, in, P384_LIMBS);
}

/* Is |generator| the standard P-384 generator (for which we have a table)?
 * Generator coordinates are stored in the Montgomery domain; the precomputed
 * table's first entry is 1*G in affine Montgomery form. */
static int ecp_nistz384_is_affine_G(const EC_POINT *generator)
{
    BN_ULONG gx[P384_LIMBS], gy[P384_LIMBS], gz[P384_LIMBS];

    if (!bn_copy_words(gx, generator->X, P384_LIMBS)
        || !bn_copy_words(gy, generator->Y, P384_LIMBS)
        || !bn_copy_words(gz, generator->Z, P384_LIMBS))
        return 0;
    return is_equal(gx, ecp_nistz384_precomputed[0][0].X)
        && is_equal(gy, ecp_nistz384_precomputed[0][0].Y)
        && is_equal(gz, ONE);
}

/* Convert a scalar to a reduced little-endian byte string of >=48 bytes. */
static int scalar_to_str(unsigned char p_str[56], const BIGNUM *scalar,
                         const BIGNUM *order, BN_CTX *ctx)
{
    BIGNUM *tmp = NULL;

    memset(p_str, 0, 56);
    if (BN_num_bits(scalar) > 384 || BN_is_negative(scalar)) {
        if ((tmp = BN_CTX_get(ctx)) == NULL)
            return 0;
        if (!BN_nnmod(tmp, scalar, order, ctx))
            return 0;
        scalar = tmp;
    }
    return BN_bn2lebinpad(scalar, p_str, 48) >= 0;
}

__owur static int ecp_nistz384_points_mul(const EC_GROUP *group, EC_POINT *r,
                                          const BIGNUM *scalar, size_t num,
                                          const EC_POINT *points[],
                                          const BIGNUM *scalars[], BN_CTX *ctx)
{
    int ret = 0;
    size_t i;
    unsigned char p_str[56];
    P384_POINT acc, tmp;
    int have_acc = 0;
    const EC_POINT *generator = NULL;
    const BIGNUM *order;

    BN_CTX_start(ctx);
    order = EC_GROUP_get0_order(group);

    /* Generator term: scalar * G */
    if (scalar != NULL) {
        generator = EC_GROUP_get0_generator(group);
        if (generator == NULL) {
            ERR_raise(ERR_LIB_EC, EC_R_UNDEFINED_GENERATOR);
            goto err;
        }
        if (ecp_nistz384_is_affine_G(generator)) {
            if (!scalar_to_str(p_str, scalar, order, ctx))
                goto err;
            ecp_nistz384_fixed_mul(&acc, p_str);
            have_acc = 1;
        } else {
            /* Non-standard generator: handle it as a variable-base point. */
            P384_POINT g;

            if (!ecp_nistz384_bignum_to_field_elem(g.X, generator->X)
                || !ecp_nistz384_bignum_to_field_elem(g.Y, generator->Y)
                || !ecp_nistz384_bignum_to_field_elem(g.Z, generator->Z)) {
                ERR_raise(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
                goto err;
            }
            if (!scalar_to_str(p_str, scalar, order, ctx))
                goto err;
            ecp_nistz384_windowed_mul(&acc, &g, p_str);
            have_acc = 1;
        }
    }

    /* Variable-base terms: scalars[i] * points[i] */
    for (i = 0; i < num; i++) {
        P384_POINT p;

        if (!ecp_nistz384_bignum_to_field_elem(p.X, points[i]->X)
            || !ecp_nistz384_bignum_to_field_elem(p.Y, points[i]->Y)
            || !ecp_nistz384_bignum_to_field_elem(p.Z, points[i]->Z)) {
            ERR_raise(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
            goto err;
        }
        if (!scalar_to_str(p_str, scalars[i], order, ctx))
            goto err;
        ecp_nistz384_windowed_mul(&tmp, &p, p_str);
        if (!have_acc) {
            acc = tmp;
            have_acc = 1;
        } else {
            ecp_nistz384_point_add(&acc, &acc, &tmp);
        }
    }

    if (!have_acc)
        memset(&acc, 0, sizeof(acc));   /* infinity */

    /* Not constant-time, but operating on the public output. */
    if (!bn_set_words(r->X, acc.X, P384_LIMBS)
        || !bn_set_words(r->Y, acc.Y, P384_LIMBS)
        || !bn_set_words(r->Z, acc.Z, P384_LIMBS))
        goto err;
    r->Z_is_one = is_equal(acc.Z, ONE) & 1;

    ret = 1;
 err:
    BN_CTX_end(ctx);
    return ret;
}

static int ecp_nistz384_window_have_precompute_mult(const EC_GROUP *group)
{
    const EC_POINT *generator = EC_GROUP_get0_generator(group);

    return generator != NULL && ecp_nistz384_is_affine_G(generator);
}

const EC_METHOD *EC_GFp_nistz384_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        NID_X9_62_prime_field,
        ossl_ec_GFp_mont_group_init,
        ossl_ec_GFp_mont_group_finish,
        ossl_ec_GFp_mont_group_clear_finish,
        ossl_ec_GFp_mont_group_copy,
        ossl_ec_GFp_mont_group_set_curve,
        ossl_ec_GFp_simple_group_get_curve,
        ossl_ec_GFp_simple_group_get_degree,
        ossl_ec_group_simple_order_bits,
        ossl_ec_GFp_simple_group_check_discriminant,
        ossl_ec_GFp_simple_point_init,
        ossl_ec_GFp_simple_point_finish,
        ossl_ec_GFp_simple_point_clear_finish,
        ossl_ec_GFp_simple_point_copy,
        ossl_ec_GFp_simple_point_set_to_infinity,
        ossl_ec_GFp_simple_point_set_affine_coordinates,
        ossl_ec_GFp_simple_point_get_affine_coordinates,
        0, 0, 0,
        ossl_ec_GFp_simple_add,
        ossl_ec_GFp_simple_dbl,
        ossl_ec_GFp_simple_invert,
        ossl_ec_GFp_simple_is_at_infinity,
        ossl_ec_GFp_simple_is_on_curve,
        ossl_ec_GFp_simple_cmp,
        ossl_ec_GFp_simple_make_affine,
        ossl_ec_GFp_simple_points_make_affine,
        ecp_nistz384_points_mul,                    /* mul */
        0,                                          /* precompute_mult */
        ecp_nistz384_window_have_precompute_mult,   /* have_precompute_mult */
        ossl_ec_GFp_mont_field_mul,
        ossl_ec_GFp_mont_field_sqr,
        0,                                          /* field_div */
        ossl_ec_GFp_mont_field_inv,
        ossl_ec_GFp_mont_field_encode,
        ossl_ec_GFp_mont_field_decode,
        ossl_ec_GFp_mont_field_set_to_one,
        ossl_ec_key_simple_priv2oct,
        ossl_ec_key_simple_oct2priv,
        0, /* set private */
        ossl_ec_key_simple_generate_key,
        ossl_ec_key_simple_check_key,
        ossl_ec_key_simple_generate_public_key,
        0, /* keycopy */
        0, /* keyfinish */
        ossl_ecdh_simple_compute_key,
        ossl_ecdsa_simple_sign_setup,
        ossl_ecdsa_simple_sign_sig,
        ossl_ecdsa_simple_verify_sig,
        0,                                          /* field_inverse_mod_ord */
        0,                                          /* blind_coordinates */
        0,                                          /* ladder_pre */
        0,                                          /* ladder_step */
        0,                                          /* ladder_post */
        0                                           /* group_full_init */
    };

    return &ret;
}
