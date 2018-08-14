#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use FindBin qw($Bin);
use lib "$Bin/../..";
use perlasm::s390x qw(:DEFAULT :VX AUTOLOAD LABEL INCLUDE);

my $flavour = shift;

my ($z,$SIZE_T);
if ($flavour =~ /3[12]/) {
	$z=0;	# S/390 ABI
	$SIZE_T=4;
} else {
	$z=1;	# zSeries ABI
	$SIZE_T=8;
}

my $output;
while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}

my $ra="%r14";
my $sp="%r15";
my $stdframe=16*$SIZE_T+4*8;

PERLASM_BEGIN($output);

INCLUDE	("s390x_arch.h");
TEXT	();

################
# void ecp_nistz256_mul_by_2(uint64_t res[4], uint64_t a[4])
{
GLOBL	("ecp_nistz256_mul_by_2");
TYPE	("ecp_nistz256_mul_by_2","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_mul_by_2");
	br	($ra);
SIZE	("ecp_nistz256_mul_by_2",".-ecp_nistz256_mul_by_2");
}

################
# void ecp_nistz256_div_by_2(uint64_t res[4], uint64_t a[4])
{
GLOBL	("ecp_nistz256_div_by_2");
TYPE	("ecp_nistz256_div_by_2","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_div_by_2");
	br	($ra);
SIZE	("ecp_nistz256_div_by_2",".-ecp_nistz256_div_by_2");
}

################
# void ecp_nistz256_mul_by_3(uint64_t res[4], uint64_t a[4])
{
GLOBL	("ecp_nistz256_mul_by_3");
TYPE	("ecp_nistz256_mul_by_3","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_mul_by_3");
	br	($ra);
SIZE	("ecp_nistz256_mul_by_3",".-ecp_nistz256_mul_by_3");
}

################
# void ecp_nistz256_add(uint64_t res[4], uint64_t a[4], uint64_t b[4])
{
GLOBL	("ecp_nistz256_add");
TYPE	("ecp_nistz256_add","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_add");
	br	($ra);
SIZE	("ecp_nistz256_add",".-ecp_nistz256_add");
}

################
# void ecp_nistz256_sub(uint64_t res[4], uint64_t a[4], uint64_t b[4])
{
GLOBL	("ecp_nistz256_sub");
TYPE	("ecp_nistz256_sub","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_sub");
	br	($ra);
SIZE	("ecp_nistz256_sub",".-ecp_nistz256_sub");
}

################
# void ecp_nistz256_neg(uint64_t res[4], uint64_t a[4])
{
GLOBL	("ecp_nistz256_neg");
TYPE	("ecp_nistz256_neg","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_neg");
	br	($ra);
SIZE	("ecp_nistz256_neg",".-ecp_nistz256_neg");
}

################
# void ecp_nistz256_ord_mul_mont(uint64_t res[4], uint64_t a[4], uint64_t b[4])
{
GLOBL	("ecp_nistz256_ord_mul_mont");
TYPE	("ecp_nistz256_ord_mul_mont","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_ord_mul_mont");
	br	($ra);
SIZE	("ecp_nistz256_ord_mul_mont",".-ecp_nistz256_ord_mul_mont");
}

################
# void ecp_nistz256_ord_sqr_mont(uint64_t res[4], uint64_t a[4], int rep)
{
GLOBL	("ecp_nistz256_ord_sqr_mont");
TYPE	("ecp_nistz256_ord_sqr_mont","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_ord_sqr_mont");
	br	($ra);
SIZE	("ecp_nistz256_ord_sqr_mont",".-ecp_nistz256_ord_sqr_mont");
}

################
# void ecp_nistz256_to_mont(uint64_t res[4], uint64_t in[4])
{
GLOBL	("ecp_nistz256_to_mont");
TYPE	("ecp_nistz256_to_mont","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_to_mont");
	br	($ra);
SIZE	("ecp_nistz256_to_mont",".-ecp_nistz256_to_mont");
}

################
# void ecp_nistz256_mul_mont(uint64_t res[4], uint64_t a[4], uint64_t b[4])
{
GLOBL	("ecp_nistz256_mul_mont");
TYPE	("ecp_nistz256_mul_mont","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_mul_mont");
	br	($ra);
SIZE	("ecp_nistz256_mul_mont",".-ecp_nistz256_mul_mont");
}

################
# void ecp_nistz256_sqr_mont(uint64_t res[4], uint64_t a[4])
{
GLOBL	("ecp_nistz256_sqr_mont");
TYPE	("ecp_nistz256_sqr_mont","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_sqr_mont");
	br	($ra);
SIZE	("ecp_nistz256_sqr_mont",".-ecp_nistz256_sqr_mont");
}

################
# void ecp_nistz256_from_mont(uint64_t res[4], uint64_t in[4])
{
GLOBL	("ecp_nistz256_from_mont");
TYPE	("ecp_nistz256_from_mont","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_from_mont");
	br	($ra);
SIZE	("ecp_nistz256_from_mont",".-ecp_nistz256_from_mont");
}

################
# void ecp_nistz256_scatter_w5(uint64_t *val, uint64_t *in_t, int index)
{
GLOBL	("ecp_nistz256_scatter_w5");
TYPE	("ecp_nistz256_scatter_w5","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_scatter_w5");
	br	($ra);
SIZE	("ecp_nistz256_scatter_w5",".-ecp_nistz256_scatter_w5");
}

################
# void ecp_nistz256_gather_w5(uint64_t *val, uint64_t *in_t, int index)
{
GLOBL	("ecp_nistz256_gather_w5");
TYPE	("ecp_nistz256_gather_w5","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_gather_w5");
	br	($ra);
SIZE	("ecp_nistz256_gather_w5",".-ecp_nistz256_gather_w5");
}

################
# void ecp_nistz256_scatter_w7(uint64_t *val, uint64_t *in_t, int index)
{
GLOBL	("ecp_nistz256_scatter_w7");
TYPE	("ecp_nistz256_scatter_w7","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_scatter_w7");
	br	($ra);
SIZE	("ecp_nistz256_scatter_w7",".-ecp_nistz256_scatter_w7");
}

################
# void ecp_nistz256_gather_w7(uint64_t *val, uint64_t *in_t, int index)
{
GLOBL	("ecp_nistz256_gather_w7");
TYPE	("ecp_nistz256_gather_w7","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_gather_w7");
	br	($ra);
SIZE	("ecp_nistz256_gather_w7",".-ecp_nistz256_gather_w7");
}

################
# void ecp_nistz256_point_double(P256_POINT *r, const P256_POINT *a)
{
GLOBL	("ecp_nistz256_point_double");
TYPE	("ecp_nistz256_point_double","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_point_double");
	br	($ra);
SIZE	("ecp_nistz256_point_double",".-ecp_nistz256_point_double");
}

################
# void ecp_nistz256_point_add(P256_POINT *r, const P256_POINT *a,
#                             const P256_POINT *b)
{
GLOBL	("ecp_nistz256_point_add");
TYPE	("ecp_nistz256_point_add","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_point_add");
	br	($ra);
SIZE	("ecp_nistz256_point_add",".-ecp_nistz256_point_add");
}

################
# void ecp_nistz256_point_add_affine(P256_POINT *r, const P256_POINT *a,
#                                    const P256_POINT_AFFINE *b)
{
GLOBL	("ecp_nistz256_point_add_affine");
TYPE	("ecp_nistz256_point_add_affine","\@function");
ALIGN	(32);
LABEL	("ecp_nistz256_point_add_affine");
	br	($ra);
SIZE	("ecp_nistz256_point_add_affine",".-ecp_nistz256_point_add_affine");
}


################
# const PRECOMP256_ROW ecp_nistz256_precomputed[37]
GLOBL	("ecp_nistz256_precomputed");
TYPE	("ecp_nistz256_precomputed","\@object");
ALIGN(4096);
LABEL	("ecp_nistz256_precomputed");
for (my $i=0; $i < 18944; $i++) {
LONG	("0x0");
}
SIZE	("ecp_nistz256_precomputed",".-ecp_nistz256_precomputed");


PERLASM_END();
