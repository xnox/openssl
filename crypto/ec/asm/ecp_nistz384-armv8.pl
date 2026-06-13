#! /usr/bin/env perl
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ECP_NISTZ384 - 64-bit, Montgomery-domain field arithmetic for NIST P-384,
# aarch64, modelled on ecp_nistz256-armv8.pl.
#
# Field-arithmetic layer only (this revision):
#   ecp_nistz384_add / sub / neg / mul_by_2 / mul_by_3 / div_by_2
#   ecp_nistz384_mul_mont (CIOS) / sqr_mont / from_mont / to_mont
#
# Montgomery reduction is a generic CIOS reduction using
#   n0 = -p^-1 mod 2^64 = 0x0000000100000001
# All routines are constant-time (csel/csetm, no data-dependent branches).

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;
$output  = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

my ($rp,$ap,$bp)=map("x$_",(0..2));

$code.=<<___;
#include "arm_arch.h"
.text

.rodata
.align	5
.Lpoly:
.quad	0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff
.LRR:	// 2^768 mod P
.quad	0xfffffffe00000001, 0x0000000200000000, 0xfffffffe00000000, 0x0000000200000000, 0x0000000000000001, 0x0000000000000000
.LONE:	// the integer 1
.quad	0x0000000000000001, 0, 0, 0, 0, 0
.previous
___

################################################################################
# Simple field ops.
{
$code.=<<___;
// void ecp_nistz384_add(uint64_t res[6], const uint64_t a[6], const uint64_t b[6]);
.globl	ecp_nistz384_add
.type	ecp_nistz384_add,%function
.align	4
ecp_nistz384_add:
	AARCH64_VALID_CALL_TARGET
	stp	x19,x30,[sp,#-16]!

	ldp	x3,x4,[$ap]
	ldp	x10,x11,[$bp]
	adds	x3,x3,x10
	adcs	x4,x4,x11
	ldp	x5,x6,[$ap,#16]
	ldp	x10,x11,[$bp,#16]
	adcs	x5,x5,x10
	adcs	x6,x6,x11
	ldp	x7,x8,[$ap,#32]
	ldp	x10,x11,[$bp,#32]
	adcs	x7,x7,x10
	adcs	x8,x8,x11
	adc	x9,xzr,xzr		// carry-out

	adrp	x12,.Lpoly
	add	x12,x12,:lo12:.Lpoly
	ldp	x10,x11,[x12]
	subs	x13,x3,x10
	sbcs	x14,x4,x11
	ldp	x10,x11,[x12,#16]
	sbcs	x15,x5,x10
	sbcs	x16,x6,x11
	ldp	x10,x11,[x12,#32]
	sbcs	x17,x7,x10
	sbcs	x19,x8,x11
	sbcs	xzr,x9,xzr		// borrow vs carry-out; CS => sum>=P

	csel	x3,x13,x3,cs
	csel	x4,x14,x4,cs
	csel	x5,x15,x5,cs
	csel	x6,x16,x6,cs
	csel	x7,x17,x7,cs
	csel	x8,x19,x8,cs
	stp	x3,x4,[$rp]
	stp	x5,x6,[$rp,#16]
	stp	x7,x8,[$rp,#32]

	ldp	x19,x30,[sp],#16
	ret
.size	ecp_nistz384_add,.-ecp_nistz384_add

// void ecp_nistz384_mul_by_2(uint64_t res[6], const uint64_t a[6]);
.globl	ecp_nistz384_mul_by_2
.type	ecp_nistz384_mul_by_2,%function
.align	4
ecp_nistz384_mul_by_2:
	AARCH64_VALID_CALL_TARGET
	stp	x19,x30,[sp,#-16]!

	ldp	x3,x4,[$ap]
	ldp	x5,x6,[$ap,#16]
	ldp	x7,x8,[$ap,#32]
	adds	x3,x3,x3
	adcs	x4,x4,x4
	adcs	x5,x5,x5
	adcs	x6,x6,x6
	adcs	x7,x7,x7
	adcs	x8,x8,x8
	adc	x9,xzr,xzr

	adrp	x12,.Lpoly
	add	x12,x12,:lo12:.Lpoly
	ldp	x10,x11,[x12]
	subs	x13,x3,x10
	sbcs	x14,x4,x11
	ldp	x10,x11,[x12,#16]
	sbcs	x15,x5,x10
	sbcs	x16,x6,x11
	ldp	x10,x11,[x12,#32]
	sbcs	x17,x7,x10
	sbcs	x19,x8,x11
	sbcs	xzr,x9,xzr

	csel	x3,x13,x3,cs
	csel	x4,x14,x4,cs
	csel	x5,x15,x5,cs
	csel	x6,x16,x6,cs
	csel	x7,x17,x7,cs
	csel	x8,x19,x8,cs
	stp	x3,x4,[$rp]
	stp	x5,x6,[$rp,#16]
	stp	x7,x8,[$rp,#32]

	ldp	x19,x30,[sp],#16
	ret
.size	ecp_nistz384_mul_by_2,.-ecp_nistz384_mul_by_2

// void ecp_nistz384_sub(uint64_t res[6], const uint64_t a[6], const uint64_t b[6]);
.globl	ecp_nistz384_sub
.type	ecp_nistz384_sub,%function
.align	4
ecp_nistz384_sub:
	AARCH64_VALID_CALL_TARGET
	ldp	x3,x4,[$ap]
	ldp	x10,x11,[$bp]
	subs	x3,x3,x10
	sbcs	x4,x4,x11
	ldp	x5,x6,[$ap,#16]
	ldp	x10,x11,[$bp,#16]
	sbcs	x5,x5,x10
	sbcs	x6,x6,x11
	ldp	x7,x8,[$ap,#32]
	ldp	x10,x11,[$bp,#32]
	sbcs	x7,x7,x10
	sbcs	x8,x8,x11
	csetm	x9,cc			// mask = -(a<b)

	adrp	x12,.Lpoly
	add	x12,x12,:lo12:.Lpoly
	ldp	x10,x11,[x12]
	and	x10,x10,x9
	and	x11,x11,x9
	adds	x3,x3,x10
	adcs	x4,x4,x11
	ldp	x10,x11,[x12,#16]
	and	x10,x10,x9
	and	x11,x11,x9
	adcs	x5,x5,x10
	adcs	x6,x6,x11
	ldp	x10,x11,[x12,#32]
	and	x10,x10,x9
	and	x11,x11,x9
	adcs	x7,x7,x10
	adc	x8,x8,x11
	stp	x3,x4,[$rp]
	stp	x5,x6,[$rp,#16]
	stp	x7,x8,[$rp,#32]
	ret
.size	ecp_nistz384_sub,.-ecp_nistz384_sub

// void ecp_nistz384_neg(uint64_t res[6], const uint64_t a[6]);
.globl	ecp_nistz384_neg
.type	ecp_nistz384_neg,%function
.align	4
ecp_nistz384_neg:
	AARCH64_VALID_CALL_TARGET
	ldp	x10,x11,[$ap]
	subs	x3,xzr,x10
	sbcs	x4,xzr,x11
	ldp	x10,x11,[$ap,#16]
	sbcs	x5,xzr,x10
	sbcs	x6,xzr,x11
	ldp	x10,x11,[$ap,#32]
	sbcs	x7,xzr,x10
	sbcs	x8,xzr,x11
	csetm	x9,cc			// mask = -(a!=0)

	adrp	x12,.Lpoly
	add	x12,x12,:lo12:.Lpoly
	ldp	x10,x11,[x12]
	and	x10,x10,x9
	and	x11,x11,x9
	adds	x3,x3,x10
	adcs	x4,x4,x11
	ldp	x10,x11,[x12,#16]
	and	x10,x10,x9
	and	x11,x11,x9
	adcs	x5,x5,x10
	adcs	x6,x6,x11
	ldp	x10,x11,[x12,#32]
	and	x10,x10,x9
	and	x11,x11,x9
	adcs	x7,x7,x10
	adc	x8,x8,x11
	stp	x3,x4,[$rp]
	stp	x5,x6,[$rp,#16]
	stp	x7,x8,[$rp,#32]
	ret
.size	ecp_nistz384_neg,.-ecp_nistz384_neg

// void ecp_nistz384_div_by_2(uint64_t res[6], const uint64_t a[6]);
.globl	ecp_nistz384_div_by_2
.type	ecp_nistz384_div_by_2,%function
.align	4
ecp_nistz384_div_by_2:
	AARCH64_VALID_CALL_TARGET
	ldp	x3,x4,[$ap]
	ldp	x5,x6,[$ap,#16]
	ldp	x7,x8,[$ap,#32]
	ands	xzr,x3,#1
	csetm	x9,ne			// mask = -(a is odd)

	adrp	x12,.Lpoly
	add	x12,x12,:lo12:.Lpoly
	ldp	x10,x11,[x12]
	and	x10,x10,x9
	and	x11,x11,x9
	adds	x3,x3,x10
	adcs	x4,x4,x11
	ldp	x10,x11,[x12,#16]
	and	x10,x10,x9
	and	x11,x11,x9
	adcs	x5,x5,x10
	adcs	x6,x6,x11
	ldp	x10,x11,[x12,#32]
	and	x10,x10,x9
	and	x11,x11,x9
	adcs	x7,x7,x10
	adcs	x8,x8,x11
	adc	x2,xzr,xzr		// top carry bit (a+P can exceed 384 bits)

	extr	x3,x4,x3,#1
	extr	x4,x5,x4,#1
	extr	x5,x6,x5,#1
	extr	x6,x7,x6,#1
	extr	x7,x8,x7,#1
	extr	x8,x2,x8,#1
	stp	x3,x4,[$rp]
	stp	x5,x6,[$rp,#16]
	stp	x7,x8,[$rp,#32]
	ret
.size	ecp_nistz384_div_by_2,.-ecp_nistz384_div_by_2

// void ecp_nistz384_mul_by_3(uint64_t res[6], const uint64_t a[6]);
.globl	ecp_nistz384_mul_by_3
.type	ecp_nistz384_mul_by_3,%function
.align	4
ecp_nistz384_mul_by_3:
	AARCH64_VALID_CALL_TARGET
	stp	x19,x30,[sp,#-16]!

	ldp	x3,x4,[$ap]
	ldp	x5,x6,[$ap,#16]
	ldp	x7,x8,[$ap,#32]
	adrp	x12,.Lpoly
	add	x12,x12,:lo12:.Lpoly

	// ---- t = 2a mod P
	adds	x3,x3,x3
	adcs	x4,x4,x4
	adcs	x5,x5,x5
	adcs	x6,x6,x6
	adcs	x7,x7,x7
	adcs	x8,x8,x8
	adc	x9,xzr,xzr
	ldp	x10,x11,[x12]
	subs	x13,x3,x10
	sbcs	x14,x4,x11
	ldp	x10,x11,[x12,#16]
	sbcs	x15,x5,x10
	sbcs	x16,x6,x11
	ldp	x10,x11,[x12,#32]
	sbcs	x17,x7,x10
	sbcs	x19,x8,x11
	sbcs	xzr,x9,xzr
	csel	x3,x13,x3,cs
	csel	x4,x14,x4,cs
	csel	x5,x15,x5,cs
	csel	x6,x16,x6,cs
	csel	x7,x17,x7,cs
	csel	x8,x19,x8,cs

	// ---- res = t + a mod P  (reload a)
	ldp	x10,x11,[$ap]
	adds	x3,x3,x10
	adcs	x4,x4,x11
	ldp	x10,x11,[$ap,#16]
	adcs	x5,x5,x10
	adcs	x6,x6,x11
	ldp	x10,x11,[$ap,#32]
	adcs	x7,x7,x10
	adcs	x8,x8,x11
	adc	x9,xzr,xzr
	ldp	x10,x11,[x12]
	subs	x13,x3,x10
	sbcs	x14,x4,x11
	ldp	x10,x11,[x12,#16]
	sbcs	x15,x5,x10
	sbcs	x16,x6,x11
	ldp	x10,x11,[x12,#32]
	sbcs	x17,x7,x10
	sbcs	x19,x8,x11
	sbcs	xzr,x9,xzr
	csel	x3,x13,x3,cs
	csel	x4,x14,x4,cs
	csel	x5,x15,x5,cs
	csel	x6,x16,x6,cs
	csel	x7,x17,x7,cs
	csel	x8,x19,x8,cs

	stp	x3,x4,[$rp]
	stp	x5,x6,[$rp,#16]
	stp	x7,x8,[$rp,#32]
	ldp	x19,x30,[sp],#16
	ret
.size	ecp_nistz384_mul_by_3,.-ecp_nistz384_mul_by_3
___
}

################################################################################
# Montgomery multiplication (CIOS).
{
my @T=map("x$_",(3..10));		# 8-word accumulator t0..t7
my ($m,$cy,$lo,$hi,$bi,$aj,$n0)=map("x$_",(11..17));
my @P=map("x$_",(19..24));		# poly[0..5]

sub cios_round {
    my $bi_off=shift;
    my $body="";
    my $i;
    $body.="\tldr\t$bi,[$bp,#8*$bi_off]\n";
    # ---- phase 1: T += a*b[i]
    $body.="\tmov\t$cy,xzr\n";
    for($i=0;$i<6;$i++) {
	$body.="\tldr\t$aj,[$ap,#8*$i]\n";
	$body.="\tmul\t$lo,$aj,$bi\n";
	$body.="\tumulh\t$hi,$aj,$bi\n";
	$body.="\tadds\t$T[$i],$T[$i],$cy\n";
	$body.="\tadc\t$hi,$hi,xzr\n";
	$body.="\tadds\t$T[$i],$T[$i],$lo\n";
	$body.="\tadc\t$cy,$hi,xzr\n";
    }
    $body.="\tadds\t$T[6],$T[6],$cy\n";
    $body.="\tadc\t$T[7],$T[7],xzr\n";
    # ---- phase 2: m=T[0]*n0; T += m*P; T[0] -> 0
    $body.="\tmul\t$m,$T[0],$n0\n";
    # j=0
    $body.="\tmul\t$lo,$m,$P[0]\n";
    $body.="\tumulh\t$hi,$m,$P[0]\n";
    $body.="\tadds\t$T[0],$T[0],$lo\n";	# T[0] becomes 0
    $body.="\tadc\t$cy,$hi,xzr\n";
    for($i=1;$i<6;$i++) {
	$body.="\tmul\t$lo,$m,$P[$i]\n";
	$body.="\tumulh\t$hi,$m,$P[$i]\n";
	$body.="\tadds\t$T[$i],$T[$i],$cy\n";
	$body.="\tadc\t$hi,$hi,xzr\n";
	$body.="\tadds\t$T[$i],$T[$i],$lo\n";
	$body.="\tadc\t$cy,$hi,xzr\n";
    }
    $body.="\tadds\t$T[6],$T[6],$cy\n";
    $body.="\tadc\t$T[7],$T[7],xzr\n";
    # T[0] is already 0; rotate so it becomes the new top word T[7].
    push(@T, shift(@T));
    return $body;
}

$code.=<<___;
// void ecp_nistz384_mul_mont(uint64_t res[6], const uint64_t a[6], const uint64_t b[6]);
.globl	ecp_nistz384_mul_mont
.type	ecp_nistz384_mul_mont,%function
.align	4
ecp_nistz384_mul_mont:
	AARCH64_VALID_CALL_TARGET
	stp	x19,x20,[sp,#-48]!
	stp	x21,x22,[sp,#16]
	stp	x23,x24,[sp,#32]

	adrp	$n0,.Lpoly
	add	$n0,$n0,:lo12:.Lpoly
	ldp	$P[0],$P[1],[$n0]
	ldp	$P[2],$P[3],[$n0,#16]
	ldp	$P[4],$P[5],[$n0,#32]
	movz	$n0,#0x0001
	movk	$n0,#0x0001,lsl#32	// n0 = 0x0000000100000001

	mov	$T[0],xzr
	mov	$T[1],xzr
	mov	$T[2],xzr
	mov	$T[3],xzr
	mov	$T[4],xzr
	mov	$T[5],xzr
	mov	$T[6],xzr
	mov	$T[7],xzr
___
for(my $r=0;$r<6;$r++) { $code.=&cios_round($r); }
$code.=<<___;
	// conditional final subtract of P (scratch x11-x16 are caller-saved/free)
	subs	x11,$T[0],$P[0]
	sbcs	x12,$T[1],$P[1]
	sbcs	x13,$T[2],$P[2]
	sbcs	x14,$T[3],$P[3]
	sbcs	x15,$T[4],$P[4]
	sbcs	x16,$T[5],$P[5]
	sbcs	xzr,$T[6],xzr		// CS => value>=P, take subtracted
	csel	$T[0],x11,$T[0],cs
	csel	$T[1],x12,$T[1],cs
	csel	$T[2],x13,$T[2],cs
	csel	$T[3],x14,$T[3],cs
	csel	$T[4],x15,$T[4],cs
	csel	$T[5],x16,$T[5],cs
	stp	$T[0],$T[1],[$rp]
	stp	$T[2],$T[3],[$rp,#16]
	stp	$T[4],$T[5],[$rp,#32]

	ldp	x23,x24,[sp,#32]
	ldp	x21,x22,[sp,#16]
	ldp	x19,x20,[sp],#48
	ret
.size	ecp_nistz384_mul_mont,.-ecp_nistz384_mul_mont

// void ecp_nistz384_sqr_mont(uint64_t res[6], const uint64_t a[6]);
.globl	ecp_nistz384_sqr_mont
.type	ecp_nistz384_sqr_mont,%function
.align	4
ecp_nistz384_sqr_mont:
	AARCH64_VALID_CALL_TARGET
	mov	$bp,$ap
	b	ecp_nistz384_mul_mont
.size	ecp_nistz384_sqr_mont,.-ecp_nistz384_sqr_mont

// void ecp_nistz384_from_mont(uint64_t res[6], const uint64_t in[6]);
.globl	ecp_nistz384_from_mont
.type	ecp_nistz384_from_mont,%function
.align	4
ecp_nistz384_from_mont:
	AARCH64_VALID_CALL_TARGET
	adrp	$bp,.LONE
	add	$bp,$bp,:lo12:.LONE
	b	ecp_nistz384_mul_mont
.size	ecp_nistz384_from_mont,.-ecp_nistz384_from_mont

// void ecp_nistz384_to_mont(uint64_t res[6], const uint64_t in[6]);
.globl	ecp_nistz384_to_mont
.type	ecp_nistz384_to_mont,%function
.align	4
ecp_nistz384_to_mont:
	AARCH64_VALID_CALL_TARGET
	adrp	$bp,.LRR
	add	$bp,$bp,:lo12:.LRR
	b	ecp_nistz384_mul_mont
.size	ecp_nistz384_to_mont,.-ecp_nistz384_to_mont
___
}

foreach (split("\n",$code)) {
	s/\`([^\`]*)\`/eval $1/ge;
	print $_,"\n";
}
close STDOUT or die "error closing STDOUT: $!";
