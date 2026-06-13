#! /usr/bin/env perl
# Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ECP_NISTZ384 - 64-bit, Montgomery-domain field arithmetic for NIST P-384,
# modelled on ecp_nistz256-x86_64.pl (Gueron-Krasnov).
#
# This first revision implements the field-arithmetic layer:
#   ecp_nistz384_add / sub / neg / mul_by_2 / mul_by_3 / div_by_2
#   ecp_nistz384_mul_mont (CIOS) / sqr_mont / from_mont / to_mont
#
# The Montgomery reduction is a generic CIOS reduction using
#   n0 = -p^-1 mod 2^64 = 0x0000000100000001
# rather than the P-256-style specialised reduction (P-384's prime does
# not have n0 == 1).  Correctness baseline; an ADX/MULX path and a
# specialised reduction are intended follow-ups.

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

# Detect whether the assembler understands MULX/ADCX/ADOX (BMI2+ADX).
if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
		=~ /GNU assembler version ([2-9]\.[0-9]+)/) {
	$addx = ($1>=2.23);
}
if (!$addx && `$ENV{CC} -v 2>&1` =~ /((?:clang|LLVM) version|.*based on LLVM) ([0-9]+)\.([0-9]+)/) {
	my $ver = $2 + $3/100.0;
	$addx = ($ver>=3.03);
}

$code.=<<___;
.text
.extern	OPENSSL_ia32cap_P

.section .rodata align=64
.align 64
# The P-384 field prime, little-endian limbs
.Lpoly:
.quad	0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff

# 2^768 mod P  (R^2, to convert into the Montgomery domain)
.LRR:
.quad	0xfffffffe00000001, 0x0000000200000000, 0xfffffffe00000000, 0x0000000200000000, 0x0000000000000001, 0x0000000000000000

# 2^384 mod P  (the Montgomery representation of 1)
.LONE_mont:
.quad	0xffffffff00000001, 0x00000000ffffffff, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000

# -P^-1 mod 2^64
.Lpoly_n0:
.quad	0x0000000100000001
.previous
___

################################################################################
# Simple field operations: add, sub, neg, mul_by_2, mul_by_3, div_by_2.
# These operate on 6-limb (384-bit) fully reduced inputs and produce fully
# reduced outputs.
{
my ($r_ptr,$a_ptr,$b_ptr)=("%rdi","%rsi","%rdx");
my @acc=map("%r$_",(8..13));		# the 6 result limbs
my $carry="%r14";
my $i;

# Conditional subtract of the modulus.
# On entry @acc holds a value in [0, 2*P) and $carry holds its top "carry"
# bit (0/1).  Spill @acc, subtract P, and cmovc back the un-subtracted value
# if the subtraction underflowed.  Result fully reduced in @acc.
sub cond_sub_poly {
    my $body="";
    for($i=0;$i<6;$i++) { $body.="\tmov\t$acc[$i], 8*$i(%rsp)\n"; }
    $body.="\tsub\t.Lpoly+8*0(%rip), $acc[0]\n";
    for($i=1;$i<6;$i++) { $body.="\tsbb\t.Lpoly+8*$i(%rip), $acc[$i]\n"; }
    $body.="\tsbb\t\$0, $carry\n";
    for($i=0;$i<6;$i++) { $body.="\tcmovc\t8*$i(%rsp), $acc[$i]\n"; }
    return $body;
}

$code.=<<___;
################################################################################
# void ecp_nistz384_mul_by_2(uint64_t res[6], const uint64_t a[6]);
.globl	ecp_nistz384_mul_by_2
.type	ecp_nistz384_mul_by_2,\@function,2
.align	32
ecp_nistz384_mul_by_2:
.cfi_startproc
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	sub	\$48, %rsp
.cfi_adjust_cfa_offset	48
.Lmul_by_2_body:
	xor	$carry, $carry
___
for($i=0;$i<6;$i++) { $code.="\tmov\t8*$i($a_ptr), $acc[$i]\n"; }
$code.="\tadd\t$acc[0], $acc[0]\n";
for($i=1;$i<6;$i++) { $code.="\tadc\t$acc[$i], $acc[$i]\n"; }
$code.="\tadc\t\$0, $carry\n";
$code.=&cond_sub_poly();
for($i=0;$i<6;$i++) { $code.="\tmov\t$acc[$i], 8*$i($r_ptr)\n"; }
$code.=<<___;
	add	\$48, %rsp
.cfi_adjust_cfa_offset	-48
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
.Lmul_by_2_epilogue:
	ret
.cfi_endproc
.size	ecp_nistz384_mul_by_2,.-ecp_nistz384_mul_by_2

################################################################################
# void ecp_nistz384_add(uint64_t res[6], const uint64_t a[6], const uint64_t b[6]);
.globl	ecp_nistz384_add
.type	ecp_nistz384_add,\@function,3
.align	32
ecp_nistz384_add:
.cfi_startproc
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	sub	\$48, %rsp
.cfi_adjust_cfa_offset	48
.Ladd_body:
	xor	$carry, $carry
___
for($i=0;$i<6;$i++) { $code.="\tmov\t8*$i($a_ptr), $acc[$i]\n"; }
$code.="\tadd\t8*0($b_ptr), $acc[0]\n";
for($i=1;$i<6;$i++) { $code.="\tadc\t8*$i($b_ptr), $acc[$i]\n"; }
$code.="\tadc\t\$0, $carry\n";
$code.=&cond_sub_poly();
for($i=0;$i<6;$i++) { $code.="\tmov\t$acc[$i], 8*$i($r_ptr)\n"; }
$code.=<<___;
	add	\$48, %rsp
.cfi_adjust_cfa_offset	-48
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
.Ladd_epilogue:
	ret
.cfi_endproc
.size	ecp_nistz384_add,.-ecp_nistz384_add

################################################################################
# void ecp_nistz384_mul_by_3(uint64_t res[6], const uint64_t a[6]);
# Computes (2*a mod P) then ((2a)+a mod P).
.globl	ecp_nistz384_mul_by_3
.type	ecp_nistz384_mul_by_3,\@function,2
.align	32
ecp_nistz384_mul_by_3:
.cfi_startproc
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	sub	\$48, %rsp
.cfi_adjust_cfa_offset	48
.Lmul_by_3_body:
	mov	$a_ptr, %r15		# stash a_ptr
	xor	$carry, $carry
___
for($i=0;$i<6;$i++) { $code.="\tmov\t8*$i($a_ptr), $acc[$i]\n"; }
$code.="\tadd\t$acc[0], $acc[0]\n";
for($i=1;$i<6;$i++) { $code.="\tadc\t$acc[$i], $acc[$i]\n"; }
$code.="\tadc\t\$0, $carry\n";
$code.=&cond_sub_poly();
# now @acc = 2a mod P; add original a
$code.="\txor\t$carry, $carry\n";
$code.="\tadd\t8*0(%r15), $acc[0]\n";
for($i=1;$i<6;$i++) { $code.="\tadc\t8*$i(%r15), $acc[$i]\n"; }
$code.="\tadc\t\$0, $carry\n";
$code.=&cond_sub_poly();
for($i=0;$i<6;$i++) { $code.="\tmov\t$acc[$i], 8*$i($r_ptr)\n"; }
$code.=<<___;
	add	\$48, %rsp
.cfi_adjust_cfa_offset	-48
	pop	%r15
.cfi_pop	%r15
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
.Lmul_by_3_epilogue:
	ret
.cfi_endproc
.size	ecp_nistz384_mul_by_3,.-ecp_nistz384_mul_by_3

################################################################################
# void ecp_nistz384_sub(uint64_t res[6], const uint64_t a[6], const uint64_t b[6]);
.globl	ecp_nistz384_sub
.type	ecp_nistz384_sub,\@function,3
.align	32
ecp_nistz384_sub:
.cfi_startproc
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	sub	\$48, %rsp
.cfi_adjust_cfa_offset	48
.Lsub_body:
	xor	$carry, $carry
___
for($i=0;$i<6;$i++) { $code.="\tmov\t8*$i($a_ptr), $acc[$i]\n"; }
$code.="\tsub\t8*0($b_ptr), $acc[0]\n";
for($i=1;$i<6;$i++) { $code.="\tsbb\t8*$i($b_ptr), $acc[$i]\n"; }
$code.="\tsbb\t\$0, $carry\n";			# $carry = 0 or -1 (borrow)
# spill diff, then add P back; keep diff if there was no borrow
for($i=0;$i<6;$i++) { $code.="\tmov\t$acc[$i], 8*$i(%rsp)\n"; }
$code.="\tadd\t.Lpoly+8*0(%rip), $acc[0]\n";
for($i=1;$i<6;$i++) { $code.="\tadc\t.Lpoly+8*$i(%rip), $acc[$i]\n"; }
$code.="\ttest\t$carry, $carry\n";
for($i=0;$i<6;$i++) { $code.="\tcmovz\t8*$i(%rsp), $acc[$i]\n"; }
for($i=0;$i<6;$i++) { $code.="\tmov\t$acc[$i], 8*$i($r_ptr)\n"; }
$code.=<<___;
	add	\$48, %rsp
.cfi_adjust_cfa_offset	-48
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
.Lsub_epilogue:
	ret
.cfi_endproc
.size	ecp_nistz384_sub,.-ecp_nistz384_sub

################################################################################
# void ecp_nistz384_neg(uint64_t res[6], const uint64_t a[6]);
.globl	ecp_nistz384_neg
.type	ecp_nistz384_neg,\@function,2
.align	32
ecp_nistz384_neg:
.cfi_startproc
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	sub	\$48, %rsp
.cfi_adjust_cfa_offset	48
.Lneg_body:
	xor	$carry, $carry
___
for($i=0;$i<6;$i++) { $code.="\txor\t$acc[$i], $acc[$i]\n"; }
$code.="\tsub\t8*0($a_ptr), $acc[0]\n";
for($i=1;$i<6;$i++) { $code.="\tsbb\t8*$i($a_ptr), $acc[$i]\n"; }
$code.="\tsbb\t\$0, $carry\n";
for($i=0;$i<6;$i++) { $code.="\tmov\t$acc[$i], 8*$i(%rsp)\n"; }
$code.="\tadd\t.Lpoly+8*0(%rip), $acc[0]\n";
for($i=1;$i<6;$i++) { $code.="\tadc\t.Lpoly+8*$i(%rip), $acc[$i]\n"; }
$code.="\ttest\t$carry, $carry\n";
for($i=0;$i<6;$i++) { $code.="\tcmovz\t8*$i(%rsp), $acc[$i]\n"; }
for($i=0;$i<6;$i++) { $code.="\tmov\t$acc[$i], 8*$i($r_ptr)\n"; }
$code.=<<___;
	add	\$48, %rsp
.cfi_adjust_cfa_offset	-48
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
.Lneg_epilogue:
	ret
.cfi_endproc
.size	ecp_nistz384_neg,.-ecp_nistz384_neg

################################################################################
# void ecp_nistz384_div_by_2(uint64_t res[6], const uint64_t a[6]);
# If a is odd, add P (making it even and < 2P), then shift right by 1.
.globl	ecp_nistz384_div_by_2
.type	ecp_nistz384_div_by_2,\@function,2
.align	32
ecp_nistz384_div_by_2:
.cfi_startproc
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
.Ldiv_by_2_body:
	xor	$carry, $carry
	xor	%r15, %r15		# a zero register
___
for($i=0;$i<6;$i++) { $code.="\tmov\t8*$i($a_ptr), $acc[$i]\n"; }
# Always compute a + P (carry into $carry); constant-time select afterwards.
$code.="\tadd\t.Lpoly+8*0(%rip), $acc[0]\n";
for($i=1;$i<6;$i++) { $code.="\tadc\t.Lpoly+8*$i(%rip), $acc[$i]\n"; }
$code.="\tadc\t\$0, $carry\n";
# If a was even, discard the +P by restoring the original limbs (and carry=0).
# The parity test must be the last flag-setting op before the cmovz chain.
$code.="\ttestb\t\$1, 8*0($a_ptr)\n";
for($i=0;$i<6;$i++) { $code.="\tcmovz\t8*$i($a_ptr), $acc[$i]\n"; }
$code.="\tcmovz\t%r15, $carry\n";
# now (carry:@acc) holds an even value; shift right by 1
for($i=0;$i<5;$i++) {
    $code.="\tshrd\t\$1, $acc[$i+1], $acc[$i]\n";
}
$code.="\tshrd\t\$1, $carry, $acc[5]\n";
for($i=0;$i<6;$i++) { $code.="\tmov\t$acc[$i], 8*$i($r_ptr)\n"; }
$code.=<<___;
	pop	%r15
.cfi_pop	%r15
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
.Ldiv_by_2_epilogue:
	ret
.cfi_endproc
.size	ecp_nistz384_div_by_2,.-ecp_nistz384_div_by_2
___
}

################################################################################
# Montgomery multiplication (CIOS) and friends.
#
# void ecp_nistz384_mul_mont(uint64_t res[6], const uint64_t a[6],
#                            const uint64_t b[6]);
# res = a*b*2^-384 mod P
{
my ($r_ptr,$a_ptr,$b_ptr)=("%rdi","%rsi","%rbx");
my @T=map("%r$_",(8..15));		# 8-word accumulator t0..t7 (legacy path)
my @M=map("%r$_",(8..15));		# 8-word accumulator (MULX/ADX path)
my $m="%rcx";
my $cy="%rbp";
my $i;					# for main-body emit loops (shadowed in cios_round)

# emit the CIOS body for one outer multiplier word at b[$bi].
# @T is the current (rotating) accumulator register list.
sub cios_round {
    my $bi=shift;
    my $body="";
    my $i;
    # ---- phase 1: T += a * b[bi]
    $body.="\txor\t$cy, $cy\n";
    for($i=0;$i<6;$i++) {
	$body.="\tmov\t8*$i($a_ptr), %rax\n";
	$body.="\tmulq\t8*$bi($b_ptr)\n";	# rdx:rax = a[i]*b[bi]
	$body.="\tadd\t$cy, %rax\n";
	$body.="\tadc\t\$0, %rdx\n";
	$body.="\tadd\t%rax, $T[$i]\n";
	$body.="\tadc\t\$0, %rdx\n";
	$body.="\tmov\t%rdx, $cy\n";
    }
    $body.="\tadd\t$cy, $T[6]\n";
    $body.="\tadc\t\$0, $T[7]\n";
    # ---- phase 2: m = T[0]*n0; T += m*P; T[0] becomes 0
    $body.="\tmov\t$T[0], $m\n";
    $body.="\timulq\t.Lpoly_n0(%rip), $m\n";
    $body.="\txor\t$cy, $cy\n";
    # j=0: discard low word (it becomes 0)
    $body.="\tmov\t.Lpoly+8*0(%rip), %rax\n";
    $body.="\tmulq\t$m\n";
    $body.="\tadd\t$T[0], %rax\n";		# low word -> 0, carry out
    $body.="\tadc\t\$0, %rdx\n";
    $body.="\tmov\t%rdx, $cy\n";
    $body.="\txor\t$T[0], $T[0]\n";		# logical value is now 0; becomes new T[7]
    for($i=1;$i<6;$i++) {
	$body.="\tmov\t.Lpoly+8*$i(%rip), %rax\n";
	$body.="\tmulq\t$m\n";
	$body.="\tadd\t$cy, %rax\n";
	$body.="\tadc\t\$0, %rdx\n";
	$body.="\tadd\t%rax, $T[$i]\n";
	$body.="\tadc\t\$0, %rdx\n";
	$body.="\tmov\t%rdx, $cy\n";
    }
    $body.="\tadd\t$cy, $T[6]\n";
    $body.="\tadc\t\$0, $T[7]\n";
    # rotate: drop T[0] (==0), it becomes new T[7]
    push(@T, shift(@T));
    return $body;
}

# Emit the final conditional subtract of P and store the 6-limb result.
# @A is the rotating accumulator: A[0..5] = value, A[6] = top overflow word.
# Scratch %rax,%rdx,%rcx,%rbx,%rsi,%rbp are all free at this point.
sub cond_sub_store {
    my @A = @_;
    my $b = "\tmov\t(%rsp), $r_ptr\n";
    $b .= "\tmov\t$A[0], %rax\n\tmov\t$A[1], %rdx\n\tmov\t$A[2], %rcx\n";
    $b .= "\tmov\t$A[3], %rbx\n\tmov\t$A[4], %rsi\n\tmov\t$A[5], %rbp\n";
    $b .= "\tsub\t.Lpoly+8*0(%rip), $A[0]\n";
    $b .= "\tsbb\t.Lpoly+8*$_(%rip), $A[$_]\n" for (1..5);
    $b .= "\tsbb\t\$0, $A[6]\n";
    $b .= "\tcmovc\t%rax, $A[0]\n\tcmovc\t%rdx, $A[1]\n\tcmovc\t%rcx, $A[2]\n";
    $b .= "\tcmovc\t%rbx, $A[3]\n\tcmovc\t%rsi, $A[4]\n\tcmovc\t%rbp, $A[5]\n";
    $b .= "\tmov\t$A[$_], 8*$_($r_ptr)\n" for (0..5);
    return $b;
}

# MULX/ADX (BMI2+ADX) Montgomery CIOS round for multiplier word b[$bi].
# Generalises ecp_nistz256's ord_mul_montx to 6 limbs with a rotating
# 8-register accumulator @M.  poly and n0 are read RIP-relative.
# Invariant: CF=OF=0 on entry and on exit (the trailing plain "adc $0" resets
# both, relying on the tiny top word not overflowing).
{
my ($mt0,$mt1)=("%rcx","%rbp");
sub montx_round {
    my $bi=shift;
    my $b="\tmov\t8*$bi($b_ptr), %rdx\n";
    # multiply: M += a * b[bi]
    for my $j (0..5) {
	$b .= "\tmulx\t8*$j($a_ptr), $mt0, $mt1\n";
	if ($j==5) {	# interleave m = M[0]*n0 before consuming the last product
	    $b .= "\t mov\t$M[0], %rdx\n\t mulx\t.Lpoly_n0(%rip), %rdx, %rax\n";
	}
	$b .= "\tadcx\t$mt0, $M[$j]\n\tadox\t$mt1, $M[$j+1]\n";
    }
    $b .= "\tadcx\t$M[7], $M[6]\n";	# M[7]==0: fold CF chain into M[6]
    $b .= "\tadox\t$M[7], $M[7]\n";	# fold OF chain into M[7]
    $b .= "\tadc\t\$0, $M[7]\n";	# resets CF=OF=0
    # reduction: M += m * poly, low word -> 0 (rdx holds m)
    for my $j (0..5) {
	$b .= "\tmulx\t.Lpoly+8*$j(%rip), $mt0, $mt1\n";
	$b .= "\tadcx\t$mt0, $M[$j]\n\tadox\t$mt1, $M[$j+1]\n";
    }
    $b .= "\tadcx\t$M[0], $M[6]\n";	# M[0]==0: fold CF chain into M[6]
    $b .= "\tadox\t$M[0], $M[7]\n";	# fold OF chain into M[7]
    $b .= "\tadc\t\$0, $M[7]\n";	# resets CF=OF=0
    push(@M, shift(@M));		# rotate: zeroed M[0] becomes new top
    return $b;
}
}

$code.=<<___;
################################################################################
.globl	ecp_nistz384_mul_mont
.type	ecp_nistz384_mul_mont,\@function,3
.align	32
ecp_nistz384_mul_mont:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	sub	\$8, %rsp		# spill slot for r_ptr (keep 16-aligned: 6 pushes => aligned, +8 => save r_ptr)
.cfi_adjust_cfa_offset	8
.Lmul_mont_body:
	mov	$r_ptr, (%rsp)		# stash result pointer
	mov	%rdx, $b_ptr		# b_ptr -> %rbx
___
if ($addx) {
$code.=<<___;
	mov	OPENSSL_ia32cap_P+8(%rip), %ecx
	and	\$0x80100, %ecx		# BMI2 (MULX) + ADX
	cmp	\$0x80100, %ecx
	je	.Lmul_montx
___
}
# ---- legacy (mul/adc) path ----
# zero the 8-word accumulator
for($i=8;$i<=15;$i++) { $code.="\txor\t%r$i, %r$i\n"; }
for($i=0;$i<6;$i++) { $code.=&cios_round($i); }
# after 6 rounds @T[0..5] hold the result, @T[6] is the top "carry" word.
$code.=&cond_sub_store(@T);
$code.="\tjmp\t.Lmul_done\n";

# ---- MULX/ADX path ----
if ($addx) {
$code.=".Lmul_montx:\n";
for($i=8;$i<=15;$i++) { $code.="\txor\t%r$i, %r$i\n"; }	# zero accumulator, clear CF/OF
for($i=0;$i<6;$i++) { $code.=&montx_round($i); }
$code.=&cond_sub_store(@M);
}

$code.=".Lmul_done:\n";
$code.=<<___;
	add	\$8, %rsp
.cfi_adjust_cfa_offset	-8
	pop	%r15
.cfi_pop	%r15
	pop	%r14
.cfi_pop	%r14
	pop	%r13
.cfi_pop	%r13
	pop	%r12
.cfi_pop	%r12
	pop	%rbp
.cfi_pop	%rbp
	pop	%rbx
.cfi_pop	%rbx
.Lmul_mont_epilogue:
	ret
.cfi_endproc
.size	ecp_nistz384_mul_mont,.-ecp_nistz384_mul_mont

################################################################################
# void ecp_nistz384_sqr_mont(uint64_t res[6], const uint64_t a[6]);
# Baseline: route through mul_mont(res, a, a).
.globl	ecp_nistz384_sqr_mont
.type	ecp_nistz384_sqr_mont,\@function,2
.align	32
ecp_nistz384_sqr_mont:
.cfi_startproc
	mov	$a_ptr, %rdx		# b = a
	jmp	ecp_nistz384_mul_mont
.cfi_endproc
.size	ecp_nistz384_sqr_mont,.-ecp_nistz384_sqr_mont

################################################################################
# void ecp_nistz384_from_mont(uint64_t res[6], const uint64_t in[6]);
# res = in * 1 * 2^-384 mod P   (i.e. Montgomery reduction of in)
.globl	ecp_nistz384_from_mont
.type	ecp_nistz384_from_mont,\@function,2
.align	32
ecp_nistz384_from_mont:
.cfi_startproc
	lea	.LONE(%rip), %rdx
	jmp	ecp_nistz384_mul_mont
.cfi_endproc
.size	ecp_nistz384_from_mont,.-ecp_nistz384_from_mont

################################################################################
# void ecp_nistz384_to_mont(uint64_t res[6], const uint64_t in[6]);
# res = in * R^2 * 2^-384 = in * 2^384 mod P
.globl	ecp_nistz384_to_mont
.type	ecp_nistz384_to_mont,\@function,2
.align	32
ecp_nistz384_to_mont:
.cfi_startproc
	lea	.LRR(%rip), %rdx
	jmp	ecp_nistz384_mul_mont
.cfi_endproc
.size	ecp_nistz384_to_mont,.-ecp_nistz384_to_mont
___
}

$code.=<<___;
.section .rodata align=64
.align 64
# plain integer 1, for from_mont
.LONE:
.quad	0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
.previous
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT or die "error closing STDOUT: $!";
