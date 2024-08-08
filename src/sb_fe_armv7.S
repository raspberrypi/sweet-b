/** @file sb_fe_armv7.s
 *  @brief constant time prime-field element operations, ARMv7 w/DSP source
 */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file is part of Sweet B, a safe, compact, embeddable library for
 * elliptic curve cryptography.
 *
 * https://github.com/westerndigitalcorporation/sweet-b
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* When reading this source, refer to sb_fe.c for corresponding C definitions
 * and to understand the algorithms being implemented */

/* All of the routines here are fully unrolled. .rept / .endr surrounds a
 * block of unrolled code, and .set is used to maintain a static iterator
 * across unrolled blocks.
 */
#if SB_FE_ASM

#if FEATURE_CANARIES
#include "bootrom.h"
#include "hardware/regs/sha256.h"
#endif

#include "sb_sw_curve_support.h"

#if defined(SB_OVERRIDE_MEMSET)
    #define memset SB_OVERRIDE_MEMSET
#endif
#if defined(SB_OVERRIDE_MEMCPY)
    #define memcpy SB_OVERRIDE_MEMCPY
#endif

.extern memset
.extern memcpy

.cpu cortex-m33
.syntax unified
.section .text.sb_fe_interp_asm, "ax"
.thumb

// A simple interpreter for operations on field elements. We can only handle operations
// that use operands in the "context", of which there are 16 (see offsets in sb_sw_lib.c);
// that covers most of the cases, fortunately. Some operations also need a prime:
// we can use either P or N as stored in the "curve".
//
// To start, call sb_fe_interp(context,curve). Then half-word opcodes following this bl
// instruction cause calls to various sb_fe_* instructions as listed below. After
// a STOP opcode we return to normal execution at the Thumb instruction immediately after it.
//
// Opcode format:
//
// +---------+----+-------------+-------------+-------------+
// |15 14 13 | 12 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
// +---------+----+-------------+-------------+-------------+
// | o  o  o | pn |  m  m  m  m |  n  n  n  n |  d  d  d  d | OP D, N, M, PN
// +---------+----+-------------+-------------+-------------+
//
//   ooo
//   000  sb_fe_mod_add(d,n,m,pn)
//   001  sb_fe_mod_sub(d,n,m,pn)
//   010  sb_fe_mont_mult(d,n,m,pn)
//   011  sb_fe_mov(d,n)
//   100  sb_fe_mod_reduce_prime_in_r3(d,pn)
//   101  sb_fe_mont_convert_prime_in_r3(d,n,pn)
//   110  sb_fe_mod_inv_r(d,m,n,pn)
//
// +------------+-------------------------+-------------+
// |15 14 13 12 | 11 10  9  8  7  6  5  4 |  3  2  1  0 |
// +------------+-------------------------+-------------+
// | 1  1  1  0 |  0  i  i  i  i  i  i  i |  d  d  d  d | MOV_SREL
// +------------+-------------------------+-------------+
//
// sb_fe_mov_srel(d,i): copy from a field element in the curve structure at offset i words to context member d
//
// +------------+-------------------------+-------------+
// |15 14 13 12 | 11 10  9  8  7  6  5  4 |  3  2  1  0 |
// +------------+-------------------------+-------------+
// | 1  1  1  0 |  1  0  0  0  0  i  i  i |  d  d  d  d | MOV_CONST
// +------------+-------------------------+-------------+
//
// sb_fe_mov_const(d,i): write a small constant i to context member d
//
// +------------------------------------------------+
// |15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0 |
// +------------------------------------------------+
// | 1  1  1  1  1  1  1  1  1  1  1  1  1  1  1  1 | STOP
// +------------------------------------------------+

// Opcode 0xFFFF is the STOP instruction.
//
// Inspired by RST 28H in the ZX81 and ZX Spectrum ROMs.

.extern SB_CURVE_P256
.extern SB_CURVE_SECP256K1

.global sb_fe_interp
.type sb_fe_interp, %function
.thumb_func
sb_fe_interp:
#if !FEATURE_CANARIES
 push {r4,r5,r6,r7}
#else
 rcp_canary_get_nodelay r3, CTAG_SB_FE_INTERP
 push {r3,r4,r5,r6,r7}
#endif
 mov r4,r0 // c: context
#ifdef SB_SW_UNIQUE_CURVE_SUPPORTED
 ldr r5,=#SB_SW_UNIQUE_CURVE_SUPPORTED
#else
 mov r5,r1 // s: curve
#endif
 sub r6,lr,#1
10:
 ldrsh r7,[r6],#2
 adds r3,r7,#1
 bne 1f
 adds r3,r6,#1 @ done? fix return address
#if !FEATURE_CANARIES
 pop {r4,r5,r6,r7}
#else
 pop {r2,r4,r5,r6,r7}
 rcp_canary_check_nodelay r2, CTAG_SB_FE_INTERP
#endif
 bx r3

1:
 ubfx r3,r7,#12,#1
 ldr r3,[r5,r3,lsl#2]
 ubfx r2,r7,#8,#4
 add r2,r4,r2,lsl#5
 ubfx r1,r7,#4,#4
 add r1,r4,r1,lsl#5
 ubfx r0,r7,#0,#4
 add r0,r4,r0,lsl#5
 ubfx r12,r7,#13,#3
 adr lr,jtab
#if !USE_16BIT_POINTERS
 ldr lr,[lr,r12,lsl#2]
#else
 ldrh lr,[lr,r12,lsl#1]
#endif
#if FEATURE_CANARIES
 push {r3}
 ldr r3, [sp, #4]
 rcp_canary_check_nodelay r3, CTAG_SB_FE_INTERP
 pop {r3}
#endif
 blx lr
 b 10b
.p2align 2
jtab:
#if !USE_16BIT_POINTERS
.word sb_fe_mod_add
.word sb_fe_mod_sub
.word sb_fe_mont_mult
.word sb_fe_mov
.word sb_fe_mod_reduce_prime_in_r3
.word sb_fe_mont_convert_prime_in_r3
.word sb_fe_mod_inv_r
.word sb_fe_mov_srel
#else
.hword sb_fe_mod_add + 1
.hword sb_fe_mod_sub + 1
.hword sb_fe_mont_mult + 1
.hword sb_fe_mov + 1
.hword sb_fe_mod_reduce_prime_in_r3 + 1
.hword sb_fe_mont_convert_prime_in_r3 + 1
.hword sb_fe_mod_inv_r + 1
.hword sb_fe_mov_srel + 1
#endif

// note one section for all the rest as they all seem to be used
.section .text.sb_asm, "ax"
.thumb

// load small constant
sb_fe_sc0:
 ubfx r1,r7,#4,#3 @ get the constant
 stmia r0!,{r1}
 movs r2,#28
 movs r1,#0
 b memset

.type sb_fe_mov_srel, %function
.thumb_func
sb_fe_mov_srel:
 sbfx r1,r7,#4,#8
 lsls r1,#2
 bmi sb_fe_sc0 @ negative if top bit of i field is set
 adds r1,r1,r5
// else fall through

.global sb_fe_mov
.type  sb_fe_mov, %function
.thumb_func
sb_fe_mov:
  push {r3,r4,lr}   // save r3 so we can be called from sb_fe_mod_inv_r
#if FEATURE_CANARIES
  rcp_canary_get_nodelay r4, CTAG_SB_FE_MOV
#endif
  movs r2,#32
  bl memcpy
#if FEATURE_CANARIES
  // we'll piggy back on previous canary
  rcp_canary_check_nodelay r4, CTAG_SB_FE_MOV
#endif
  pop {r3,r4,pc}

.global sb_fe_mov_pair
.type  sb_fe_mov_pair, %function
.thumb_func
sb_fe_mov_pair:
 movs r2,#64
 b memcpy

.type sb_fe_mont_convert_prime_in_r3, %function
.thumb_func
sb_fe_mont_convert_prime_in_r3:
 movs r2,r3
 .global sb_fe_mont_convert
.type sb_fe_mont_convert, %function
.thumb_func
sb_fe_mont_convert:
	mov	r3, r2
	adds	r2, r2, #100    // this is offsetof(sb_prime_field_t,r2_mod_p), static_assert():ed in sb_sw_lib.c
	b	sb_fe_mont_mult

/* Returns 1 if the bit is set, 0 otherwise
sb_word_t
sb_fe_test_bit(const sb_fe_t a[static const 1], const sb_bitcount_t bit)

r0 = a, r1 = bit
return value in r0
*/

.weak sb_fe_test_bit
.type  sb_fe_test_bit, %function
.thumb_func

/*
sb_fe_test_bit(const sb_fe_t a[static const 1], const sb_bitcount_t bit)
 */
// preserves r1,r3
sb_fe_test_bit:
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_SB_FE_TEST_BIT
#endif
    lsrs r2, r1, #3     /* get which byte */
    ldrb r0, [r0, r2]   /* load byte */
    and r2, r1, #0x7    /* get which bit in word */
    lsrs r0, r0, r2     /* move bit to LSB */
    and r0, r0, #1      /* isolate LSB */
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_SB_FE_TEST_BIT
#endif
    bx lr               /* return */

.size sb_fe_test_bit, .-sb_fe_test_bit

sb_fe_sub_cmp:
 mvns r7,#0
 b sb_fe_add_sub_cmp
sb_fe_add:
 movs r7,#0
@ r7=0: add, 0xffffffff: subtract/compare
@ r0=dest, 0 for compare
@ r1,r2=operands; r2=NULL for zero operand
@ carry out in r2, NE flag in r6b31
@ preserves r3
sb_fe_add_sub_cmp:
 asrs r7,r7,#1 // preserve r7, clear C for add/set for subtract
sb_fe_adc_sbc:
#if FEATURE_CANARIES
  rcp_canary_get_nodelay ip, CTAG_SB_FE_ADC_SBC
#endif
 movs r6,#0
1:
 ldr  r4, [r1, r6,lsl#2]
 movs r5,#0 // possibly zero second argument
 ands r2,r2,r2
 itt ne
 ldrne r5, [r2, r6,lsl#2]
 eorne r5,r5,r7 @ negate for subtract/compare
 add  r6, r6, #1     /* Doesn't change carry but 32bits */
 adcs r4, r4, r5
 it ne
 orrne r6,r6,#0x80000000 // set b31 of r6 for nonzero result
 ands r0,r0,r0 // destination==NULL?
 it ne
 stmiane r0!,{r4}
 tst  r6, #8        /* Doesn't change carry but 32bits */
 beq 1b
 movs r2, #0         /* r2 = 0 */
 adcs r2, r2, r2     /* r2 = 0 + 0 + carry */
#if FEATURE_CANARIES
  rcp_canary_check_nodelay ip, CTAG_SB_FE_ADC_SBC
#endif
 bx lr

/* Given quasi-reduced left and right, produce quasi-reduced left + right.

void
sb_fe_mod_add(sb_fe_t dest[static const 1], const sb_fe_t left[static const 1],
              const sb_fe_t right[static const 1],
              const sb_prime_field_t p[static const 1]) */
// preserves r0,r1,r3
.weak sb_fe_mod_add
.type  sb_fe_mod_add, %function
.thumb_func
sb_fe_mod_add:
    adds r7,#0 @ C=0
.thumb_func
sb_fe_mod_adc:
    push {r0, r4, r5, r6, r7, lr}
    movs r7,#0
    bl sb_fe_adc_sbc

    /* pass r0, r3 unchanged on */
    pop { r0, r4, r5, r6, r7, lr}
    b sb_fe_lt_cond_sub_p

/* Field element subtraction without incoming borrow. */
/*sb_word_t sb_fe_sub(sb_fe_t dest[static const 1],
                    const sb_fe_t left[static const 1],
                    const sb_fe_t right[static const 1])
*/
.weak sb_fe_sub
.type sb_fe_sub, %function
.thumb_func
sb_fe_sub:
    subs r3, r3, r3     /* set carry flag and zero r3 */

    /* fall into sb_fe_sub_borrow */

/* Field element subtraction with incoming borrow

sb_word_t sb_fe_sub_borrow(sb_fe_t dest[static const 1],
                           const sb_fe_t left[static const 1],
                           const sb_fe_t right[static const 1],
                           sb_word_t borrow)

r0 = dest, r1 = left, r2 = right, r3 = borrow
return value in r0
*/

sb_fe_sub_borrow:
    /* Entry must have the carry flag set correctly*/
    push {r4, r5, r6, r7, lr}
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_SB_FE_SUB_BORROW
#endif
    mvns r7,#0
    bl sb_fe_adc_sbc
    mov r0,r2 // not-borrow out is carry
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_SB_FE_SUB_BORROW
#endif
    pop {r4, r5, r6, r7, pc}

.size sb_fe_sub_borrow, .-sb_fe_sub_borrow

.weak sb_fe_cmp
.type sb_fe_cmp, %function
.thumb_func
/* Field element compare

sb_word_t sb_fe_cmp(const sb_fe_t left[static 1],
                    const sb_fe_t right[static 1])

r0 = left, r1 = right
return value in r0; does NOT modify the value of r1
r0=-1: LO; r0=0: EQ; r0=1: HI; flags not set accordingly
*/

sb_fe_cmp:
#if !FEATURE_CANARIES
    push {r1, r4, r5, r6, r7, lr}
#else
    rcp_canary_get_nodelay r3, CTAG_SB_FE_CMP
    push {r1, r3, r4, r5, r6, r7, lr}
#endif
    movs r2,r1
    movs r1,r0
    movs r0,#0
    bl sb_fe_sub_cmp
#if BOOTROM_HARDENING
    str r6, [sp, #0]         /* r1 will be (on pop) loop counter with top bit set on non zero */
#endif
    lsrs r0,r6,#31 // equal? return 0
    beq 1f
    adds r0,r2,r2 // return ±1
    subs r0,#1
1:
#if !FEATURE_CANARIES
    pop {r1, r4, r5, r6, r7, pc}
#else
    ldr r3, [sp, #4]
    rcp_canary_check_nodelay r3, CTAG_SB_FE_CMP
    pop {r1, r3, r4, r5, r6, r7, pc}
#endif

.size sb_fe_cmp, .-sb_fe_cmp

#if SB_SW_SECP256K1_SUPPORT
.set sb_fe_one,SB_CURVE_SECP256K1_P+0x22*4
#else
sb_fe_one:
 .word 1,0,0,0,0,0,0,0
#endif
/*
// Quasi-reduce the input, under the assumption that 2 * p > 2^SB_FE_BITS or
// that the input < 2 * p. The input range is [0, 2^SB_FE_BITS - 1].
void sb_fe_mod_reduce(sb_fe_t dest[static const restrict 1],
                      const sb_prime_field_t p[static const restrict 1])

 */
.type sb_fe_mod_reduce_prime_in_r3, %function
.thumb_func
sb_fe_mod_reduce_prime_in_r3:
 movs r1,r3
.weak sb_fe_mod_reduce
.type  sb_fe_mod_reduce, %function
.thumb_func
sb_fe_mod_reduce:
    push {r3, r4, r5, r6, r7, lr}

    mov r3, r1
    mov	r1, r0  /* dest */
    subs r2,r2,r2 // r2=0, C=1

    bl sb_fe_mod_adc // preserves r0,r1,r3

#if !BOOTROM_BUILD
    ldr.n r2, =#sb_fe_one
#else
    movw r2, P16(sb_fe_one)
#endif
    // tail call
    b sb_fe_mod_sub_nostack

/*
void sb_fe_mod_sub(sb_fe_t dest[static const 1],
                   const sb_fe_t left[static const 1],
                   const sb_fe_t right[static const 1],
                   const sb_prime_field_t p[static const 1])
 */
// preserves r3
.weak sb_fe_mod_sub
.type sb_fe_mod_sub, %function

.thumb_func

sb_fe_mod_sub:
    push   { r3, r4, r5, r6, r7, lr}
sb_fe_mod_sub_nostack:
    mov	    r4, r0      /* dest */
    mov	    r5, r3      /* p */
    adds r3,#0 @ C=0 so we calculate x-y-1

    bl      sb_fe_sub_borrow
#define STEPTAG_SB_FE_MOD_SUB_NOSTACK (STEPTAG_SB_FE_SUB_BORROW + 1)

    /* fall into sb_fe_cond_add_p_1 ( optimised) */
/*
 * This helper adds 1 or (p + 1), depending on c.
 *
 * void sb_fe_cond_add_p_1(sb_fe_t dest[static const restrict 1],
 *                         sb_word_t c,
 *                         const sb_fe_t p[static const restrict 1])
 *
 * r4 is dest, r0 is c, r5 is p
 */
//sb_fe_cond_add_p_1:

  subs r1,r0,#1 // 0 for no borrow, 0xffffffff for borrow
  ands r2,r5,r1 // p or 0
  movs r0,r4 // dest
  movs r1,r4
  subs r7,r7,r7 // set up for add with carry set so we add 1 or p+1
  bl sb_fe_adc_sbc

#if FEATURE_CANARIES
    // piggyback on call to sb_fe_adc_sbc
    rcp_count_check_nodelay STEPTAG_SB_FE_MOD_SUB_NOSTACK
#endif
    pop {r3, r4, r5, r6, r7, pc}

//.size sb_fe_cond_add_p_1, .-sb_fe_cond_add_p_1



/*
// Montgomery squaring: dest = left * left * R^-1 mod p
void sb_fe_mont_square(sb_fe_t dest[static const restrict 1],
                       const sb_fe_t left[static const 1],
                       const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(dest, left, left, p);
}

 */
/*
 * Montgomery multiplication
 *
 * void sb_fe_mont_mult(sb_fe_t A[static const restrict 1],
 *                      const sb_fe_t x[static const 1],
 *                      const sb_fe_t y[static const 1],
 *                      const sb_prime_field_t p[static const 1])
 *
 * r0 is A, r1 is x, r2 is y, r3 is p
 * p[32] is p->mp
 */

     /*
     * HAC gives the algorithm for Montgomery multiplication as follows:
     *
     * 1: A := 0
     * 2: For i from 0 to (n - 1) do:
     * 2.1: u_i := (a_0 + x_i * y_0) * m' mod b
     * 2.2:   A := (A + x_i * y + u_i * m) / b
     * 3: If A >= m then A := A - m
     * 4: Return A
     *
     * The algorithm is implemented below as follows:
     *
     * 1. carry := 0
     * 2. For i from 0 to (n - 1) do:
     * 2.1: c := 0; c2 := 0
     * 2.2: For j from 0 to (n - 1) by 2 do:
     * 2.2.2: If i == 0 then:
     * 2.2.2.1: (c, t) := x_i * y_j + c; (c, t2) := x_i * y_(j + 1) + c
     * 2.2.2.2: else: (c, t) := a_0 + x_i * y_j + c;
     *                (c, t2) := a_1 + x_i * y_(j + 1) + c
     * 2.2.3: If j == 0 then: u_i = t * m' mod b
     * 2.2.4: (c2, t) := t + u_i * m_j + c2
     * 2.2.5: If j > 0 then: A[j - 1] = t
     * 2.2.6: (c2, t2) := t2 + u_i * m_(j + 1) + c2
     * 2.2.7: A[j] = t2
     * 2.3: A[n - 1] = (c + c2 + carry); set carry
     * 3: If A > m or carry == 1 then A := A - m
     * 4: Return A
     *
     * Notably:
     * 1. There is no explicit A := 0 step; rather, on the first iteration
     *    zero values are loaded into registers instead of loading from A.
     * 2. u_i is computed when A + x_i * y_0 is computed as part of computing
     *    A + x_i * y + u_i * m.
     * 3. The division by b is handled by an implicit word shift in storing
     *    results back to A; the lowest word is not stored, and subsequent
     *    words are stored at an offset. The highest bit in A is kept in the
     *    carry flag.
     * 4. The implementation is fully unrolled, so all comparisons to i and j
     *    take place at macro-assembly time, not at runtime.
     *
     */


.weak sb_fe_mont_square
.type sb_fe_mont_square, %function
.thumb_func
.weak sb_fe_mont_mult
.type sb_fe_mont_mult, %function
.thumb_func

sb_fe_mont_square:
    mov     r3, r2
    mov     r2, r1

    /* fall into sb_fe_mont_mult */

sb_fe_mont_mult:
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_SB_FE_MONT_MULT
#endif
    push    {r4, r5, r6, r7, r8, r9, sl, lr}

    mov	    ip, r2      /* y */

    movs	r7, #0      /* outer loop counter i */
    mov 	lr, r7      /* main carry flag */

/*registers
    r0 A const
    r1 x const
    r2 inner loop counter j
    r3 p ( const)
    r4 reg for mul
    r5 reg for mul
    r6 reg for mul
    r7 outer loop counter i
    r8 c1 carry flag
    r9 r9= p[8]*A[0]
    r10 (sl) c2
    r11(fp)  not used ( not stacked)
    r12(ip) y
    lr overall carry
    */

_sb_fe_mont_mult_outerloop:

    movs    r2, #0          /* inner loop counter j */
    mov	    r8, r2          /* c1  carry */
    mov     sl, r2          /* c2  carry*/

_sb_fe_mont_mult_innerloop:
    ldr	    r4, [r1, r7]    /* x[i] */
    movs    r5, r7          /* check if  */
    beq     _sb_fe_mont_mult_skipload
    ldr 	r5, [r0, r2]    /*A[j] */
_sb_fe_mont_mult_skipload:
    ldr	    r6, [ip, r2]    /*y[j] */
    umaal	r5, r8, r4, r6

    cbnz    r2, _sb_fe_mont_mult_skip_mul
    /* only do this for j=0 */
    ldr	    r4, [r3, #32]   /* p[8] */
    mul 	r9, r5, r4      /*r9= p[8]*A[0]   */
_sb_fe_mont_mult_skip_mul:

    ldr 	r6, [r3, r2]    /*p[j] */
    umaal   r5, sl, r9, r6

    cbz     r2, _sb_fe_mont_mult_skipstore
    subs    r2, r2, #4
    str 	r5, [r0, r2]    /*A[j] += r9*p[j]  */
    adds    r2, r2, #4
_sb_fe_mont_mult_skipstore:
    adds	r2, r2, #4      /* inner loop counter j */
    cmp	    r2, #32
    bne 	_sb_fe_mont_mult_innerloop

    movs    r6, #1

    umaal   sl, lr, r6, r8

    adds	r7, r7, #4      /* loop counter i increment */

    cmp	    r7, #32
    str	    sl, [r0, #28]   /*A[7]= A[] + carry + p[j] */
    bne 	_sb_fe_mont_mult_outerloop

    mov     r2, lr

#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_SB_FE_MONT_MULT
#endif
    pop     {r4, r5, r6, r7, r8, r9, sl, lr}
    // r0 =A and r1= x r3 = p preserved here
    // r2 = carry
sb_fe_lt_cond_sub_p:
    push    {r0, r1, r3, r4, r5, r6, r7, lr}
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_SB_FE_LT_COND_SUB_P
#endif
    mov	    r1, r0
    mov	    r0, r3
    /*  r0 = p
        r1 = A
        r2 = carry
        r3 = p */

    push    {r1,r2,r3}
    /*  r1 = A
        r0 = p*/

    bl	    sb_fe_cmp
    lsrs    r4,r0,#31 // 1 if LT

    pop     {r0,r1,r2}

// Now: r0 = A
//      r1 = (carry | (p < A))
//      r2 = p
    orrs    r1, r1, r4  /* ip = (ip | r0) == (carry | (p < A)) */

   /* fall into sb_fe_cond_sub_p */
.size sb_fe_mont_mult, .-sb_fe_mont_mult
/*
 * This helper routine subtracts p if c is 1;
 * void sb_fe_cond_sub_p(sb_fe_t dest[static const restrict 1],
 *                       sb_word_t c,
 *                       const sb_fe_t p[static const restrict 1])
 *
 * r0 is dest, r1 is c, r2 is p
 */
    cbz r1, _sb_fe_cond_sub_p_exit

    movs r1,r0
    bl sb_fe_sub_cmp

_sb_fe_cond_sub_p_exit:
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_SB_FE_LT_COND_SUB_P
#endif
    pop {r0, r1, r3, r4, r5, r6, r7, pc}


.weak sb_fe_mod_inv_r
.type sb_fe_mod_inv_r, %function
.thumb_func

/*
// See sb_prime_field_t in sb_fe.h for more comments on modular inversion.
void sb_fe_mod_inv_r(sb_fe_t dest[static const restrict 1],
                     sb_fe_t t2[static const restrict 1],
                     sb_fe_t t3[static const restrict 1],
                     const sb_prime_field_t p[static const restrict 1])
{ */
sb_fe_mod_inv_r:
    push    {r0, r1, r2, r4, r5, r6, r7, r8, lr}
#if FEATURE_CANARIES
    rcp_canary_get_nodelay r8, CTAG_SB_FE_MOD_INV_R
#endif

//  dest( x ) at [sp,#0]
//  t2        at [sp,#4]
//  t3        at [sp,#8]

    movs	r5, #36 /* ->p_minus_two_f1 */
   //movs    r5, #68 /* second time round: ->p_minus_two_f2 */

_sb_fe_mod_expt_loop:
    ldr r0,[sp,#4] /* *t2= */
    add     r1, r3, #132 /* *p->r_mod_p */
    bl      sb_fe_mov
    movs	r7, #0
    movs r4,#255  // was: ldr     r4, [r3, #164], where 164 is the offset of the "bits" field in sb_prime_field_t
_sb_fe_mod_expt_r_loop:
    mov	    r1, r4 /* i */
    adds    r0, r3, r5 /* e */
    bl	    sb_fe_test_bit
    cbnz    r7, _sb_fe_mod_expt_r_do_square
    cbz	    r0, _sb_fe_mod_expt_r_continue

_sb_fe_mod_expt_r_do_square:
    mov	    r6, r0 /* save b  */
    ldr r1,[sp,#4] /* t2 */
    ldr r0,[sp,#8] /* t3 */
    mov     r2, r1
    bl	    sb_fe_mont_mult         // was square preserves r3

    cbz	    r6, _sb_fe_mod_expt_r_t2eqt3

    ldr r2,[sp,#0] /* x  */
    ldr r1,[sp,#8] /* t3 */
    ldr r0,[sp,#4] /* t2 */
    bl      sb_fe_mont_mult
    b       _sb_fe_mod_expt_r_setby

_sb_fe_mod_expt_r_t2eqt3 :
    ldr r0,[sp,#4] /* *t2 = */
    ldr r1,[sp,#8] /* *t3 */
    bl      sb_fe_mov

_sb_fe_mod_expt_r_setby:
    movs    r7, #1

_sb_fe_mod_expt_r_continue:
    subs    r4, r4, #1
    bpl     _sb_fe_mod_expt_r_loop

_sb_fe_mod_expt_r_exit:
    ldr r0,[sp,#0] /* *x= */
    ldr r1,[sp,#4] /* *t2 */
    bl      sb_fe_mov
    adds    r5, r5, #68-36
    cmp     r5, #68+ (68-36)
    bne     _sb_fe_mod_expt_loop

#if FEATURE_CANARIES
    rcp_canary_check_nodelay r8, CTAG_SB_FE_MOD_INV_R
#endif
    pop     {r0, r1, r2, r4, r5, r6, r7, r8, pc}

#if BOOTROM_HARDENING
.global sb_fe_hard_lo
.type sb_fe_hard_lo, %function
.thumb_func
sb_fe_hard_lo:
    rcp_canary_get_nodelay r2, CTAG_SB_FE_HARD
    push {r2, lr}
    bl	    sb_fe_cmp
    lsrs    r0, r0, #31  // 1 for LT
    b common_neq_1_path

.global sb_fe_hard_neq
.type sb_fe_hard_neq, %function
.thumb_func
sb_fe_hard_neq:
    rcp_canary_get_nodelay r2, CTAG_SB_FE_HARD
    push {r2, lr}
    bl	    sb_fe_cmp
common_neq_1_path:
    cbz     r0, return_hard_false
    // r0 = abs(r0)
    it	lt
    neglt	r0, r0
    // r1 should be 0x80000008 at this point
    // convert that to another 1
    adds    r1, r1 // r1 = 0x10, C==1
    sbcs    r1, #0xf
    b make_hx_bool_and_return

.global sb_fe_hard_eq
.type sb_fe_hard_eq, %function
.thumb_func
sb_fe_hard_eq:
    rcp_canary_get_nodelay r2, CTAG_SB_FE_HARD
    push {r2, lr}
    bl	    sb_fe_cmp
    cbnz    r0, return_hard_false
    adds    r0, #1
    // r1 should be 8 at this point
    // convert that to another 1
    subs    r1, #0x7
    b make_hx_bool_and_return

return_hard_false:
    movs r0, #0
    movs r1, #0

make_hx_bool_and_return:
    bl sonly_varm_make_hx_bool_impl
    pop {r2, r3}
    rcp_canary_check_nodelay r2, CTAG_SB_FE_HARD
    bx r3
#endif

/*
static sb_bool_t sb_sw_zscalar_validate(sb_fe_t k[static const 1],
                      const sb_fe_t right[static 1])
 */
.global sb_sw_zscalar_validate
.type sb_sw_zscalar_validate, %function
.thumb_func

sb_sw_zscalar_validate:
#if FEATURE_CANARIES
    rcp_canary_get_nodelay r3, CTAG_SB_SW_ZSCALAR_VALIDATE
    push	{r0, r1, r3, r4, lr} // save pointers on stack
#else
    push	{r0, r1, r4, lr}
#endif
#if !BOOTROM_HARDENING
    bl	    sb_fe_cmp   // preserves r1
    lsrs    r0, r0, #31  // 1 for LT
    beq     1f
    ldr     r0, [sp,#0] // k
    bl	    sb_fe_mod_reduce
    ldr     r0,[sp,#0]  // k
    ldr     r1,[sp,#4]  // right
    bl	    sb_fe_cmp
    and     r0,r0,#1
1:
#else
    //r &= SB_FE_LT(k, right); // k < n
    //sb_fe_mod_reduce(k, right); // after reduction, 0 is represented as n
    //r &= !SB_FE_EQ(k, right); // k != 0
    bl      sb_fe_hard_lo
    movs    r4, r0
    bpl     1f

    ldr     r0,[sp,#0] // k
    ldr     r1,[sp,#4]  // right
    bl	    sb_fe_mod_reduce // preserves R3

    ldr     r0,[sp,#0]  // k
    ldr     r1,[sp,#4]  // right
    bl	    sb_fe_hard_neq
    cmp     r0, #0
    bpl     1f
    rcp_b2and r0, r4
    b 2f
1:
    hx_bit_pattern_false r0
2:
#endif
#if FEATURE_CANARIES
    pop {r1, r2, r3, r4} // discard saved pointers
    rcp_canary_check_nodelay r3, CTAG_SB_SW_ZSCALAR_VALIDATE
    pop {pc}
#else
    pop	    {r1, r2, r4, pc}
#endif

/* hmac stuff */

/*
// Process a buffer of an arbitrary number of bytes
void sb_sha256_update(sb_sha256_state_t sha[static const restrict 1],
                      const sb_byte_t* restrict input,
                      size_t len) */

.cpu cortex-m23
// Assumes len is non zero
.ifeq 0
.weak sb_sha256_update  // This needs to be weak to help the test system.
.type sb_sha256_update, %function
.thumb_func
sb_sha256_update:
    push	{r4, lr}
#if SB_TEST
    cbz    r2, _sb_sha256_update_skip
#endif

    ldr	    r3, [r0, #0]
    adds	r3, r3, r2
    str	    r3, [r0, #0]

    adds	r4, r1, r2  // datapointer+length
    rsbs    r2, r2, #0  // -length

_sb_sha256_update_loop:
    ldrb	r0, [r4, r2 ]
    bl	    s_sha256_put_byte // Increments R2
    bne     _sb_sha256_update_loop
#define STEPTAG_SB_SHA256_UPDATE (STEPTAG_S_SHA256_PUT_BYTE + 1)
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_check_nodelay STEPTAG_SB_SHA256_UPDATE
.cpu cortex-m23
#endif
#if SB_TEST
_sb_sha256_update_skip:
#endif
    pop	    {r4, pc}

/*
// As above, but take a word buffer. Len is still in bytes.
void sb_sha256_update_32(sb_sha256_state_t sha[static restrict 1],
                             const uint32_t* restrict input,
                             size_t len) {
 */
.weak sb_sha256_update_32
.type sb_sha256_update_32, %function
.thumb_func
sb_sha256_update_32:
    push	{ r4, lr}

    ldr	    r3, [r0, #0]
    adds	r3, r3, r2
    str	    r3, [r0, #0]

    movs	r4, r1  // input

    lsrs	r2, r2, #2

    // the last thing we do is call s_varm_sha256_put_word
#define STEPTAG_S_SHA256_UPDATE_32 (STEPTAG_S_VARM_SHA256_PUT_WORD + 1)

    // if we know len >0 then this will never be taken and we can remove both instructions
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_set_nodelay STEPTAG_S_SHA256_UPDATE_32
.cpu cortex-m23
#endif
    beq     _sb_sha256_update_32_done

_sb_sha256_update_32_loop:
    ldmia	r4!, {r0}
    bl	    s_varm_sha256_put_word  // preserves R2
    subs    r2, r2, #1
    bne     _sb_sha256_update_32_loop

_sb_sha256_update_32_done:
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_check_nodelay STEPTAG_S_SHA256_UPDATE_32
.cpu cortex-m23
#endif
    pop	    { r4, pc}


/* static void s_sha256_put_byte(uint8_t x)  */
// increaments  R2
.weak s_sha256_put_byte
.type s_sha256_put_byte, %function
.thumb_func
s_sha256_put_byte:
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_set_nodelay STEPTAG_S_SHA256_PUT_BYTE
.cpu cortex-m23
#endif
    ldr	    r3, =SHA256_BASE
_sha256_put_byte_loop:
    ldr	    r1, [r3, #0]
    lsrs    r1, r1, #2 // WDATA_RDY bit
    bcc	    _sha256_put_byte_loop
    strb	r0, [r3, #4]
    adds    r2, r2, #1
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_check_nodelay STEPTAG_S_SHA256_PUT_BYTE
.cpu cortex-m23
#endif
    bx	    lr

.weak s_varm_sha256_put_word_inc
.global s_varm_sha256_put_word_inc
.type s_varm_sha256_put_word_inc, %function
.thumb_func
s_varm_sha256_put_word_inc:
.cpu cortex-m23
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_set_nodelay STEPTAG_S_SHA256_PUT_WORD_INC
.cpu cortex-m23
#endif
    ldr     r3, [r1]
    adds    r3, r3, #4
    str     r3, [r1]
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_check_nodelay STEPTAG_S_SHA256_PUT_WORD_INC
.cpu cortex-m23
#endif
.cpu cortex-m33

// fall thru

/* static void s_sha256_put_word(uint32_t x)  */
// preserves R2
// R3 = base of SHA-256
.weak s_varm_sha256_put_word
.type s_varm_sha256_put_word, %function
.thumb_func
s_varm_sha256_put_word:
.cpu cortex-m23
    ldr	    r3, =SHA256_BASE
s_varm_sha256_put_word_fast:
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_set_nodelay STEPTAG_S_VARM_SHA256_PUT_WORD
.cpu cortex-m23
#endif
_sha256_put_word_loop:
    ldr	    r1, [r3, #0]
    lsrs    r1, r1, #2 // WDATA_RDY bit
    bcc	    _sha256_put_word_loop
    str	    r0, [r3, #4]
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_check_nodelay STEPTAG_S_VARM_SHA256_PUT_WORD
.cpu cortex-m23
#endif
    bx	    lr
.cpu cortex-m33
.endif
.ifeq 0
.weak sb_sha256_finish
.type sb_sha256_finish, %function
.thumb_func
/* void sb_sha256_finish(sb_sha256_state_t sha[static restrict 1],  sb_byte_t output[static restrict SB_SHA256_SIZE]) {
 */
sb_sha256_finish:
#if !FEATURE_CANARIES
    push	{ r4, r5, lr}
#else
    rcp_canary_get r3, CTAG_S_SHA256_FINISH
    push	{ r3, r4, r5, lr}
#endif
    movs	r4, r1
    ldr	    r5, [r0]    // get total bytes

    movs	r0, #128	// 0x80

    movs	r2, r5

_sb_sha256_finish_loop1:
    bl      s_sha256_put_byte         // Preserves R2
    movs	r0, #0
    //ands	r3, r2, #63
    lsls    r3, r2, #26
    lsrs    r3, r3, #26
    cmp	    r3, #56
    bne	    _sb_sha256_finish_loop1

    lsrs	r0, r5, #29
    rev	    r0, r0
    bl	    s_varm_sha256_put_word        // Preserves R2
    lsls	r0, r5, #3
    rev	    r0, r0
    bl	    s_varm_sha256_put_word_fast
    // the above leaves pointer to base of SHA-256 in R3
_sb_sha256_finish_loop2:
    ldr	    r2, [r3, #0]
    lsrs    r2, r2, #3  // LOG (SHA256_CSR_SUM_VLD_BITS)+1
    bcc	    _sb_sha256_finish_loop2

    movs	r5, #8
    adds    r1, r3, r5 // .sum

 _sb_sha256_finish_loop3:
    ldm	    r1!, { r2 }
    subs	r5, #1
    rev	    r2, r2
    stm     r4!, { r2 }
    bne	    _sb_sha256_finish_loop3
#if FEATURE_CANARIES
    pop     {r3}
    rcp_canary_check_nodelay r3, CTAG_S_SHA256_FINISH
#endif
    pop	    {r4, r5, pc}
.endif

.cpu cortex-m33
.ifeq 0
/*void sb_hmac_sha256_finish(sb_hmac_sha256_state_t hmac[static const restrict 1],
                           sb_byte_t output[static const
                           restrict SB_SHA256_SIZE]) */
.weak sb_hmac_sha256_finish
.type sb_hmac_sha256_finish, %function
.thumb_func
sb_hmac_sha256_finish:
    push	{r0, r1, r4, r5, lr}
// hmac at [sp.#0]
// output at [sp,#4]
    bl	    sb_sha256_finish

    movs	r1, #92	// 0x5c opad
    ldr r0,[sp,#0] //hmac

    bl      sb_mac_sha256_reinit_cse

    ldr r1,[sp,#4] // output
    movs	r2, #32
    bl	    sb_sha256_update
    ldr r1,[sp,#4] // output
    ldr r0,[sp,#0] // hmac
    bl	    sb_sha256_finish
    pop     {r0, r1, r4, r5, lr}
// hmac in r0
    movs	r1, #92	// 0x5c opad
    b.n	    sb_hmac_sha256_key_pad
.endif

sb_mac_sha256_reinit_cse:
// Leave hmac pointer in r0
    push	{r0, lr}
    bl	    sb_hmac_sha256_key_pad  // Leaves r0 = r0+4
    subs    r0,r0,#4

    bl      sb_sha256_init   // preserves R0

    adds    r1, r0, #4
    movs	r2, #64
    bl	    sb_sha256_update
#define STEPTAG_SB_MAC_SHA256_REINIT_CSE (STEPTAG_SB_SHA256_UPDATE + 1)
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_SB_MAC_SHA256_REINIT_CSE
#endif
    pop     {r0, pc}

/* void sb_sha256_init(sb_sha256_state_t sha[static const 1]) */

.cpu cortex-m23
// preserves R0
.weak sb_sha256_init
.type sb_sha256_init, %function
.thumb_func
sb_sha256_init:
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_set_nodelay STEPTAG_SB_SHA256_INIT
.cpu cortex-m23
#endif
    movw	r2, #SHA256_CSR_RESET | SHA256_CSR_BSWAP_BITS | SHA256_CSR_START_BITS
    ldr	    r3, = SHA256_BASE
    str	    r2, [r3, #0]
    movs	r3, #0
    str 	r3, [r0]
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_check_nodelay STEPTAG_SB_SHA256_INIT
.cpu cortex-m23
#endif
    bx      lr
.cpu cortex-m33

/*  void sb_hmac_sha256_init_small(sb_hmac_sha256_state_t hmac[static const restrict 1],
                         const sb_byte_t* const restrict key)*/
.weak sb_hmac_sha256_init_small
.type sb_hmac_sha256_init_small, %function
.thumb_func
sb_hmac_sha256_init_small:
    push    { r0, lr }
    movs    r2, #32
    adds    r0, r0, #4       // copy hmac->key
    bl      memcpy
    movs    r2, #32
    add     r0, r0, r2
    movs    r1, #0
    bl      memset          // clear remaing 32 bytes
    pop     { r0, lr}
                            // below clears first word of hmac
// Fall into sb_hmac_sha256_reinit

/*void sb_hmac_sha256_reinit(sb_hmac_sha256_state_t hmac[static const 1]) */
.ifeq 0
.weak sb_hmac_sha256_reinit
.type sb_hmac_sha256_reinit, %function
.thumb_func
sb_hmac_sha256_reinit:
    movs	r1, #54 // 0x36 ipad
    push {r1, lr}
    bl      sb_mac_sha256_reinit_cse
    /* fall into  sb_hmac_sha256_key_pad*/
#define STEPTAG_SB_HMAC_SHA256_REINIT (STEPTAG_SB_MAC_SHA256_REINIT_CSE + 1)
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_SB_HMAC_SHA256_REINIT
#endif
    pop {r1, lr}
.endif

/*
static void sb_hmac_sha256_key_pad(sb_hmac_sha256_state_t hmac[static const 1],
                                   sb_byte_t const pad)
 */
 // leaves R0 = r0 +4
.ifeq 0
.global sb_hmac_sha256_key_pad
.type sb_hmac_sha256_key_pad, %function
.thumb_func
sb_hmac_sha256_key_pad:
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_SB_HMAC_SHA256_KEY_PAD
#endif
    adds	r0, r0, #4
    movs	r3, #63
_sb_hmac_sha256_key_pad_loop:
    ldrb	r2, [r0, r3]
    eors	r2, r1
    strb	r2, [r0, r3]
    subs	r3, #1
    bpl 	_sb_hmac_sha256_key_pad_loop
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_SB_HMAC_SHA256_KEY_PAD
#endif
    bx	    lr
.endif
/*
void sb_fe_from_bytes_big_endian(sb_fe_t dest[static const restrict 1],
                      const sb_byte_t src[static const restrict SB_ELEM_BYTES])
 */

 .global sb_fe_from_bytes_big_endian
 .global sb_fe_to_bytes_big_endian // the same function!
.type sb_fe_from_bytes_big_endian, %function
.type sb_fe_to_bytes_big_endian, %function
.thumb_func
sb_fe_from_bytes_big_endian:
.thumb_func
sb_fe_to_bytes_big_endian:
#if FEATURE_CANARIES
 rcp_count_set_nodelay STEPTAG_SB_FE_FROM_BYTES_BIG_ENDIAN
#endif
 movs r3,#8
 adds r0,r0,#28
1:
 ldmia r1!,{r2}
 rev r2,r2
 str r2,[r0],#-4
 subs r3,r3,#1
 bne 1b
#if FEATURE_CANARIES
 rcp_count_check_nodelay STEPTAG_SB_FE_FROM_BYTES_BIG_ENDIAN
#endif
 bx lr

#endif
