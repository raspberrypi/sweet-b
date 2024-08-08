/** @file sb_sw_lib.c
 *  @brief operations on short Weierstrass elliptic curves
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

#include <stddef.h>
#include <string.h>

#include "sb_test.h"
#include "sb_fe.h"
#include "sb_sw_lib.h"
#include "sb_sw_curves.h"
#include "sb_hmac_drbg.h"
#include "sb_hkdf.h"
#include "sb_error.h"
#include "sb_test_cavp.h"


#if BOOTROM_BUILD
#include "bootram.h"
#elif FEATURE_CANARIES
#include "bootrom.h"
#endif

// Used for point addition and conjugate addition
#define C_X1(ct) (&(ct)->param_use.curve_arith.p[0].x)
#define C_Y1(ct) (&(ct)->param_use.curve_arith.p[0].y)
#define C_X2(ct) (&(ct)->param_use.curve_arith.p[1].x)
#define C_Y2(ct) (&(ct)->param_use.curve_arith.p[1].y)
#define C_T5(ct) (&(ct)->param_use.curve_temporaries.t[0])
#define C_T6(ct) (&(ct)->param_use.curve_temporaries.t[1])
#define C_T7(ct) (&(ct)->param_use.curve_temporaries.t[2])
#define C_T8(ct) (&(ct)->param_use.curve_temporaries.t[3])

#define MULT_STATE(ct) (&(ct)->param_use.saved_state)

// The scalar used for point multiplication
#define MULT_K(ct) (&(ct)->params.k)

// The initial Z value, and the current Z coordinate in multiplication-addition
#define MULT_Z(ct) (&(ct)->params.z)

// Candidate to be tested during Z generation
#define MULT_Z2(ct) (&(ct)->param_gen.z2)

// The point to be multiplied, for shared secret generation and signature
// verification
#define MULT_POINT(ct) (&(ct)->param_use.mult.point)
#define MULT_POINT_X(ct) (&(ct)->param_use.mult.point.x)
#define MULT_POINT_Y(ct) (&(ct)->param_use.mult.point.y)

// The message to be signed as a scalar
#define SIGN_MESSAGE(ct) (&(ct)->param_use.sign.message)

// The private key used in signing as a scalar (K is the signature k)
#define SIGN_PRIVATE(ct) (&(ct)->param_use.sign.priv)

// The scalar to multiply the base point by in signature verification
#define MULT_ADD_KG(ct) (&(ct)->param_use.verify.late.kg)

// Stores P + G in signature verification
#define MULT_ADD_PG(ct) (&(ct)->param_use.verify.late.pg)

// The message to be verified as a scalar
#define VERIFY_MESSAGE(ct) (&(ct)->param_use.verify.early.message)

// The two working components of the signature, R and S
#define VERIFY_QS(ct) (&(ct)->param_use.verify.early.qs)
#define VERIFY_QR(ct) (&(ct)->param_use.verify.common.qr)

// Offsets of various point buffers in context

#include <assert.h>
#if SB_FE_ASM
#define O_C_X1 2
static_assert(O_C_X1*32==offsetof(sb_sw_context_t,          param_use.curve_arith.p[0].x), "");
#define O_C_Y1 3
static_assert(O_C_Y1*32==offsetof(sb_sw_context_t,          param_use.curve_arith.p[0].y), "");
#define O_C_X2 4
static_assert(O_C_X2*32==offsetof(sb_sw_context_t,          param_use.curve_arith.p[1].x), "");
#define O_C_Y2 5
static_assert(O_C_Y2*32==offsetof(sb_sw_context_t,          param_use.curve_arith.p[1].y), "");
#define O_C_T5 8
static_assert(O_C_T5*32==offsetof(sb_sw_context_t,          param_use.curve_temporaries.t[0]), "");
#define O_C_T6 9
static_assert(O_C_T6*32==offsetof(sb_sw_context_t,          param_use.curve_temporaries.t[1]), "");
#define O_C_T7 10
static_assert(O_C_T7*32==offsetof(sb_sw_context_t,          param_use.curve_temporaries.t[2]), "");
#define O_C_T8 11
static_assert(O_C_T8*32==offsetof(sb_sw_context_t,          param_use.curve_temporaries.t[3]), "");
#define O_MULT_K 0
static_assert(O_MULT_K*32==offsetof(sb_sw_context_t,        params.k), "");
#define O_MULT_Z 1
static_assert(O_MULT_Z*32==offsetof(sb_sw_context_t,        params.z), "");
#define O_MULT_Z2 2
static_assert(O_MULT_Z2*32==offsetof(sb_sw_context_t,       param_gen.z2));
#define O_MULT_POINT 6
static_assert(O_MULT_POINT*32==offsetof(sb_sw_context_t,    param_use.mult.point));
#define O_MULT_POINT_X 6
static_assert(O_MULT_POINT_X*32==offsetof(sb_sw_context_t,  param_use.mult.point.x));
#define O_MULT_POINT_Y 7
static_assert(O_MULT_POINT_Y*32==offsetof(sb_sw_context_t,  param_use.mult.point.y));
#define O_SIGN_MESSAGE 12
static_assert(O_SIGN_MESSAGE*32==offsetof(sb_sw_context_t,  param_use.sign.message));
#define O_SIGN_PRIVATE 13
static_assert(O_SIGN_PRIVATE*32==offsetof(sb_sw_context_t,  param_use.sign.priv));
#define O_MULT_ADD_KG 13
static_assert(O_MULT_ADD_KG*32==offsetof(sb_sw_context_t,   param_use.verify.late.kg));
#define O_MULT_ADD_PG 14
static_assert(O_MULT_ADD_PG*32==offsetof(sb_sw_context_t,   param_use.verify.late.pg));
#define O_MULT_ADD_PG_X 14
static_assert(O_MULT_ADD_PG_X*32==offsetof(sb_sw_context_t,   param_use.verify.late.pg.x));
#define O_MULT_ADD_PG_Y 15
static_assert(O_MULT_ADD_PG_Y*32==offsetof(sb_sw_context_t,   param_use.verify.late.pg.y));
#define O_VERIFY_MESSAGE 13
static_assert(O_VERIFY_MESSAGE*32==offsetof(sb_sw_context_t,param_use.verify.early.message));
#define O_VERIFY_QS 14
static_assert(O_VERIFY_QS*32==offsetof(sb_sw_context_t,     param_use.verify.early.qs));
#define O_VERIFY_QR 12
static_assert(O_VERIFY_QR*32==offsetof(sb_sw_context_t,     param_use.verify.common.qr));

#define O_CURVE_G_R_X 2
static_assert(O_CURVE_G_R_X*4==offsetof(sb_sw_curve_t,g_r.x));
#define O_CURVE_G_R_Y 10
static_assert(O_CURVE_G_R_Y*4==offsetof(sb_sw_curve_t,g_r.y));
#define O_CURVE_H_R_X 18
static_assert(O_CURVE_H_R_X*4==offsetof(sb_sw_curve_t,h_r.x));
#define O_CURVE_H_R_Y 26
static_assert(O_CURVE_H_R_Y*4==offsetof(sb_sw_curve_t,h_r.y));
#define O_CURVE_G_H_R_X 34
static_assert(O_CURVE_G_H_R_X*4==offsetof(sb_sw_curve_t,g_h_r.x));
#define O_CURVE_G_H_R_Y 42
static_assert(O_CURVE_G_H_R_Y*4==offsetof(sb_sw_curve_t,g_h_r.y));

#if SB_SW_P256_SUPPORT
#define O_CURVE_MINUS_A 50
static_assert(O_CURVE_MINUS_A*4==offsetof(sb_sw_curve_t,minus_a));
#define O_CURVE_B 59
static_assert(O_CURVE_B*4==offsetof(sb_sw_curve_t,b));
#endif

static_assert(offsetof(sb_sw_curve_t,p)==0); // FE interpreter and other assembler relies on these also
static_assert(offsetof(sb_sw_curve_t,n)==4);
static_assert(offsetof(sb_prime_field_t,p_minus_two_f1)==36);
static_assert(offsetof(sb_prime_field_t,p_minus_two_f2)==68);
static_assert(offsetof(sb_prime_field_t,r2_mod_p)==100);
static_assert(offsetof(sb_prime_field_t,r_mod_p)==132);
static_assert(offsetof(sb_prime_field_padded_t,p_minus_two_f1)==36);
static_assert(offsetof(sb_prime_field_padded_t,p_minus_two_f2)==68);
static_assert(offsetof(sb_prime_field_padded_t,r2_mod_p)==100);
static_assert(offsetof(sb_prime_field_padded_t,r_mod_p)==132);
static_assert(offsetof(sb_prime_field_padded_t,r_mod_p)==132);
static_assert(offsetof(sb_prime_field_padded_t,pad0)==164);

extern void sb_fe_mov(void*dest,const void*src);
extern void sb_fe_mov_pair(void*dest,const void*src);
#ifdef SB_SW_UNIQUE_CURVE_SUPPORTED
#define SB_FE_START(C) { register uintptr_t _c asm ("r0") = (uintptr_t)C; asm volatile( "bl sb_fe_interp\n"
#define SB_FE_STOP ".short 0xffff\n" \
                   : "+l" (_c) \
                   : \
                   : "r2", "r3", "ip", "lr"); }
#else
#define SB_FE_START(C,F) { register uintptr_t _c asm ("r0") = (uintptr_t)C; register uintptr_t _f asm ("r1") = (uintptr_t)F; asm volatile( "bl sb_fe_interp\n"
#define SB_FE_STOP ".short 0xffff\n" \
                   : "+l" (_c), "+l" (_f) \
                   : \
                   : "r2", "r3", "ip", "lr"); }
#endif
#define XSTR(s) STR(s)
#define STR(s) #s
#define SB_FE_MOD_ADD(D,N,M,PN)    ".short 0x0000+(" XSTR(PN) "<<12)+(" XSTR(M) "<<8)+(" XSTR(N) "<<4)+" XSTR(D) "\n"
#define SB_FE_MOD_DOUBLE(D,N,PN)   ".short 0x0000+(" XSTR(PN) "<<12)+(" XSTR(N) "<<8)+(" XSTR(N) "<<4)+" XSTR(D) "\n"
#define SB_FE_MOD_SUB(D,N,M,PN)    ".short 0x2000+(" XSTR(PN) "<<12)+(" XSTR(M) "<<8)+(" XSTR(N) "<<4)+" XSTR(D) "\n"
#define SB_FE_MONT_MULT(D,N,M,PN)  ".short 0x4000+(" XSTR(PN) "<<12)+(" XSTR(M) "<<8)+(" XSTR(N) "<<4)+" XSTR(D) "\n"
#define SB_FE_MONT_SQUARE(D,N,PN)  ".short 0x4000+(" XSTR(PN) "<<12)+(" XSTR(N) "<<8)+(" XSTR(N) "<<4)+" XSTR(D) "\n"
#define SB_FE_MOV(D,N)             ".short 0x6000+("                                     XSTR(N) "<<4)+" XSTR(D) "\n"
#define SB_FE_MOD_REDUCE(D,PN)     ".short 0x8000+(" XSTR(PN) "<<12)+"                                   XSTR(D) "\n"
#define SB_FE_MONT_CONVERT(D,N,PN) ".short 0xa000+(" XSTR(PN) "<<12)+("                  XSTR(N) "<<4)+" XSTR(D) "\n"
#define SB_FE_MOD_INV_R(D,N,M,PN)  ".short 0xc000+(" XSTR(PN) "<<12)+(" XSTR(M) "<<8)+(" XSTR(N) "<<4)+" XSTR(D) "\n"
#define SB_FE_MOV_SREL(D,I)        ".short 0xe000+("                                     XSTR(I) "<<4)+" XSTR(D) "\n"
#define SB_FE_MOV_CONST(D,I)       ".short 0xe800+("                                     XSTR(I) "<<4)+" XSTR(D) "\n"
#else
#define O_C_X1 C_X1(_c)
#define O_C_X2 C_X2(_c)
#define O_C_Y1 C_Y1(_c)
#define O_C_Y2 C_Y2(_c)
#define O_C_T5 C_T5(_c)
#define O_C_T6 C_T6(_c)
#define O_C_T7 C_T7(_c)
#define O_C_T8 C_T8(_c)
#define O_MULT_K MULT_K(_c)
#define O_MULT_Z MULT_Z(_c)
#define O_MULT_Z2 MULT_Z2(_c)
#define O_MULT_POINT_X MULT_POINT_X(_c)
#define O_MULT_POINT_Y MULT_POINT_Y(_c)
#define O_SIGN_MESSAGE SIGN_MESSAGE(_c)
#define O_MULT_ADD_KG MULT_ADD_KG(_c)
#define O_MULT_ADD_PG_X (&MULT_ADD_PG(_c)->x)
#define O_MULT_ADD_PG_Y (&MULT_ADD_PG(_c)->y)
#define O_VERIFY_MESSAGE VERIFY_MESSAGE(_c)
#define O_VERIFY_QR VERIFY_QR(_c)
#define O_VERIFY_QS VERIFY_QS(_c)

#define PN (PN ? _s->p : _s->n)
#define SB_FE_START(C,F) { sb_sw_context_t *_c = C; const sb_sw_curve_t *_s = F; ((void)_s->p)
#define SB_FE_MOD_ADD(D,N,M,PN) sb_fe_mod_add(D,N,M,PN?_s->p:_s->n)
#define SB_FE_MOD_DOUBLE(D,N,PN) sb_fe_mod_double(D,N,PN?_s->p:_s->n)
#define SB_FE_MOD_SUB(D,N,M,PN) sb_fe_mod_sub(D,N,M,PN?_s->p:_s->n)
#define SB_FE_MONT_MULT(D,N,M,PN) sb_fe_mont_mult(D,N,M,PN?_s->p:_s->n)
#define SB_FE_MONT_SQUARE(D,N,PN) sb_fe_mont_square(D,N,PN?_s->p:_s->n)
#define SB_FE_MOV(D,N) *D = *N
#define SB_FE_MONT_CONVERT(D,N,PN) sb_fe_mont_reduce(D,N,PN?_s->p:_s->n)
#define SB_FE_MOD_REDUCE(D,PN) sb_fe_mod_reduce(D,PN?_s->p:_s->n)
#define SB_FE_MOD_INV_R(D,N,M,PN) sb_fe_mod_inv_r(D,N,M,PN?_s->p:_s->n)
#define SB_FE_MOV_SREL(D,I) memcpy(D,(char*)_s+(I)*4,32)
#define SB_FE_MOV_CONST(D,I) memset(D,0,32) ; *(unsigned char*)_s=(I)
#define SB_FE_STOP }
#endif

#if SB_SW_P256_SUPPORT

// P256 is defined over F(p) where p is the Solinas prime
// 2^256 - 2^224 + 2^192 + 2^96 - 1
const sb_prime_field_t SB_CURVE_P256_P = {
    .p = SB_FE_CONST_QR(0xFFFFFFFF00000001, 0x0000000000000000,
                        0x00000000FFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                        &SB_CURVE_P256_P),
    // p - 2 has Hamming weight 128. Factors:

    // Hamming weight 100
    .p_minus_two_f1 =
        SB_FE_CONST_QR(0x00000000F04D3168, 0xCA47D4443B0552EC,
                       0x999CB770B4B62944, 0x6571423119245693,
                       &SB_CURVE_P256_P),

    // Hamming weight 16
    .p_minus_two_f2 = SB_FE_CONST_QR(0, 0, 0, 0x110B9592F,
                                     &SB_CURVE_P256_P),

    .p_mp = (sb_word_t) UINT64_C(1),
    .r2_mod_p = SB_FE_CONST_QR(0x00000004FFFFFFFD, 0xFFFFFFFFFFFFFFFE,
                               0xFFFFFFFBFFFFFFFF, 0x0000000000000003,
                               &SB_CURVE_P256_P),
    .r_mod_p = SB_FE_CONST_QR(0x00000000FFFFFFFE, 0xFFFFFFFFFFFFFFFF,
                              0xFFFFFFFF00000000, 0x0000000000000001,
                              &SB_CURVE_P256_P),
};

// The prime order of the P256 group
const sb_prime_field_t SB_CURVE_P256_N = {
    .p = SB_FE_CONST_QR(0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF,
                        0xBCE6FAADA7179E84, 0xF3B9CAC2FC632551,
                        &SB_CURVE_P256_N),

    // p - 2 has Hamming weight 169. Factors:

    // Hamming weight 85:
    .p_minus_two_f1 =
        SB_FE_CONST(0, 0x1E85574166915052,
                    0x945E2FDE9505C722, 0x24DC681531C30637),

    // Hamming weight 29:
    .p_minus_two_f2 = SB_FE_CONST(0, 0, 0x8, 0x6340A6B209A6CDA9),

    .p_mp = (sb_word_t) UINT64_C(0xCCD1C8AAEE00BC4F),
    .r2_mod_p =
        SB_FE_CONST_QR(0x66E12D94F3D95620, 0x2845B2392B6BEC59,
                       0x4699799C49BD6FA6, 0x83244C95BE79EEA2,
                       &SB_CURVE_P256_N),
    .r_mod_p =
        SB_FE_CONST_QR(0x00000000FFFFFFFF, 0x0000000000000000,
                       0x4319055258E8617B, 0x0C46353D039CDAAF,
                       &SB_CURVE_P256_N),
};

const sb_sw_curve_t SB_CURVE_P256 = {
    .p = &SB_CURVE_P256_P,
    .n = &SB_CURVE_P256_N,
    .g_r = {
        SB_FE_CONST_QR(0x18905F76A53755C6, 0x79FB732B77622510,
                       0x75BA95FC5FEDB601, 0x79E730D418A9143C,
                       &SB_CURVE_P256_P),
        SB_FE_CONST_QR(0x8571FF1825885D85, 0xD2E88688DD21F325,
                       0x8B4AB8E4BA19E45C, 0xDDF25357CE95560A, &SB_CURVE_P256_P)
    },
    .h_r = {
        SB_FE_CONST_QR(0x3DABB6DD63469FDA, 0xD6636C75F0AEE963,
                       0x5E3BDEACE03C7C1E, 0x599DE4BA95AEDB71,
                       &SB_CURVE_P256_P),
        SB_FE_CONST_QR(0xCA44FCA952D8F196, 0x7AC346280EA74210,
                       0x77AE0F653969D951, 0x3EF12A374A0D7441, &SB_CURVE_P256_P)
    },
    .g_h_r = {
        SB_FE_CONST_QR(0x41FBBA1A1842253C, 0x2DDFA21F8A5F4377,
                       0x928D36DAB2C0BD2F, 0x2C487DEB40FA32F9,
                       &SB_CURVE_P256_P),
        SB_FE_CONST_QR(0xD041EE1CCC6223C9, 0xCD81EFC57B6F0943,
                       0xC614355C4D10A425, 0x3A1739581FCABBB7, &SB_CURVE_P256_P)
    },
#if SB_SW_P256_SUPPORT
    .minus_a = SB_FE_CONST_QR(0, 0, 0, 3, &SB_CURVE_P256_P),
    .minus_a_r_over_three = &SB_CURVE_P256_P.r_mod_p,
    .b = SB_FE_CONST_QR(0x5AC635D8AA3A93E7, 0xB3EBBD55769886BC,
                        0x651D06B0CC53B0F6, 0x3BCE3C3E27D2604B,
                        &SB_CURVE_P256_P),
#endif
};

#endif

#if SB_SW_SECP256K1_SUPPORT

// secp256k1 is defined over F(p):
const sb_prime_field_padded_t SB_CURVE_SECP256K1_P = {
    .p = SB_FE_CONST_QR(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFC2F,
                        &SB_CURVE_SECP256K1_P),

    // p - 2 has Hamming weight 249. Factors:

    // Hamming weight 64:
    .p_minus_two_f1 =
        SB_FE_CONST(0, 0, 0x037F6FF774E142D5, 0xC004A68677B5D811),

    // Hamming weight 58:
    .p_minus_two_f2 = SB_FE_CONST(0, 0x49,
                                  0x30562E37A2A6A014, 0x99B40D0074369E5D),

    .p_mp = (sb_word_t) UINT64_C(0xD838091DD2253531),
    .r2_mod_p =
        SB_FE_CONST_QR(0x0000000000000000, 0x0000000000000000,
                       0x0000000000000001, 0x000007A2000E90A1,
                       &SB_CURVE_SECP256K1_P),
    .r_mod_p =
        SB_FE_CONST_QR(0, 0, 0, 0x1000003D1,
                       &SB_CURVE_SECP256K1_P),
    .pad0 = 0, // this pad ensures that the last 32 bytes of this structure are equal to SB_FE_ONE
};

/* we would like to:
static_assert(((const uint32_t*)&SB_CURVE_SECP256K1_P)[0x22]==1);
static_assert(((const uint32_t*)&SB_CURVE_SECP256K1_P)[0x23]==0);
static_assert(((const uint32_t*)&SB_CURVE_SECP256K1_P)[0x24]==0);
static_assert(((const uint32_t*)&SB_CURVE_SECP256K1_P)[0x25]==0);
static_assert(((const uint32_t*)&SB_CURVE_SECP256K1_P)[0x26]==0);
static_assert(((const uint32_t*)&SB_CURVE_SECP256K1_P)[0x27]==0);
static_assert(((const uint32_t*)&SB_CURVE_SECP256K1_P)[0x28]==0);
static_assert(((const uint32_t*)&SB_CURVE_SECP256K1_P)[0x29]==0);
but apparently those are not constants we can static_assert.
*/

// The prime order of the secp256k1 group:
const sb_prime_field_t SB_CURVE_SECP256K1_N = {
    .p = SB_FE_CONST_QR(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE,
                        0xBAAEDCE6AF48A03B, 0xBFD25E8CD0364141,
                        &SB_CURVE_SECP256K1_N),

    // p -2 has Hamming weight 196. Factors:

    // Hamming weight 134:
    .p_minus_two_f1 = SB_FE_CONST(0x3333333333333333, 0x3333333333333332,
                                  0xF222F8FAEFDB533F, 0x265D461C29A47373),

    // Hamming weight 2:
    .p_minus_two_f2 = SB_FE_CONST(0, 0, 0, 5),

    .p_mp = (sb_word_t) UINT64_C(0x4B0DFF665588B13F),
    .r2_mod_p = SB_FE_CONST_QR(0x9D671CD581C69BC5, 0xE697F5E45BCD07C6,
                               0x741496C20E7CF878, 0x896CF21467D7D140,
                               &SB_CURVE_SECP256K1_N),
    .r_mod_p = SB_FE_CONST_QR(0x0000000000000000, 0x0000000000000001,
                              0x4551231950B75FC4, 0x402DA1732FC9BEBF,
                              &SB_CURVE_SECP256K1_N),
};

const sb_sw_curve_t SB_CURVE_SECP256K1 = {
    .p = (const sb_prime_field_t*) &SB_CURVE_SECP256K1_P,
    .n = &SB_CURVE_SECP256K1_N,
    .g_r = {
        SB_FE_CONST_QR(0x9981E643E9089F48, 0x979F48C033FD129C,
                       0x231E295329BC66DB, 0xD7362E5A487E2097,
                       &SB_CURVE_SECP256K1_P),
        SB_FE_CONST_QR(0xCF3F851FD4A582D6, 0x70B6B59AAC19C136,
                       0x8DFC5D5D1F1DC64D, 0xB15EA6D2D3DBABE2,
                       &SB_CURVE_SECP256K1_P)
    },
    .h_r = {
        SB_FE_CONST_QR(0x30A198DEBBCEFCAE, 0x537053ECF418BA53,
                       0xD8C36C4D8EC6CE34, 0xA381C3D21219CA1C,
                       &SB_CURVE_SECP256K1_P),
        SB_FE_CONST_QR(0xC198D9AFBD3AB7C6, 0xA5495A07C2AFCCE5,
                       0xF671D727A3637755, 0x446A2AD0C25FF948,
                       &SB_CURVE_SECP256K1_P)
    },
    .g_h_r = {
        SB_FE_CONST_QR(0x7BCE0EF2C201767E, 0xEC431492C7C96E54,
                       0x15EF56335DF148DB, 0xCDA8D7EF632EA0D8,
                       &SB_CURVE_SECP256K1_P),
        SB_FE_CONST_QR(0x3FB97A191E4DE5EA, 0xBBA21827B7EFEC04,
                       0xC7B977CC32E0BAA9, 0xC374BB2A1315A22F,
                       &SB_CURVE_SECP256K1_P)
    },
#if SB_SW_P256_SUPPORT
    .minus_a = SB_FE_CONST_QR(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                              0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFC2F,
                              &SB_CURVE_SECP256K1_P),
    .minus_a_r_over_three = &SB_CURVE_SECP256K1_P.p,
    .b = SB_FE_CONST_QR(0, 0, 0, 7, &SB_CURVE_SECP256K1_P),
#endif
};

#endif

#if !SB_SW_P256_SUPPORT
// static const sb_fe_t secp256k1_b=SB_FE_CONST_QR(0, 0, 0, 7, &SB_CURVE_SECP256K1_P);
static const sb_fe_t secp256k1_b=SB_FE_CONST(0, 0, 0, 7);
#endif

// Helper to fetch a curve given its curve_id
#if !BOOTROM_BUILD
static sb_error_t sb_sw_curve_from_id(const sb_sw_curve_t** const s,
                                      sb_sw_curve_id_t const curve)
{
    switch (curve) {
#if SB_SW_P256_SUPPORT
        case SB_SW_CURVE_P256: {
            *s = &SB_CURVE_P256;
            return 0;
        }
#endif
#if SB_SW_SECP256K1_SUPPORT
        case SB_SW_CURVE_SECP256K1: {
            *s = &SB_CURVE_SECP256K1;
            return 0;
        }
#endif
#ifdef SB_TEST
        case SB_SW_CURVE_INVALID:
            break;
#endif
    }
    // Huh?
    *s = NULL;
    return SB_ERROR_CURVE_INVALID;
}
#endif

#if !BOOTROM_BUILD
// Helper to fetch a curve_id given a curve
static sb_sw_curve_id_t sb_sw_id_from_curve(const sb_sw_curve_t* const s)
{
#if SB_SW_P256_SUPPORT
  if(s==&SB_CURVE_P256) return SB_SW_CURVE_P256;
#endif
#if SB_SW_SECP256K1_SUPPORT
  if(s==&SB_CURVE_SECP256K1) return SB_SW_CURVE_SECP256K1;
#endif
  return 999;
}
#endif

// All multiplication in Sweet B takes place using Montgomery multiplication
// MM(x, y) = x * y * R^-1 mod M where R = 2^SB_FE_BITS
// This has the nice property that MM(x * R, y * R) = x * y * R
// which means that sequences of operations can be chained together

// The inner loop of the Montgomery ladder takes place with coordinates that have been
// pre-multiplied by R. Point addition involves no constants, only additions, subtractions,
// and multiplications (and squarings). As such, the factor of R in coordinates is maintained
// throughout: mont_mult(a * R, b * R) = (a * b) * R, a * R + b * R = (a + b) * R, etc.
// For simplicity, the factor R will be ignored in the following comments.

// Initial point doubling: compute 2P in Jacobian coordinates from P in
// affine coordinates.

// Algorithm 23 from Rivain 2011, modified slightly

// Input:  P = (x2, y2) in affine coordinates
// Output: (x1, y1) = P', (x2, y2) = 2P in co-Z with t5 = Z = 2 * y2
// Cost:   6MM + 11A
#if !BOOTROM_BUILD
static void sb_sw_point_initial_double(sb_sw_context_t c[static const 1],
                                       const sb_sw_curve_t s[static const 1])
{

    SB_FE_START(c,s)
    SB_FE_MOD_DOUBLE(O_C_T5,O_C_Y2,0)                 // sb_fe_mod_double(C_T5(c), C_Y2(c), s->p); // t5 = Z
    SB_FE_MONT_SQUARE(O_C_Y1,O_C_X2,0)                // sb_fe_mont_square(C_Y1(c), C_X2(c), s->p); // t2 = x^2
#if SB_SW_P256_SUPPORT // otherwise a is identically zero
    SB_FE_STOP

    sb_fe_mod_sub(C_Y1(c), C_Y1(c), s->minus_a_r_over_three, s->p); // t2 = x^2 + a / 3

    SB_FE_START(c,s)
#endif
    SB_FE_MOD_DOUBLE(O_C_X1, O_C_Y1, 0)        // sb_fe_mod_double(C_X1(c), C_Y1(c), s->p);          // t1 = 2 * (x^2 + a / 3)
    SB_FE_MOD_ADD(O_C_Y1, O_C_Y1, O_C_X1, 0)   // sb_fe_mod_add(C_Y1(c), C_Y1(c), C_X1(c), s->p);    // t2 = (3 * x^2 + a) = B

    SB_FE_MONT_SQUARE(O_C_T6, O_C_Y2, 0)       // sb_fe_mont_square(C_T6(c), C_Y2(c), s->p);         // t6 = y^2
    SB_FE_MOD_DOUBLE(O_C_Y2, O_C_T6, 0)        // sb_fe_mod_double(C_Y2(c), C_T6(c), s->p);          // t4 = 2 * y^2
    SB_FE_MOD_DOUBLE(O_C_T6, O_C_Y2, 0)        // sb_fe_mod_double(C_T6(c), C_Y2(c), s->p);          // t6 = 4 * y^2
    SB_FE_MONT_MULT(O_C_X1, O_C_X2, O_C_T6, 0) // sb_fe_mont_mult(C_X1(c), C_X2(c), C_T6(c), s->p);  // t1 = 4 * x * y^2 = A

    SB_FE_MONT_SQUARE(O_C_X2, O_C_Y1, 0)       // sb_fe_mont_square(C_X2(c), C_Y1(c), s->p);         // t3 = B^2

    SB_FE_MOD_SUB(O_C_X2, O_C_X2, O_C_X1, 0)   // sb_fe_mod_sub(C_X2(c), C_X2(c), C_X1(c), s->p);    // t2 = B^2 - A
    SB_FE_MOD_SUB(O_C_X2, O_C_X2, O_C_X1, 0)   // sb_fe_mod_sub(C_X2(c), C_X2(c), C_X1(c), s->p);    // x2 = B^2 - 2 * A = X2

    SB_FE_MOD_SUB(O_C_T6, O_C_X1, O_C_X2, 0)   // sb_fe_mod_sub(C_T6(c), C_X1(c), C_X2(c), s->p);    // t6 = A - X2
    SB_FE_MONT_MULT(O_C_T7, O_C_Y1, O_C_T6, 0) // sb_fe_mont_mult(C_T7(c), C_Y1(c), C_T6(c), s->p);  // t7 = B * (A - X2)

    SB_FE_MONT_SQUARE(O_C_Y1, O_C_Y2, 0)       // sb_fe_mont_square(C_Y1(c), C_Y2(c), s->p);         // t2 = (2 * y^2)^2 = 4 * y^4
    SB_FE_MOD_DOUBLE(O_C_Y1, O_C_Y1, 0)        // sb_fe_mod_double(C_Y1(c), C_Y1(c), s->p);          // Y1 = 8 * y^4 = Z^3 * y
    SB_FE_MOD_SUB(O_C_Y2, O_C_T7, O_C_Y1, 0)   // sb_fe_mod_sub(C_Y2(c), C_T7(c), C_Y1(c), s->p);    // Y2 = B * (A - X2) - Y1
    SB_FE_STOP
}
#endif

// Co-Z point addition with update:
// Input: P = (x1, y1), Q = (x2, y2) in co-Z, with x2 - x1 in t6
// Output: P + Q = (x3, y3) in (x1, y1), P = (x1', y1') in (x2, y2)
//         B + C = t5 with Z' = Z * (x2 - x1)
//     or: P = P + Q, Q = P'
// Uses:   t5, t6, t7; leaves t8 unmodified (used by conjugate addition and Z recovery)
// Cost:   6MM + 6A
static void sb_sw_point_co_z_add_update_zup(sb_sw_context_t c[static const 1],
                                            const sb_sw_curve_t s[static const 1])
{
    SB_FE_START(c,s)
    SB_FE_MONT_SQUARE(O_C_T5, O_C_T6,         0)  //  sb_fe_mont_square(C_T5(c), C_T6(c), s->p);        // t5 = (x2 - x1)^2 = (Z' / Z)^2 = A
    SB_FE_MONT_MULT  (O_C_T6, O_C_X2, O_C_T5, 0)  //  sb_fe_mont_mult(C_T6(c), C_X2(c), C_T5(c), s->p); // t6 = x2 * A = C
    SB_FE_MONT_MULT  (O_C_X2, O_C_X1, O_C_T5, 0)  //  sb_fe_mont_mult(C_X2(c), C_X1(c), C_T5(c), s->p); // t3 = x1 * A = B = x1'
    SB_FE_MOD_SUB    (O_C_T7, O_C_Y2, O_C_Y1, 0)  //  sb_fe_mod_sub(C_T7(c), C_Y2(c), C_Y1(c), s->p);   // t7 = y2 - y1
    SB_FE_MOD_ADD    (O_C_T5, O_C_X2, O_C_T6, 0)  //  sb_fe_mod_add(C_T5(c), C_X2(c), C_T6(c), s->p);   // t5 = B + C
    SB_FE_MOD_SUB    (O_C_T6, O_C_T6, O_C_X2, 0)  //  sb_fe_mod_sub(C_T6(c), C_T6(c), C_X2(c), s->p);   // t6 = C - B = (x2 - x1)^3 = (Z' / Z)^3
    SB_FE_MONT_MULT  (O_C_Y2, O_C_Y1, O_C_T6, 0)  //  sb_fe_mont_mult(C_Y2(c), C_Y1(c), C_T6(c), s->p); // y1' = y1 * (Z' / Z)^3 = E
    SB_FE_MONT_SQUARE(O_C_X1, O_C_T7,         0)  //  sb_fe_mont_square(C_X1(c), C_T7(c), s->p);        // t1 = (y2 - y1)^2 = D
    SB_FE_MOD_SUB    (O_C_X1, O_C_X1, O_C_T5, 0)  //  sb_fe_mod_sub(C_X1(c), C_X1(c), C_T5(c), s->p);   // x3 = D - B - C
    SB_FE_MOD_SUB    (O_C_T6, O_C_X2, O_C_X1, 0)  //  sb_fe_mod_sub(C_T6(c), C_X2(c), C_X1(c), s->p);   // t6 = B - x3
    SB_FE_MONT_MULT  (O_C_Y1, O_C_T7, O_C_T6, 0)  //  sb_fe_mont_mult(C_Y1(c), C_T7(c), C_T6(c), s->p); // t4 = (y2 - y1) * (B - x3)
    SB_FE_MOD_SUB    (O_C_Y1, O_C_Y1, O_C_Y2, 0)  //  sb_fe_mod_sub(C_Y1(c), C_Y1(c), C_Y2(c), s->p);   // y3 = (y2 - y1) * (B - x3) - E
    SB_FE_STOP

}

// Co-Z addition with update, with Z-update computation
// Sets t6 to x2 - x1 before calling sb_sw_point_co_z_add_update_zup
// Cost: 6MM + 7A
static inline void
sb_sw_point_co_z_add_update(sb_sw_context_t c[static const 1],
                            const sb_sw_curve_t s[static const 1])
{
    sb_fe_mod_sub(C_T6(c), C_X2(c), C_X1(c), s->p); // t6 = x2 - x1 = Z' / Z
    sb_sw_point_co_z_add_update_zup(c, s);
}

#if !BOOTROM_BUILD
// Co-Z conjugate addition with update, with Z-update computation
// Input:  P = (x1, y1), Q = (x2, y2) in co-Z, with x2 - x1 in t6
// Output: P + Q = (x3, y3) in (x1, y1), P - Q = in (x2, y2), P' in (t6, t7)
//         with Z' = Z * (x2 - x1)
//     or: P = P + Q, Q = P - Q
// Uses:   t5, t6, t7, t8
// Cost:   8MM + 11A (6MM + 7A for addition-with-update + 2MM + 4A)
static void sb_sw_point_co_z_conj_add(sb_sw_context_t c[static const 1],
                                      const sb_sw_curve_t s[static const 1])
{
    sb_fe_mod_add(C_T8(c), C_Y1(c), C_Y2(c), s->p); // t8 = y1 + y2

    sb_sw_point_co_z_add_update(c, s); // t5 = B + C

    *C_T6(c) = *C_X2(c);
    *C_T7(c) = *C_Y2(c);

    sb_fe_mont_square(C_X2(c), C_T8(c), s->p); // t6 = (y1 + y2)^2 = F
    sb_fe_mod_sub(C_X2(c), C_X2(c), C_T5(c), s->p); // t6 = F - (B + C) = x3'

    sb_fe_mod_sub(C_T5(c), C_X2(c), C_T6(c), s->p); // t5 = x3' - B
    sb_fe_mont_mult(C_Y2(c), C_T8(c), C_T5(c),
                    s->p); // t2 = (y2 + y1) * (x3' - B)
    sb_fe_mod_sub(C_Y2(c), C_Y2(c), C_T7(c),
                  s->p); // y3' = (y2 + y1) * (x3' - B) - E
}
#endif

// Regularize the bit count of the scalar by adding CURVE_N or 2 * CURVE_N
// The resulting scalar will have P256_BITS + 1 bits, with the highest bit set
// This enables the Montgomery ladder to start at (1P, 2P) instead of (0P, 1P).
// The resulting scalar k is always >= N + R (where R is 2^256 mod N) and
// < 2N + R.
// To see how this works, consider an input scalar of R: the first addition
// produces N + (2^256 - N) = 2^256 and overflows; therefore the resulting
// scalar will be N + R, and this is the lowest scalar that produces
// overflow on the first addition. Now consider an input scalar of R - 1:
// the first addition produces N + (2^256 - N - 1) = 2^256 - 1 which does
// not overflow; hence a second addition is necessary. This is the largest
// scalar which requires two additions.

#if !BOOTROM_BUILD
static void sb_sw_regularize_scalar(sb_fe_t scalar[static const 1],
                                    sb_sw_context_t c[static const 1],
                                    const sb_sw_curve_t s[static const 1])
{
    const sb_word_t c_1 = sb_fe_add(C_T5(c), scalar, &s->n->p);
    sb_fe_add(scalar, C_T5(c), &s->n->p);
    sb_fe_ctswap(c_1, scalar, C_T5(c));
}
#endif

// NOT USED
#if !BOOTROM_BUILD
static void
sb_sw_point_mult_start(sb_sw_context_t m[static const 1],
                       const sb_sw_curve_t curve[static const 1])
{
    // Input scalars MUST always be checked for validity
    // (k is reduced and nonzero mod N).

    sb_sw_context_saved_state_t state = *MULT_STATE(m);

    // If the top bit of the scalar is set, invert the scalar and the input
    // point. This ensures that the scalar -2, which would otherwise be
    // exceptional in our ladder, is treated as the scalar 2. The
    // corresponding inversion will be performed to the output point at the
    // end of the ladder. Note that this assumes a 256-bit field order;
    // this assumption is also made in sb_sw_regularize_scalar. All
    // inversions are computed unconditionally, and the inv_k flag is used
    // for constant-time swaps.
    state.inv_k = sb_fe_test_bit(MULT_K(m), SB_FE_BITS - 1);

    sb_fe_mod_negate(C_T5(m), MULT_K(m), curve->n);
    sb_fe_ctswap(state.inv_k, C_T5(m), MULT_K(m));

    // The scalar 1 will be handled by allowing the ladder to produce the
    // exceptional output (0, 0), then adding in the original point X and Y
    // values to produce P. This addition is performed unconditionally, and the
    // k_one flag is used only for constant-time swaps. Because of the scalar
    // inversion above, -1 will be handled as 1 during the ladder, and P will
    // be inverted to produce -P.
    state.k_one = SB_FE_EQ(MULT_K(m), &SB_FE_ONE);

    sb_sw_regularize_scalar(MULT_K(m), m, curve);

    // Throughout the ladder, (x1, y1) is (X0 * R, Y0 * R)
    // (x2, y2) is (X1 * R, Y1 * R)
    // This enables montgomery multiplies to be used in the ladder without
    // explicit multiplies by R^2 mod P
    // It is assumed that the input point has been pre-multiplied by R. In
    // the case of the base point of the curve, it is stored this way in the
    // curve constant. In the case of ECDH, the point X and Y values will be
    // converted to the Montgomery domain in the wrapper for this routine.

    *C_X2(m) = *MULT_POINT_X(m);
    *C_Y2(m) = *MULT_POINT_Y(m);

    sb_sw_point_initial_double(m, curve);

    // The following applies a Z update of iz * R^-1.

    sb_fe_mont_square(C_T7(m), MULT_Z(m), curve->p); // t7 = z^2
    sb_fe_mont_mult(C_T6(m), MULT_Z(m), C_T7(m), curve->p); // t6 = z^3

    *C_T5(m) = *C_X1(m);
    sb_fe_mont_mult(C_X1(m), C_T5(m), C_T7(m), curve->p); // x z^2
    *C_T5(m) = *C_Y1(m);
    sb_fe_mont_mult(C_Y1(m), C_T5(m), C_T6(m), curve->p); // y z^3
    *C_T5(m) = *C_X2(m);
    sb_fe_mont_mult(C_X2(m), C_T5(m), C_T7(m), curve->p); // x z^2
    *C_T5(m) = *C_Y2(m);
    sb_fe_mont_mult(C_Y2(m), C_T5(m), C_T6(m), curve->p); // y z^3

    state.i = SB_FE_BITS - 1;
    state.stage = SB_SW_POINT_MULT_OP_STAGE_LADDER;

    *MULT_STATE(m) = state;
}
#endif

#define SB_SW_POINT_ITERATIONS 16

// NOT USED
#if !BOOTROM_BUILD
static _Bool
sb_sw_point_mult_continue(sb_sw_context_t m[static const 1],
                          const sb_sw_curve_t curve[static const 1])
{
    sb_sw_context_saved_state_t state = *MULT_STATE(m);

    // (x1 * R^-1, y1 * R^-1) = R0, (x2 * R^-1, y2 * R^-1) = R1
    // R1 - R0 = P' for some Z

    // To show that the ladder is complete for scalars ∉ {-2, -1, 0, 1}, let:
    // P  = p * G
    // R1 = 2 * p * G
    // R0 = p * G
    // It is easy to see that in a prime-order group, neither R1 nor R0 is
    // the point at infinity at the beginning of the algorithm assuming nonzero p.
    // In other words, every point on the curve is a generator.

    // Through the ladder, at the end of each ladder step, we have:
    // R0 = k[256..i] * P
    // R1 = R0 + P
    // where k[256..i] is the 256th through i_th bit of `k` inclusive
    // The beginning of the loop is the end of the first ladder step (i = 256).

    // Each ladder step computes the sum of R0 and R1, and one point doubling.
    // The point doubling formula does not have exceptional cases, so we must
    // consider point additions by zero and inadvertent point doublings.
    // (Additions of -P and P would produce zero, which reduces to the case
    // of addition by zero.) Point doublings do not occur simply because R0 +
    // (R0 + P) is never a doubling operation.

    // R0 = k[256..i] * P is the point at infinity if k[256..i] is zero.
    // k[256] is 1 and N is 256 bits long. Therefore, k[256..i] is nonzero
    // and less than N for all i > 1.
    // It remains to consider the case of k[256..1] = N and
    // k[256..0] = 2N. If k[256..1] is N, then k[256..0] is 2N or 2N + 1.
    // Because the original input scalar was reduced, this only occurs with
    // an input scalar of 0 or 1.

    // R1 = (k[256..i] + 1) * P is zero if k[256..i] + 1 is zero.
    // N is 256 bits long. For i > 1, k[256..i] is at most 255 bits long and therefore
    // less than N - 1. It remains to consider k[256..1] = N - 1 and k[256..0] = 2N - 1.
    // If k[256..1] is N - 1, then k[256..0] is 2N - 2 or 2N - 1.
    // Because the input scalar was reduced, this only occurs with an input
    // scalar of -2 or -1.

    // The following intermediaries are generated:
    // (2 * k[256..i] + 1) * P, P, and -P

    // Because the order of the group is prime, it is easy to see that
    // k[256..i] * P = 0 iff k[256..i] is 0 for nonzero p.
    // What about (2 * k[256..i] + 1) * P?
    // 2 * k[256..i] + 1 must be zero.
    // For i > 2, 2 * k[256..i] is at most 255 bits long and thus
    // less than N - 1. It remains to consider 2 * k[256..2] = N - 1,
    // 2 * k[256..1] = N - 1, and 2 * k[256..0] = N - 1.

    // If 2 * k[256..2] = N - 1, then k[256..2] = (N - 1) / 2.
    // k[256..1] is then N - 1 or N, and k[256..0] is 2N - 2, 2N - 1, N, or N + 1.
    // Thus, this occurs only if k ∈ { -2, -1, 0, 1 }.

    // If 2 * k[256..1] = N - 1, then k[256..1] is (N - 1) / 2.
    // k[256..0] is then N - 1 or N, which only occurs if k ∈ { -1, 0 }.

    // Thus, for reduced inputs ∉ {-2, -1, 0, 1} the Montgomery ladder
    // is non-exceptional for our short Weierstrass curves.

    // Because of the conditional inversion of the scalar at the beginning of
    // this routine, the inputs -2 and -1 are treated as 2 and 1,
    // respectively. As 1 is still an exceptional input, the set of remaining
    // exceptional cases is {-1, 0, 1} mod N. The case of -1 and 1 will be
    // handled after the ladder produces the point at infinity through a
    // series of unconditional additions and constant-time swaps.

    // 14MM + 18A per bit
    // c.f. Table 1 in Rivain 2011 showing 9M + 5S + 18A

    switch (state.stage) {
        case SB_SW_POINT_MULT_OP_STAGE_LADDER: {
            for (sb_bitcount_t ops = 0; state.i > 0 &&
                                        ops < SB_SW_POINT_ITERATIONS;
                 ops++, state.i--) {
                const sb_word_t b = sb_fe_test_bit(MULT_K(m), state.i);

                // if swap is 0: (x2, y2) = R0; (x1, y1) = R1
                // if swap is 1: (x2, y2) = R1; (x1, y1) = R0

                // swap iff bit is set:
                // (x1, y1) = R_b; (x2, y2) = R_{1-b}
                state.swap ^= b;
                sb_fe_ctswap(state.swap, C_X1(m), C_X2(m));
                sb_fe_ctswap(state.swap, C_Y1(m), C_Y2(m));
                state.swap = b;

                // our scalar 'k' is a 257-bit integer
                // R0 = k[256..(i+1)] * P
                // at the beginning of the loop, when i is 255:
                // R0 = k[256..256] * P = 1 * P
                // R1 = R0 + P = (k[256..(i+1)] + 1) * P


                // When k[i] is 0:
                // (x1, y1) = k[256..(i+1)] * P
                // (x2, y2) = (k[256..(i+1)] + 1) * P

                // When k[i] is 1:
                // (x1, y1) = (k[256..(i+1)] + 1) * P
                // (x2, y2) = k[256..(i+1)] * P

                // R_b = R_b + R_{1-b}; R_{1-b} = R_{b} - R{1-b}
                sb_sw_point_co_z_conj_add(m, curve); // 6MM + 7A

                // (x1, y1) = (2 * k[256..(i+1)] + 1 ) * P

                // if k[i] is 0:
                // (x2, y2) = -1 * P

                // if k[i] is 1:
                // (x2, y2) = 1 * P

                // R_b = R_b + R_{1-b}; R_{1-b} = R_b'
                sb_sw_point_co_z_add_update(m, curve); // 8MM + 11A

                // if k[i] is 0:
                // (x1, y1) is 2 * k[256..(i+1)] * P = k[256..i] * P
                // (x2, y2) is (2 * k[256..(i+1)] + 1 ) * P = (k[256..i] + 1) * P

                // if k[i] is 1:
                // (x1, y1) is (2 * k[256..(i+1)] + 2) * P = (k[256..i] + 1) * P
                // (x2, y2) is (2 * k[256..(i+1)] + 1 ) * P = k[256..i] * P

                // R_swap is k[256..i] * P
                // R_!swap is (k[256..i] + 1) * P
            }

            // If the above loop has terminated due to i being equal to zero,
            // move on to the next stage before yielding.
            if (state.i == 0) {
                state.stage = SB_SW_POINT_MULT_OP_STAGE_INV_Z;
            }

            *MULT_STATE(m) = state;
            return 0;
        }
        case SB_SW_POINT_MULT_OP_STAGE_INV_Z: {
            const sb_word_t b = sb_fe_test_bit(MULT_K(m), 0);

            // (x1, y1) = R0; (x2, y2) = R1

            // swap iff bit is set:
            state.swap ^= b;
            sb_fe_ctswap(state.swap, C_X1(m), C_X2(m));
            sb_fe_ctswap(state.swap, C_Y1(m), C_Y2(m));

            // (x1, y1) = R_b; (x2, y2) = R_{1-b}

            // here the logical meaning of the registers swaps!
            sb_sw_point_co_z_conj_add(m, curve);
            // (x1, y1) = R_{1-b}, (x2, y2) = R_b

            // if b is 1, swap the registers
            sb_fe_ctswap(b, C_X1(m), C_X2(m));
            sb_fe_ctswap(b, C_Y1(m), C_Y2(m));
            // (x1, y1) = R1; (x2, y2) = R0

            // Compute final Z^-1
            sb_fe_mod_sub(C_T8(m), C_X1(m), C_X2(m), curve->p); // X1 - X0

            // if b is 1, swap the registers back
            sb_fe_ctswap(b, C_X1(m), C_X2(m));
            sb_fe_ctswap(b, C_Y1(m), C_Y2(m));
            // (x1, y1) = R_{1-b}, (x2, y2) = R_b

            sb_fe_mont_mult(C_T5(m), C_T8(m), C_Y2(m), curve->p);
            // t5 = Y_b * (X_1 - X_0)

            sb_fe_mont_mult(C_T8(m), C_T5(m), MULT_POINT_X(m), curve->p);
            // t8 = t5 * x_P = x_P * Y_b * (X_1 - X_0)

            sb_fe_mod_inv_r(C_T8(m), C_T5(m), C_T6(m), curve->p);
            // t8 = 1 / (x_P * Y_b * (X_1 - X_0))

            sb_fe_mont_mult(C_T5(m), C_T8(m), MULT_POINT_Y(m), curve->p);
            // t5 = yP / (x_P * Y_b * (X_1 - X_0))

            sb_fe_mont_mult(C_T8(m), C_T5(m), C_X2(m), curve->p);
            // t8 = (X_b * y_P) / (x_P * Y_b * (X_1 - X_0))
            // = final Z^-1

            // (x1, y1) = R_{1-b}, (x2, y2) = R_b
            sb_sw_point_co_z_add_update(m, curve);
            // the logical meaning of the registers is reversed
            // (x1, y1) = R_b, (x2, y2) = R_{1-b}

            // if b is 0, swap the registers
            sb_fe_ctswap((b ^ (sb_word_t) 1), C_X1(m), C_X2(m));
            sb_fe_ctswap((b ^ (sb_word_t) 1), C_Y1(m), C_Y2(m));
            // (x1, y1) = R1; (x2, y2) = R0

            // t8 = Z^-1 * R
            // x2 = X0 * Z^2 * R
            // y2 = Y0 * Z^3 * R

            sb_fe_mont_square(C_T5(m), C_T8(m),
                              curve->p); // t5 = Z^-2 * R
            sb_fe_mont_mult(C_T6(m), C_T5(m), C_T8(m),
                            curve->p); // t6 = Z^-3 * R

            // Handle the exceptional cases of multiplies by -1 or 1 here. Because
            // the scalar has not been re-inverted yet, the value of MULT_K(m) will
            // be the scalar 1 if the original input scalar was -1.

            // Because a scalar of 1 produces an exception, the resulting X and Y
            // will be equal to P. Add the original point value to the result X and
            // Y, and swap it into the output X and Y if the scalar is 1.

            // The addition takes place before the Montgomery reduction because the
            // input point is in the Montgomery domain.

            // Apply the recovered Z to produce the X value of the output point, in the
            // Montgomery domain.
            sb_fe_mont_mult(C_T7(m), C_T5(m), C_X2(m),
                            curve->p); // t7 = X0 * Z^-2 * R

            // Add X_P and swap iff the scalar is 1.
            sb_fe_mod_add(C_X2(m), C_T7(m), MULT_POINT_X(m), curve->p);
            // x2 = t7 + x_P
            sb_fe_ctswap(state.k_one, C_T7(m), C_X2(m));

            sb_fe_mont_reduce(C_X1(m), C_T7(m),
                              curve->p); // Montgomery reduce to x1

            // Apply the recovered Z to produce the Y value of the output point, in the
            // Montgomery domain.
            sb_fe_mont_mult(C_T7(m), C_T6(m), C_Y2(m),
                            curve->p); // t7 = Y0 * Z^-3 * R

            // Add Y_P and swap iff the scalar is 1.
            sb_fe_mod_add(C_Y2(m), C_T7(m), MULT_POINT_Y(m), curve->p);
            // y2 = t7 + y_P
            sb_fe_ctswap(state.k_one, C_T7(m), C_Y2(m));

            sb_fe_mont_reduce(C_Y1(m), C_T7(m),
                              curve->p); // Montgomery reduce to y1

            // If the scalar was inverted, invert the output point. On a short
            // Weierstrass curve, -(X, Y) = (X, -Y).
            sb_fe_mod_negate(C_T5(m), C_Y1(m), curve->p);
            sb_fe_ctswap(state.inv_k, C_Y1(m), C_T5(m));

            sb_fe_sub(MULT_K(m), MULT_K(m),
                      &curve->n->p); // subtract off the overflow
            sb_fe_mod_reduce(MULT_K(m),
                             curve->n); // reduce to restore original scalar

            // And finally, if the scalar was inverted, re-invert it to restore the
            // original value.
            sb_fe_mod_negate(C_T5(m), MULT_K(m), curve->n);
            sb_fe_ctswap(state.inv_k, C_T5(m), MULT_K(m));

            // This operation is done.
            state.stage = SB_SW_POINT_MULT_OP_DONE;
            *MULT_STATE(m) = state;
            return 1;
        }
        default: {
            return state.stage == SB_SW_POINT_MULT_OP_DONE;
        }
    }
}
#endif

// NOT USED
#if !BOOTROM_BUILD
// Are we there yet?
static _Bool sb_sw_point_mult_is_finished(sb_sw_context_t m[static const 1])
{
    return MULT_STATE(m)->stage == SB_SW_POINT_MULT_OP_DONE;
}
#endif

// Multiplication-addition using Shamir's trick to produce k_1 * P + k_2 * Q
#if 1 || !SB_FE_ASM
// sb_sw_point_mult_add_z_update computes the new Z and then performs co-Z
// point addition at a cost of 7MM + 7A
static void __attribute__((noipa)) sb_sw_point_mult_add_z_update(sb_sw_context_t q[static const 1],
                                          const sb_sw_curve_t s[static const 1])
{
#if FEATURE_CANARIES
    canary_entry(SB_SW_POINT_MULT_ADD_Z_UPDATE);
#endif
    SB_FE_START(q,s)
    SB_FE_MOD_SUB  (O_C_T6, O_C_X2, O_C_X1, 0)    //  sb_fe_mod_sub  (C_T6(q), C_X2(q), C_X1(q), s->p);   // t6 = x2 - x1 = Z' / Z
    SB_FE_MONT_MULT(O_C_T5, O_C_T6, O_MULT_Z, 0)  //  sb_fe_mont_mult(C_T5(q), C_T6(q), MULT_Z(q), s->p); // updated Z
    SB_FE_MOV(O_MULT_Z,O_C_T5)                    //  *MULT_Z(q) = *C_T5(q);

    // Manually inlined from sb_sw_point_co_z_add_update_zup(q, s);

    SB_FE_MONT_SQUARE(O_C_T5, O_C_T6,         0)  //  sb_fe_mont_square(C_T5(c), C_T6(c), s->p);        // t5 = (x2 - x1)^2 = (Z' / Z)^2 = A
    SB_FE_MONT_MULT  (O_C_T6, O_C_X2, O_C_T5, 0)  //  sb_fe_mont_mult(C_T6(c), C_X2(c), C_T5(c), s->p); // t6 = x2 * A = C
    SB_FE_MONT_MULT  (O_C_X2, O_C_X1, O_C_T5, 0)  //  sb_fe_mont_mult(C_X2(c), C_X1(c), C_T5(c), s->p); // t3 = x1 * A = B = x1'
    SB_FE_MOD_SUB    (O_C_T7, O_C_Y2, O_C_Y1, 0)  //  sb_fe_mod_sub(C_T7(c), C_Y2(c), C_Y1(c), s->p);   // t7 = y2 - y1
    SB_FE_MOD_ADD    (O_C_T5, O_C_X2, O_C_T6, 0)  //  sb_fe_mod_add(C_T5(c), C_X2(c), C_T6(c), s->p);   // t5 = B + C
    SB_FE_MOD_SUB    (O_C_T6, O_C_T6, O_C_X2, 0)  //  sb_fe_mod_sub(C_T6(c), C_T6(c), C_X2(c), s->p);   // t6 = C - B = (x2 - x1)^3 = (Z' / Z)^3
    SB_FE_MONT_MULT  (O_C_Y2, O_C_Y1, O_C_T6, 0)  //  sb_fe_mont_mult(C_Y2(c), C_Y1(c), C_T6(c), s->p); // y1' = y1 * (Z' / Z)^3 = E
    SB_FE_MONT_SQUARE(O_C_X1, O_C_T7,         0)  //  sb_fe_mont_square(C_X1(c), C_T7(c), s->p);        // t1 = (y2 - y1)^2 = D
    SB_FE_MOD_SUB    (O_C_X1, O_C_X1, O_C_T5, 0)  //  sb_fe_mod_sub(C_X1(c), C_X1(c), C_T5(c), s->p);   // x3 = D - B - C
    SB_FE_MOD_SUB    (O_C_T6, O_C_X2, O_C_X1, 0)  //  sb_fe_mod_sub(C_T6(c), C_X2(c), C_X1(c), s->p);   // t6 = B - x3
    SB_FE_MONT_MULT  (O_C_Y1, O_C_T7, O_C_T6, 0)  //  sb_fe_mont_mult(C_Y1(c), C_T7(c), C_T6(c), s->p); // t4 = (y2 - y1) * (B - x3)
    SB_FE_MOD_SUB    (O_C_Y1, O_C_Y1, O_C_Y2, 0)  //  sb_fe_mod_sub(C_Y1(c), C_Y1(c), C_Y2(c), s->p);   // y3 = (y2 - y1) * (B - x3) - E
    SB_FE_STOP

#if FEATURE_CANARIES
    canary_exit_void(SB_SW_POINT_MULT_ADD_Z_UPDATE);
#endif
}
#else
extern void sb_sw_point_mult_add_z_update(sb_sw_context_t q[static const 1],
                                          const sb_sw_curve_t s[static const 1]);

#endif

#if 1 || !SB_FE_ASM
// sb_sw_point_mult_add_apply_z applies a Z value to the selected point
// (H, P + H, G + H, or P + G + H) at a cost of 4MM
static void sb_sw_point_mult_add_apply_z(sb_sw_context_t q[static const 1],
                                         const sb_sw_curve_t s[static const 1])
{
#if FEATURE_CANARIES
    canary_entry(SB_SW_POINT_MULT_ADD_APPLY_Z);
#endif
    SB_FE_START(q,s)
    SB_FE_MONT_SQUARE(O_C_T6, O_MULT_Z,           0)        //  sb_fe_mont_square(C_T6(q), MULT_Z(q), s->p);        // Z^2
    SB_FE_MONT_MULT  (O_C_T7, O_C_X2,   O_C_T6,   0)   //  sb_fe_mont_mult(C_T7(q), C_X2(q), C_T6(q), s->p);
    SB_FE_MOV        (O_C_X2, O_C_T7)                                //  *C_X2(q) = *C_T7(q);
    SB_FE_MONT_MULT  (O_C_T7, O_C_T6,   O_MULT_Z, 0) //  sb_fe_mont_mult(C_T7(q), C_T6(q), MULT_Z(q), s->p); // Z^3
    SB_FE_MONT_MULT  (O_C_T6, O_C_Y2,   O_C_T7,   0)   //  sb_fe_mont_mult(C_T6(q), C_Y2(q), C_T7(q), s->p);
    SB_FE_MOV        (O_C_Y2, O_C_T6)                                //  *C_Y2(q) = *C_T6(q);
    SB_FE_STOP
#if FEATURE_CANARIES
    canary_exit_void(SB_SW_POINT_MULT_ADD_APPLY_Z);
#endif
}
#else
extern void sb_sw_point_mult_add_apply_z(sb_sw_context_t q[static const 1],
                                         const sb_sw_curve_t s[static const 1]);
#endif

#if !SB_FE_ASM
// sb_sw_point_mult_add_select selects the point to conjugate-add to the
// running total based on the bits of the given input scalars
static void sb_sw_point_mult_add_select(const sb_word_t bp, const sb_word_t bg,
                                        sb_sw_context_t q[static const 1],
                                        const sb_sw_curve_t s[static const 1])
{
    // select a point S for conjugate addition with R
    // if bp = 0 and bg = 0, select h
    // if bp = 0 and bg = 1, select g + h
    // if bp = 1 and bg = 0, select p + h
    // if bp = 1 and bg = 1, select p + g + h
    SB_FE_START(q,s);
    SB_FE_MOV_SREL(O_C_X2,O_CURVE_H_R_X);     // *C_X2(q) = s->h_r.x;
    SB_FE_MOV_SREL(O_C_Y2,O_CURVE_H_R_Y);     // *C_Y2(q) = s->h_r.y;
    SB_FE_MOV_SREL(O_C_T5,O_CURVE_G_H_R_X);   // *C_T5(q) = s->g_h_r.x;
    SB_FE_MOV_SREL(O_C_T6,O_CURVE_G_H_R_Y);   // *C_T6(q) = s->g_h_r.y;
    SB_FE_STOP;

    sb_fe_ctswap(bg, C_X2(q), C_T5(q));
    sb_fe_ctswap(bg, C_Y2(q), C_T6(q));

    SB_FE_START(q,s);
    SB_FE_MOV(O_C_T5,O_MULT_POINT_X);   // *C_T5(q) = *MULT_POINT_X(q);
    SB_FE_MOV(O_C_T6,O_MULT_POINT_Y);   // *C_T6(q) = *MULT_POINT_Y(q);
    SB_FE_STOP;

    sb_fe_ctswap(bp, C_X2(q), C_T5(q));
    sb_fe_ctswap(bp, C_Y2(q), C_T6(q));

    SB_FE_START(q,s);
    SB_FE_MOV(O_C_T5,O_MULT_ADD_PG_X);   // *C_T5(q) = *MULT_ADD_PG(q)->x;
    SB_FE_MOV(O_C_T6,O_MULT_ADD_PG_Y);   // *C_T6(q) = *MULT_ADD_PG(q)->y;
    SB_FE_STOP;

    sb_fe_ctswap(bp & bg, C_X2(q), C_T5(q));
    sb_fe_ctswap(bp & bg, C_Y2(q), C_T6(q));

    sb_sw_point_mult_add_apply_z(q, s);
}
#endif

// as above but without the constant time guarantee (but probably close in practice)
static void sb_sw_point_mult_add_select_NOT_CT(const sb_word_t bp, const sb_word_t bg,
                                               sb_sw_context_t q[static const 1],
                                               const sb_sw_curve_t s[static const 1])
{
    // select a point S for conjugate addition with R
    // if bp = 0 and bg = 0, select h
    // if bp = 0 and bg = 1, select g + h
    // if bp = 1 and bg = 0, select p + h
    // if bp = 1 and bg = 1, select p + g + h

    static_assert(O_C_X2+1==O_C_Y2);
    static_assert(O_CURVE_H_R_X+8==O_CURVE_H_R_Y);
    static_assert(O_CURVE_G_H_R_X+8==O_CURVE_G_H_R_Y);
    static_assert(O_MULT_POINT_X+1==O_MULT_POINT_Y);
    static_assert(O_MULT_ADD_PG_X+1==O_MULT_ADD_PG_Y);

    const sb_fe_pair_t*p;

    if(!bp) {
      if(!bg) p=&s->h_r;
      else    p=&s->g_h_r;
    } else {
      if(!bg) p=(sb_fe_pair_t*)MULT_POINT_X(q);
      else    p=(sb_fe_pair_t*)&MULT_ADD_PG(q)->x;
      }
    sb_fe_mov_pair(C_X2(q),&p->x);

    sb_sw_point_mult_add_apply_z(q, s);
}

// Signature verification uses a regular double-and-add algorithm with Shamir's
// trick for dual scalar-basepoint multiplication. Because adding O (the
// point at infinity) is an exceptional case in the standard formulae for
// point addition on short Weierstrass curves, each iteration adds an
// additional point H. The initial value of the point accumulator register is H,
// and at the end of the loop, (2^257 - 1) * H has been added, producing
// k_p * P + k_g * G + (2^257 - 1) * H. To correct for this, one could
// subtract the extra multiple of H at the end of the algorithm, but instead
// H has been chosen so that we can easily adjust k_g before the
// multiplication instead. Let H be (2^257 - 1)^-1 * G. Then compute:
//   k_p * P + (k_g - 1) * G + (2^257 - 1) * H
// = k_p * P + (k_g - 1) * G + (2^257 - 1) * (2^257 - 1)^-1 * G
// = k_p * P + (k_g - 1) * G + G
// = k_p * P + k_g * G

// The algorithm is as follows:

// Given inputs k_p, P, k_g on some curve with base point G, and let H as
// above, with G + H precomputed

// 1. Compute P + H and P + G + H

// Let S(b_p, b_g) be:         H if b_p == 0 && b_g == 0
//                         P + H if b_p == 1 && b_g == 0
//                         G + H if b_p == 0 && b_g == 1
//                     P + G + H if b_p == 1 && b_g == 1

// 2. k_g := k_g - 1
// 3. R := H
// 4. R := 2 * R
// 5. R := R + S(k_p_255, k_g_255)
// 6. for i from 254 downto 0:
//    6.1. R' := R + S(k_p_i, k_g_i)
//    6.2. R  := R + R'
// 7. return R

// Note that this algorithm is NOT exception-free! It is assumed that
// exceptions do not matter in practice here, because they occur only in one
// of the following situations:

// P = +/- H
// P = +/- G
// P = +/- (G + H)
// k_g[255 .. n] * G + (2^257 - 1)[255 .. n] * H = +/- k_p[255 .. n] * P

// It's possible to express any of these equivalences in the following form:

// p * G = P for some p

// In other words, exceptions during signature verification imply that the
// private key of the message signer can be deduced with simple algebra.
// While it might be preferable to have a signature verification algorithm
// that can correctly verify such signatures, in this case it would
// complicate the implementation greatly. Furthermore, it could also be
// argued that refusing to verify such signatures is, in fact, the preferable
// choice, as any signature created with this private key might be forged.

// USED
// Produces kp * P + kg * G in (x1, y1) with Z * R in Z
static void sb_sw_point_mult_add_z_continue
    (sb_sw_context_t q[static const 1],
     const sb_sw_curve_t s[static const 1])
{
// SB_SW_VERIFY_OP_STAGE_INV_Z: // ==1

    // Subtract one from kg to account for the addition of (2^257 - 1) * H = G

    // multiply (x, y) of P by R
    SB_FE_START(q,s)
    SB_FE_MOV_CONST(O_C_T8,1)
    SB_FE_MOD_SUB(O_MULT_ADD_KG,O_MULT_ADD_KG,O_C_T8,0)// sb_fe_sub(MULT_ADD_KG(q), MULT_ADD_KG(q), &SB_FE_ONE);
    SB_FE_MONT_CONVERT(O_C_X1,O_MULT_POINT_X,0)        // sb_fe_mont_convert(C_X1(q), MULT_POINT_X(q), s->p);
    SB_FE_MOV(O_MULT_POINT_X,O_C_X1)                   // *MULT_POINT_X(q) = *C_X1(q);
    SB_FE_MONT_CONVERT(O_C_Y1,O_MULT_POINT_Y,0)        // sb_fe_mont_convert(C_Y1(q), MULT_POINT_Y(q), s->p);
    SB_FE_MOV(O_MULT_POINT_Y,O_C_Y1)                   // *MULT_POINT_Y(q) = *C_Y1(q);
    SB_FE_MOV(O_C_T8,O_MULT_Z)                         // *C_T8(q) = *MULT_Z(q); // Save initial Z in T8 until it can be applied
    SB_FE_MOV_SREL(O_C_X2,O_CURVE_H_R_X)               // *C_X2(q) = s->h_r.x;
    SB_FE_MOV_SREL(O_C_Y2,O_CURVE_H_R_Y)               // *C_Y2(q) = s->h_r.y;
    SB_FE_STOP

    // P and H are in affine coordinates, so our current Z is one (R in
    // Montgomery domain)
    sb_fe_mov(MULT_Z(q),&__get_opaque_ptr(s)->p->r_mod_p); //  *MULT_Z(q) = s->p->r_mod_p;

    // (x1, x2) = P + H; (x2, y2) = P'
    sb_sw_point_mult_add_z_update(q, s);

    // Apply Z to G before co-Z addition of (P + H) and G
    SB_FE_START(q,s)
    SB_FE_MOV_SREL(O_C_X2,O_CURVE_G_R_X)  // *C_X2(q) = s->g_r.x;
    SB_FE_MOV_SREL(O_C_Y2,O_CURVE_G_R_Y)  // *C_Y2(q) = s->g_r.y;
    SB_FE_STOP
    sb_sw_point_mult_add_apply_z(q, s);

    // (x1, x2) = P + G + H; (x2, y2) = P + H
    sb_sw_point_mult_add_z_update(q, s);

    // Invert Z and multiply so that P + H and P + G + H are in affine
    // coordinates
    SB_FE_START(q,s)
    SB_FE_MOV(O_C_T5,O_MULT_Z)                           // *C_T5(q) = *MULT_Z(q); // t5 = Z * R
    SB_FE_MOD_INV_R(O_C_T5,O_C_T6,O_C_T7,0)              // sb_fe_mod_inv_r(C_T5(q), C_T6(q), C_T7(q), s->p); // t5 = Z^-1 * R
    SB_FE_MONT_SQUARE(O_C_T6,O_C_T5,0)                   // sb_fe_mont_square(C_T6(q), C_T5(q), s->p); // t6 = Z^-2 * R
    SB_FE_MONT_MULT  (O_C_T7,O_C_T5,O_C_T6,0)            // sb_fe_mont_mult(C_T7(q), C_T5(q), C_T6(q), s->p); // t7 = Z^-3 * R
    SB_FE_MONT_MULT  (O_MULT_POINT_X,O_C_X2,O_C_T6,0)    // sb_fe_mont_mult(MULT_POINT_X(q), C_X2(q), C_T6(q), s->p); // Apply Z to P + H
    SB_FE_MONT_MULT  (O_MULT_POINT_Y,O_C_Y2,O_C_T7,0)    // sb_fe_mont_mult(MULT_POINT_Y(q), C_Y2(q), C_T7(q), s->p);
    SB_FE_MONT_MULT  (O_MULT_ADD_PG_X,O_C_X1,O_C_T6,0)   // sb_fe_mont_mult(&MULT_ADD_PG(q)->x, C_X1(q), C_T6(q), s->p); // Apply Z to P + G + H
    SB_FE_MONT_MULT  (O_MULT_ADD_PG_Y,O_C_Y1,O_C_T7,0)   // sb_fe_mont_mult(&MULT_ADD_PG(q)->y, C_Y1(q), C_T7(q), s->p);

    // Computation begins with R = H. If bit 255 of kp and kpg are both 0,
    // this would lead to a point doubling!
    // Avoid the inadvertent doubling in the first bit, so that the regular
    // ladder can start at 2 * H + S

    SB_FE_MOV_SREL(O_C_X2,O_CURVE_H_R_X) // *C_X2(q) = s->h_r.x;
    SB_FE_MOV_SREL(O_C_Y2,O_CURVE_H_R_Y) // *C_Y2(q) = s->h_r.y;

// manually inlined from sb_sw_point_initial_double(q, s);
    SB_FE_MOD_DOUBLE(O_C_T5,O_C_Y2,0)                 // sb_fe_mod_double(C_T5(c), C_Y2(c), s->p); // t5 = Z
    SB_FE_MONT_SQUARE(O_C_Y1,O_C_X2,0)                // sb_fe_mont_square(C_Y1(c), C_X2(c), s->p); // t2 = x^2
// in the SECP526K1 curva a_r is zero, so we can skip this operation
#if SB_SW_P256_SUPPORT
    SB_FE_STOP
    sb_fe_mod_sub(C_Y1(q), C_Y1(q), s->minus_a_r_over_three, s->p); // t2 = x^2 + a / 3
    SB_FE_START(q,s)
#endif
    SB_FE_MOD_DOUBLE(O_C_X1, O_C_Y1, 0)        // sb_fe_mod_double(C_X1(c), C_Y1(c), s->p);          // t1 = 2 * (x^2 + a / 3)
    SB_FE_MOD_ADD(O_C_Y1, O_C_Y1, O_C_X1, 0)   // sb_fe_mod_add(C_Y1(c), C_Y1(c), C_X1(c), s->p);    // t2 = (3 * x^2 + a) = B

    SB_FE_MONT_SQUARE(O_C_T6, O_C_Y2, 0)       // sb_fe_mont_square(C_T6(c), C_Y2(c), s->p);         // t6 = y^2
    SB_FE_MOD_DOUBLE(O_C_Y2, O_C_T6, 0)        // sb_fe_mod_double(C_Y2(c), C_T6(c), s->p);          // t4 = 2 * y^2
    SB_FE_MOD_DOUBLE(O_C_T6, O_C_Y2, 0)        // sb_fe_mod_double(C_T6(c), C_Y2(c), s->p);          // t6 = 4 * y^2
    SB_FE_MONT_MULT(O_C_X1, O_C_X2, O_C_T6, 0) // sb_fe_mont_mult(C_X1(c), C_X2(c), C_T6(c), s->p);  // t1 = 4 * x * y^2 = A

    SB_FE_MONT_SQUARE(O_C_X2, O_C_Y1, 0)       // sb_fe_mont_square(C_X2(c), C_Y1(c), s->p);         // t3 = B^2

    SB_FE_MOD_SUB(O_C_X2, O_C_X2, O_C_X1, 0)   // sb_fe_mod_sub(C_X2(c), C_X2(c), C_X1(c), s->p);    // t2 = B^2 - A
    SB_FE_MOD_SUB(O_C_X2, O_C_X2, O_C_X1, 0)   // sb_fe_mod_sub(C_X2(c), C_X2(c), C_X1(c), s->p);    // x2 = B^2 - 2 * A = X2

    SB_FE_MOD_SUB(O_C_T6, O_C_X1, O_C_X2, 0)   // sb_fe_mod_sub(C_T6(c), C_X1(c), C_X2(c), s->p);    // t6 = A - X2
    SB_FE_MONT_MULT(O_C_T7, O_C_Y1, O_C_T6, 0) // sb_fe_mont_mult(C_T7(c), C_Y1(c), C_T6(c), s->p);  // t7 = B * (A - X2)

    SB_FE_MONT_SQUARE(O_C_Y1, O_C_Y2, 0)       // sb_fe_mont_square(C_Y1(c), C_Y2(c), s->p);         // t2 = (2 * y^2)^2 = 4 * y^4
    SB_FE_MOD_DOUBLE(O_C_Y1, O_C_Y1, 0)        // sb_fe_mod_double(C_Y1(c), C_Y1(c), s->p);          // Y1 = 8 * y^4 = Z^3 * y
    SB_FE_MOD_SUB(O_C_Y2, O_C_T7, O_C_Y1, 0)   // sb_fe_mod_sub(C_Y2(c), C_T7(c), C_Y1(c), s->p);    // Y2 = B * (A - X2) - Y1

    // 2 * H is now in (x2, y2); Z is in t5

    // apply initial Z
    SB_FE_MOV(O_MULT_Z,O_C_T8) // *MULT_Z(q) = *C_T8(q);
    SB_FE_STOP
    sb_sw_point_mult_add_apply_z(q, s);

    // z coordinate of (x2, y2) is now iz * t5
    SB_FE_START(q,s)
    SB_FE_MONT_MULT(O_C_T6,O_MULT_Z,O_C_T5,0)         // sb_fe_mont_mult(C_T6(q), MULT_Z(q), C_T5(q), s->p);
    SB_FE_MOV(O_MULT_Z,O_C_T6)                        // *MULT_Z(q) = *C_T6(q);
    SB_FE_MOV(O_C_X1,O_C_X2)                          // *C_X1(q) = *C_X2(q); // move 2 * H to (x1, y1)
    SB_FE_MOV(O_C_Y1,O_C_Y2)                          // *C_Y1(q) = *C_Y2(q);
    SB_FE_STOP

    // SB_SW_VERIFY_OP_STAGE_LADDER:
    // 14MM + 14A + 4MM co-Z update = 18MM + 14A per bit

    // The algorithm used here is regular and reuses the existing co-Z addition
    // operation. If you want a variable-time ladder, consider using
    // Algorithms 14 and 17 from Rivain 2011 instead.

    // Note that mixed Jacobian-affine doubling-addition can be done in 18MM.
    // Assuming a Hamming weight of ~128 on both scalars and 8MM doubling, the
    // expected performance of a variable-time Jacobian double-and-add
    // implementation would be (3/4 * 18MM) + (1/4 * 8MM) = 15.5MM/bit

    // Note that this algorithm may also not be SPA- or DPA-resistant, as H,
    // P + H, G + H, and P + G + H are stored and used in affine coordinates,
    // so the co-Z update of these variables might be detectable even with
    // Z blinding.

    // This loop goes from 255 down to 0, inclusive. When state.i
    // reaches 0 and is decremented, it wraps around to the most
    // positive sb_size_t, which is greater than or equal to SB_FE_BITS
    // (by quite a lot!).

    for ( int i=SB_FE_BITS - 1 ; i>=0; i-- ) {
        const sb_word_t bp = sb_fe_test_bit(MULT_K(q), (unsigned int)i);
        const sb_word_t bg = sb_fe_test_bit(MULT_ADD_KG(q), (unsigned int)i);

        sb_sw_point_mult_add_select_NOT_CT(bp, bg, q, s);

        // (x1, y1) = (R + S), (x2, y2) = R'
        sb_sw_point_mult_add_z_update(q, s);

        // The initial point has already been doubled
        if (i < SB_FE_BITS - 1) {
            // R := (R + S) + R = 2 * R + S
            sb_sw_point_mult_add_z_update(q, s);
        }
    }


    SB_FE_START(q,s)
    SB_FE_MOV(O_C_T6,O_C_X1)                                   // *C_T6(q) = *C_X1(q);
    SB_FE_MOV(O_C_T7,O_C_Y1)                                   // *C_T6(q) = *C_Y1(q);
    SB_FE_MOV_CONST(O_C_T8,1)
    SB_FE_MONT_MULT(O_C_X1,O_C_T6,O_C_T8,0)                    // sb_fe_mont_reduce(C_X1(q), C_T6(q), s->p); : this is the same as mont_mult by SB_FE_ONE
    SB_FE_MONT_MULT(O_C_Y1,O_C_T7,O_C_T8,0)                    // sb_fe_mont_reduce(C_Y1(q), C_T7(q), s->p); : this is the same as mont_mult by SB_FE_ONE
    SB_FE_STOP
}

// // Given a point context with x in *C_X1(c), computes
// // y^2 = x^3 + a * x + b in *C_Y1(c)
// static inline void sb_sw_curve_y2(sb_sw_context_t c[static const 1],
//                            const sb_sw_curve_t s[static const 1])
// {
// #if SB_SW_P256_SUPPORT
//       sb_fe_mont_convert(C_T5(c), C_X1(c), s->p); // t5 = x * R
//       sb_fe_mont_mult(C_T6(c), C_T5(c), C_X1(c), s->p);   // t6 = x^2
//       sb_fe_mod_sub(C_T6(c), C_T6(c), &s->minus_a, s->p); // t6 = x^2 + a
//       sb_fe_mont_mult(C_Y1(c), C_T5(c), C_T6(c), s->p);       // sb_fe_mont_mult(C_Y1(c), C_T5(c), C_T6(c), s->p);   // y1 = (x^2 + a) * x * R * R^-1 = x^3 + a * x
//       sb_fe_mod_add  (C_Y1(c), C_Y1(c), &s->b, s->p);           // sb_fe_mod_add(C_Y1(c), C_Y1(c), &s->b, s->p);       // y1 = y^2 = x^3 + a * x + b
// #endif
// }

// See SP 800-56A rev 3, section 5.6.2.3.4
// Note that the "full" test in 5.6.2.3.3 and the "partial" test in 5.6.2.3.4
// are equivalent on prime-order curves, since every point on the curve
// satisfies nQ = 0. The NSA's "Suite B Implementer's Guide to FIPS 186-3"
// document says as much in A.3.

// As implemented, all tests are performed regardless of whether any one test
// fails; in other words, tests are not short-circuited. This reduces the
// number of possible execution traces of the input.

// Note that this assumes reduced input, not quasi-reduced input! Special
// points of the form (0, Y) will be converted to quasi-reduced form in this
// routine.

static sb_bool_t
sb_sw_point_validate(sb_sw_context_t c[static const 1],
                     const sb_sw_curve_t s[static const 1])
{
    // 5.6.2.3.4 step 1: the point at infinity is not valid.
    // The only point with (X, 0) is the point at infinity. On the curve
    // P-256, the point (0, ±√B) is a valid point. The input point
    // representation (X, P) will be rejected by the step 2 test.
    SB_RETURN_FALSE_IF_NOT_CHECKED(SB_FE_HARD_NEQZ(&MULT_POINT(c)->y));  // if(SB_FE_EQ(&MULT_POINT(c)->y, &SB_FE_ZERO)) r=0;  // r &= !sb_fe_equal(&MULT_POINT(c)->y, &SB_FE_ZERO);

    // 5.6.2.3.4 step 2: unreduced points are not valid.
    // r &= (sb_fe_lt(&MULT_POINT(c)->x, &s->p->p) &&
    //       sb_fe_lt(&MULT_POINT(c)->y, &s->p->p));
    sb_bool_t v0 = SB_FE_HARD_LO(&MULT_POINT(c)->x, &s->p->p);
    sb_bool_t v1 = SB_FE_HARD_LO(&MULT_POINT(c)->y, &s->p->p);
    SB_RETURN_FALSE_IF_NOT(v0);
    SB_RETURN_FALSE_IF_NOT(v1);
    SB_FE_ASSERT_AND_TRUE(v0, v1);

#if SB_SW_SECP256K1_SUPPORT 
    if(s==&SB_CURVE_SECP256K1) {
#else
    if(0) {
#endif    
      // Valid Y values are now ensured to be quasi-reduced. Invalid Y values
      // have been flagged above, but must be quasi-reduced for the remainder
      // of the checks.
      SB_FE_START(c,s)
      SB_FE_MOD_REDUCE(O_MULT_POINT_Y,0) // sb_fe_mod_reduce(&MULT_POINT(c)->y, s->p);

      // If the input point has the form (0, Y) then the X value may be zero.
      // The modular quasi-reduction routine will change this to (P, Y).
      SB_FE_MOD_REDUCE(O_MULT_POINT_X,0) // sb_fe_mod_reduce(&MULT_POINT(c)->x, s->p);

      // 5.6.2.3.4 step 3: verify y^2 = x^3 + ax + b
      SB_FE_MONT_SQUARE(O_C_T5,O_MULT_POINT_Y,0)    // sb_fe_mont_square(C_T5(c), &MULT_POINT(c)->y, s->p); // t5 = y^2 * R^-1
      SB_FE_MONT_CONVERT(O_C_Y2,O_C_T5,0)           // sb_fe_mont_convert(C_Y2(c), C_T5(c), s->p); // y2 = y^2
      SB_FE_MOV(O_C_X1,O_MULT_POINT_X)              // *C_X1(c) = MULT_POINT(c)->x;

    // manually inlined from sb_sw_curve_y2(c, s);
      SB_FE_MONT_CONVERT(O_C_T5,O_C_X1,0)           // sb_fe_mont_convert(C_T5(c), C_X1(c), s->p); // t5 = x * R
      SB_FE_MONT_MULT   (O_C_T6,O_C_T5,O_C_X1, 0)   // sb_fe_mont_mult(C_T6(c), C_T5(c), C_X1(c), s->p);   // t6 = x^2
// in the SECP256K1 case a is zero in this case so we can skip these two lines
//      SB_FE_MOV_SREL    (O_C_T7,O_CURVE_MINUS_A)    // *C_T7(c)=s->minus_a;
//      SB_FE_MOD_SUB     (O_C_T6,O_C_T6,O_C_T7,0)    // sb_fe_mod_sub  (C_T6(c), C_T6(c), C_T7(c), s->p); // t6 = x^2 + a
      SB_FE_MONT_MULT   (O_C_Y1,O_C_T5,O_C_T6,0)    // sb_fe_mont_mult(C_Y1(c), C_T5(c), C_T6(c), s->p);   // y1 = (x^2 + a) * x * R * R^-1 = x^3 + a * x
      // SB_FE_MOV_SREL    (O_C_T5,O_CURVE_B)
      SB_FE_MOV_CONST   (O_C_T5,7)
      SB_FE_MOD_ADD     (O_C_Y1,O_C_Y1,O_C_T5,0)    // sb_fe_mod_add(C_Y1(c), C_Y1(c), &s->b, s->p);       // y1 = y^2 = x^3 + a * x + b ; b is 7 in this case
      SB_FE_STOP
    } else {

      // we do not use this path as we only implement CURVE_SECP256K1, but keep it for the regression tests

      // Valid Y values are now ensured to be quasi-reduced. Invalid Y values
      // have been flagged above, but must be quasi-reduced for the remainder
      // of the checks.
      SB_FE_START(c,s)
      SB_FE_MOD_REDUCE(O_MULT_POINT_Y,0) // sb_fe_mod_reduce(&MULT_POINT(c)->y, s->p);

      // If the input point has the form (0, Y) then the X value may be zero.
      // The modular quasi-reduction routine will change this to (P, Y).
      SB_FE_MOD_REDUCE(O_MULT_POINT_X,0) // sb_fe_mod_reduce(&MULT_POINT(c)->x, s->p);

      // 5.6.2.3.4 step 3: verify y^2 = x^3 + ax + b
      SB_FE_MONT_SQUARE(O_C_T5,O_MULT_POINT_Y,0) // sb_fe_mont_square(C_T5(c), &MULT_POINT(c)->y, s->p); // t5 = y^2 * R^-1
      SB_FE_MONT_CONVERT(O_C_Y2,O_C_T5,0) // sb_fe_mont_convert(C_Y2(c), C_T5(c), s->p); // y2 = y^2
      SB_FE_MOV(O_C_X1,O_MULT_POINT_X)     // *C_X1(c) = MULT_POINT(c)->x;
      SB_FE_STOP

      sb_fe_mont_convert(C_T5(c), C_X1(c), s->p); // t5 = x * R
      sb_fe_mont_mult(C_T6(c), C_T5(c), C_X1(c), s->p);   // t6 = x^2
#if SB_SW_P256_SUPPORT
      sb_fe_mod_sub(C_T6(c), C_T6(c), &s->minus_a, s->p); // t6 = x^2 + a
#endif
      sb_fe_mont_mult(C_Y1(c), C_T5(c), C_T6(c), s->p);       // sb_fe_mont_mult(C_Y1(c), C_T5(c), C_T6(c), s->p);   // y1 = (x^2 + a) * x * R * R^-1 = x^3 + a * x
#if SB_SW_P256_SUPPORT
    sb_fe_mod_add  (C_Y1(c), C_Y1(c), &s->b, s->p);           // sb_fe_mod_add(C_Y1(c), C_Y1(c), &s->b, s->p);       // y1 = y^2 = x^3 + a * x + b
#else
    sb_fe_mod_add  (C_Y1(c), C_Y1(c), &secp256k1_b, s->p);           // sb_fe_mod_add(C_Y1(c), C_Y1(c), &s->b, s->p);       // y1 = y^2 = x^3 + a * x + b
#endif
      }

      return SB_FE_HARD_EQ(C_Y1(c), C_Y2(c));
}

#if !BOOTROM_BUILD
static sb_word_t
sb_sw_point_decompress(sb_sw_context_t c[static const 1],
                       const sb_word_t sign,
                       const sb_sw_curve_t s[static const 1])
{
    /* First validate the X coordinate of the point. */
    sb_word_t r = 1;

    // 5.6.2.3.4 step 2: unreduced points are not valid.
    r &= SB_FE_LO(&MULT_POINT(c)->x, &s->p->p);

    // The input X value may be 0 on some curves (such as NIST P-256).
    // The modular quasi-reduction routine will change this to P.
    sb_fe_mod_reduce(&MULT_POINT(c)->x, s->p);

    // Compute y^2 = x^3 + ax + b in C_Y1(c)
    *C_X1(c) = MULT_POINT(c)->x;
    sb_fe_mont_convert(C_T5(c), C_X1(c), s->p); // t5 = x * R
    sb_fe_mont_mult(C_T6(c), C_T5(c), C_X1(c), s->p);   // t6 = x^2
#if SB_SW_P256_SUPPORT
    sb_fe_mod_sub(C_T6(c), C_T6(c), &s->minus_a, s->p); // t6 = x^2 + a ; a is zero in the SECP256K1 case
#endif
    sb_fe_mont_mult(C_Y1(c), C_T5(c), C_T6(c), s->p);       // sb_fe_mont_mult(C_Y1(c), C_T5(c), C_T6(c), s->p);   // y1 = (x^2 + a) * x * R * R^-1 = x^3 + a * x
#if SB_SW_P256_SUPPORT
    sb_fe_mod_add  (C_Y1(c), C_Y1(c), &s->b, s->p);           // sb_fe_mod_add(C_Y1(c), C_Y1(c), &s->b, s->p);       // y1 = y^2 = x^3 + a * x + b
#else
    sb_fe_mod_add  (C_Y1(c), C_Y1(c), &secp256k1_b, s->p);           // sb_fe_mod_add(C_Y1(c), C_Y1(c), &s->b, s->p);       // y1 = y^2 = x^3 + a * x + b
#endif

    // Compute the candidate square root
    r &= sb_fe_mod_sqrt(C_Y1(c), C_T5(c), C_T6(c), C_T7(c), C_T8(c), s->p);

    // If the "sign" bit does not match, invert the candidate square root
    const sb_word_t sign_mismatch = sb_fe_test_bit(C_Y1(c), 1) ^sign;
    sb_fe_mod_negate(C_T5(c), C_Y1(c), s->p);
    sb_fe_ctswap(sign_mismatch, C_Y1(c), C_T5(c));

    MULT_POINT(c)->y = *C_Y1(c);

    return r;
}
#endif

#if !SB_FE_ASM
// common subexpression
static sb_bool_t sb_sw_zscalar_validate(sb_fe_t k[static const 1],
                      const sb_fe_t right[static 1])
{
    sb_word_t r = 1;

    r &= SB_FE_LT(k, right); // k < n
    sb_fe_mod_reduce(k, right); // after reduction, 0 is represented as n
    r &= !SB_FE_EQ(k, right); // k != 0

    return r;
}
#else
extern sb_bool_t sb_sw_zscalar_validate(sb_fe_t k[static const 1],
                      const sb_fe_t right[static 1]);
#endif
// A scalar is valid if it is reduced and not equal to zero mod N.
static sb_bool_t
sb_sw_scalar_validate(sb_fe_t k[static const 1],
                      const sb_sw_curve_t s[static const 1])
{
  /*  sb_word_t r = 1;

    r &= sb_fe_lt(k, &s->n->p); // k < n
    sb_fe_mod_reduce(k, s->n); // after reduction, 0 is represented as n
    r &= !sb_fe_equal(k, &s->n->p); // k != 0
    return r;
*/
    return sb_sw_zscalar_validate(k, &s->n->p);
}

// A z-coordinate is valid if it is reduced and not equal to zero mod P.
static sb_bool_t
sb_sw_z_validate(sb_fe_t z[static const 1],
                 const sb_sw_curve_t s[static const 1])
{
/*
    sb_word_t r = 1;

    r &= sb_fe_lt(z, &s->p->p); // k < p
    sb_fe_mod_reduce(z, s->p); // after reduction, 0 is represented as p
    r &= !sb_fe_equal(z, &s->p->p); // k != 0
    return r;
*/
    return sb_sw_zscalar_validate(z, &s->p->p);
}

// NOT USED
#if !BOOTROM_BUILD
static void
sb_sw_sign_start(sb_sw_context_t g[static const 1],
                 const sb_sw_curve_t s[static const 1])
{
    *MULT_POINT(g) = s->g_r;

    *MULT_STATE(g) = (sb_sw_context_saved_state_t) {
        .operation = SB_SW_INCREMENTAL_OPERATION_SIGN_MESSAGE_DIGEST,
        .curve_id = sb_sw_id_from_curve(s)
    };

    sb_sw_point_mult_start(g, s);
}
#endif

#if !BOOTROM_BUILD
static _Bool sb_sw_sign_is_finished(sb_sw_context_t g[static const 1])
{
    return MULT_STATE(g)->stage == SB_SW_SIGN_OP_STAGE_DONE;
}
#endif

// NOT USED
#if !BOOTROM_BUILD
// Places (r, s) into (x2, y2) when finished
static sb_error_t
sb_sw_sign_continue(sb_sw_context_t g[static const 1],
                    const sb_sw_curve_t s[static const 1],
                    _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;

    switch (MULT_STATE(g)->stage) {
        case SB_SW_SIGN_OP_STAGE_DONE: {
            *done = 1;
            return SB_SUCCESS;
        }
        case SB_SW_SIGN_OP_STAGE_INV: {
            sb_sw_context_saved_state_t state = *MULT_STATE(g);

            // This is used to quasi-reduce x1 modulo the curve N:
            *C_X2(g) = *C_X1(g);
            sb_fe_mod_reduce(C_X2(g), s->n);

            // If the ladder has produced (0, ±√B), then signing can't continue
            // and this is indicative of a DRBG failure.
            err |= SB_ERROR_IF(DRBG_FAILURE, SB_FE_EQ(C_X2(g), &s->n->p));

            sb_fe_mont_convert(C_T7(g), MULT_K(g), s->n); // t7 = k * R
            sb_fe_mod_inv_r(C_T7(g), C_T5(g), C_T6(g), s->n); // t7 = k^-1 * R
            sb_fe_mont_convert(C_T6(g), SIGN_PRIVATE(g), s->n); // t6 = d_A * R
            sb_fe_mont_mult(C_T5(g), C_X2(g), C_T6(g), s->n); // t5 = r * d_A
            sb_fe_mod_add(C_T5(g), C_T5(g), SIGN_MESSAGE(g),
                          s->n); // t5 = z + r * d_A
            sb_fe_mont_mult(C_Y2(g), C_T5(g), C_T7(g),
                            s->n); // y2 = k^-1 * R * (z + r * d_A) * R^-1 mod N

            // mont_mul produces quasi-reduced output, so 0 is represented as N.
            // If signing has produced a signature with an S value of 0, this
            // indicates DRBG failure (again) and the signature is invalid.
            err |= SB_ERROR_IF(DRBG_FAILURE, SB_FE_EQ(C_Y2(g), &s->n->p));

            state.stage = SB_SW_SIGN_OP_STAGE_DONE;
            *MULT_STATE(g) = state;
            *done = 1;
            return err;
        }
        default: {
            sb_sw_point_mult_continue(g, s);
            *done = 0;
            return SB_SUCCESS; // it's not done until the signing inversion is done
        }
    }
}
#endif

// NOT USED (inlined)
#if 0
static int sb_sw_verify_continue_and_finish(sb_sw_context_t v[static const 1],
                                   const sb_sw_curve_t s[static const 1])
{
// SB_SW_VERIFY_OP_STAGE_INV_S:
    // A signature with either r or s as 0 or N is invalid;
    // see `sb_test_invalid_sig` for a unit test of this
    // check.
    if(!sb_sw_scalar_validate(VERIFY_QR(v), s)) goto err;      // state.res &= sb_sw_scalar_validate(VERIFY_QR(v), s);
    if(!sb_sw_scalar_validate(VERIFY_QS(v), s)) goto err;      // state.res &= sb_sw_scalar_validate(VERIFY_QS(v), s);

    SB_FE_START(v,s)
    SB_FE_MOD_REDUCE  (O_VERIFY_MESSAGE,1)                    // sb_fe_mod_reduce(VERIFY_MESSAGE(v), s->n);
    SB_FE_MONT_CONVERT(O_C_T5,O_VERIFY_QS,1)                  // sb_fe_mont_convert(C_T5(v), VERIFY_QS(v), s->n); // t5 = s * R
    SB_FE_MOD_INV_R   (O_C_T5,O_C_T6,O_C_T7,1)                // sb_fe_mod_inv_r(C_T5(v), C_T6(v), C_T7(v), s->n); // t5 = s^-1 * R
    SB_FE_MOV         (O_C_T6,O_VERIFY_MESSAGE)               // *C_T6(v) = *VERIFY_MESSAGE(v);
    SB_FE_MONT_MULT   (O_MULT_ADD_KG,O_C_T6,O_C_T5,1)         // sb_fe_mont_mult(MULT_ADD_KG(v), C_T6(v), C_T5(v), s->n); // k_G = m * s^-1
    SB_FE_MONT_MULT   (O_MULT_K,O_VERIFY_QR,O_C_T5,1)         // sb_fe_mont_mult(MULT_K(v), VERIFY_QR(v), C_T5(v), s->n); // k_P = r * s^-1
    SB_FE_STOP

    // A message of zero is also invalid.
    if(SB_FE_EQ(VERIFY_MESSAGE(v), &s->n->p)) goto err;     // state.res &= !sb_fe_equal(VERIFY_MESSAGE(v), &s->n->p);

// SB_SW_VERIFY_OP_STAGE_INV_Z, SB_SW_VERIFY_OP_STAGE_LADDER:
    sb_sw_point_mult_add_z_continue(v, s);
// SB_SW_VERIFY_OP_STAGE_TEST:
    // This happens when p is some multiple of g that occurs within
    // the ladder, such that additions inadvertently produce a point
    // doubling. When that occurs, the private scalar that generated p is
    // also obvious, so this is bad news. Don't do this.
    if(SB_FE_EQ(C_X1(v), &s->p->p) & SB_FE_EQ(C_Y1(v), &s->p->p)) goto err; // state.res &= !(sb_fe_equal(C_X1(v), &s->p->p) & sb_fe_equal(C_Y1(v), &s->p->p));

    // qr ==? x mod N, but we don't have x, just x * z^2
    // Given that qr is reduced mod N, if it is >= P - N, then it can be used
    // directly. If it is < P - N, then we need to try to see if the original
    // value was qr or qr + N.

    // Try directly first:
    SB_FE_START(v,s)
    SB_FE_MONT_SQUARE(O_C_T6,O_MULT_Z,0)                                 // sb_fe_mont_square(C_T6(v), MULT_Z(v), s->p); // t6 = Z^2 * R
    SB_FE_MONT_MULT  (O_C_T7,O_VERIFY_QR,O_C_T6,0)                       // sb_fe_mont_mult(C_T7(v), VERIFY_QR(v), C_T6(v), s->p); // t7 = r * Z^2
    SB_FE_STOP
    if(SB_FE_EQ(C_T7(v), C_X1(v))) {
        rc = sb_ok_true();
        goto done;                        // ver |= sb_fe_equal(C_T7(v), C_X1(v));
    }

    // If that didn't work, and qr < P - N, then we need to compare
    // (qr + N) * z^2 against x * z^2

    // If qr = P - N, then we do not compare against (qr + N),
    // because qr + N would be equal to P, and the X component of the
    // point is thus zero and should have been rejected.

    // See the small_r_signature tests, which generate signatures
    // where this path is tested.

    sb_fe_mod_add(C_T5(v), VERIFY_QR(v), &s->n->p, s->p); // t5 = (N + r)

    SB_FE_START(v,s)
    SB_FE_MONT_MULT(O_C_T7,O_C_T5,O_C_T6,0)     // sb_fe_mont_mult(C_T7(v), C_T5(v), C_T6(v), s->p);     // t7 = (N + r) * Z^2
    SB_FE_STOP

    sb_fe_sub(C_T5(v), &s->p->p, &s->n->p);               // t5 = P - N

    // if((sb_fe_lt(VERIFY_QR(v), C_T5(v)) & // r < P - N
    //          sb_fe_equal(C_T7(v), C_X1(v)))) goto sig_ok; // t7 == x
    if((SB_FE_LO(VERIFY_QR(v), C_T5(v)) && SB_FE_EQ(C_T7(v), C_X1(v)))) {
        rc = sb_ok_true();
        goto done;   // ver |= (sb_fe_lt(VERIFY_QR(v), C_T5(v)) & // r < P - N
    }
err:
    rc = sb_ok_false();
done:
#if 0 && FEATURE_CANARIES
    canary_exit_return(SB_SW_VERIFY_CONTINUE_AND_FINISH, rc);
#else
    return rc;
#endif
}
#endif

// USED
// Generate a Z from SB_SW_FIPS186_4_CANDIDATES worth of DRBG-produced data
// in c->param_gen.buf. Note that this tests a fixed number of candidates, and
// if it succeeds, there is no bias in the generated Z values.
static sb_hard_error_t sb_sw_z_from_buf(sb_sw_context_t ctx[static const 1],
                                   const sb_sw_curve_t s[static const 1])
{
    sb_fe_from_bytes(MULT_Z(ctx), ctx->param_gen.buf);

    for (sb_size_t i = 1; i < SB_SW_FIPS186_4_CANDIDATES; i++) {
        /* Is the current candidate valid? */
        const sb_bool_t zv = sb_sw_z_validate(MULT_Z(ctx), s);

        /* Generate another candidate. */
        sb_fe_from_bytes(MULT_Z2(ctx),
                         &ctx->param_gen.buf[i * SB_ELEM_BYTES]);

        /* If the current candidate is invalid, swap in the new candidate. */
        if (SB_FE_IS_FALSE(zv)) {
            sb_fe_mov(MULT_Z(ctx), MULT_Z2(ctx)); // sb_fe_ctswap((sb_word_t) (zv ^ SB_UWORD_C(1)), MULT_Z(ctx), MULT_Z2(ctx));
        } else {
            SB_FE_ASSERT_TRUE(zv);
        }
    }

    /* If this loop has not created a valid candidate, it means that the DRBG
     * has produced outputs with extremely low probability. */
    return SB_ERROR_IF_NOT(DRBG_FAILURE, sb_sw_z_validate(MULT_Z(ctx), s));
}

// Initial Z generation for Z blinding (Coron's third countermeasure)
static sb_hard_error_t sb_sw_generate_z(sb_sw_context_t c[static const 1],
                                   sb_hmac_drbg_state_t* const drbg,
                                   const sb_sw_curve_t s[static const 1],
                                   const sb_byte_t* const d1, const size_t l1,
                                   const sb_byte_t* const d2, const size_t l2,
                                   const sb_byte_t* const d3, const size_t l3,
                                   const sb_byte_t* const label,
                                   const size_t label_len)
{
#if !BOOTROM_BUILD
    sb_error_t err = SB_SUCCESS;
#endif

    if (drbg) {
#if !BOOTROM_BUILD
        // Use the supplied data as additional input to the DRBG
        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            d1, d2, d3, label
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            l1, l2, l3, label_len
        };

        err |= sb_hmac_drbg_generate_additional_vec(drbg,
                                                    c->param_gen.buf,
                                                    SB_SW_FIPS186_4_CANDIDATES *
                                                    SB_ELEM_BYTES,
                                                    add, add_len);
        // It is a bug if this ever fails; the DRBG reseed count should have
        // been checked already, and the DRBG limits should allow these inputs.
        SB_ASSERT(!err, "Z generation should never fail.");
#endif
    } else {
        // Initialize the HKDF with the input supplied
        sb_hkdf_extract_init(&c->param_gen.hkdf, NULL, 0);

        if (l1) sb_hkdf_extract_update(&c->param_gen.hkdf, d1, l1);
        if (l2) sb_hkdf_extract_update(&c->param_gen.hkdf, d2, l2);
        if (l3) sb_hkdf_extract_update(&c->param_gen.hkdf, d3, l3);

        sb_hkdf_extract_finish(&c->param_gen.hkdf);

        sb_hkdf_expand(&c->param_gen.hkdf, label, label_len,
                       c->param_gen.buf,
                       SB_SW_FIPS186_4_CANDIDATES * SB_ELEM_BYTES);
    }

#if BOOTROM_BUILD
    // we didn't take the drbg path above, so can't have an error from above
    bootrom_assert(SWEETB, !drbg);
    // Place the generated Z in MULT_Z(c) and validate it.
    return sb_sw_z_from_buf(c, s);
#else

    // Place the generated Z in MULT_Z(c) and validate it.
    err |= SB_ERROR_FROM_HARD_ERROR(sb_sw_z_from_buf(c, s), DRBG_FAILURE);

    return SB_HARD_ERROR_FROM_ERROR(err);
#endif
}

// Generate a private key from pseudo-random data filled in buf. The
// fips186_4 parameter controls whether 1 is added to candidate values; this
// should be true unless this function is being used for RFC6979 per-message
// secret generation.
#if !BOOTROM_BUILD
static sb_error_t sb_sw_k_from_buf(sb_sw_context_t ctx[static const 1],
                                   const _Bool fips186_4,
                                   const sb_sw_curve_t* const s,
                                   __unused sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Generate the initial candidate.
    sb_fe_from_bytes(MULT_K(ctx), ctx->param_gen.buf);

    if (fips186_4) {
        // per FIPS 186-4 B.4.2: d = c + 1
        // if this overflows, the value was invalid to begin with, and the
        // resulting value is all zeros, which is also invalid.
        sb_fe_add(MULT_K(ctx), MULT_K(ctx), &SB_FE_ONE);
    }

    for (sb_size_t i = 1; i < SB_SW_FIPS186_4_CANDIDATES; i++) {
        /* Is the current candidate valid? */
        sb_word_t kv = SB_WORD_FROM_BOOL(sb_sw_scalar_validate(MULT_K(ctx), s));

        /* Test another candidate. */
        sb_fe_from_bytes(MULT_Z(ctx),
                         &ctx->param_gen.buf[i * SB_ELEM_BYTES]);

        if (fips186_4) {
            /* d = c + 1 */
            sb_fe_add(MULT_Z(ctx), MULT_Z(ctx), &SB_FE_ONE);
        }

        /* If the current candidate is invalid, swap in the new candidate. */
        sb_fe_ctswap((sb_word_t) (kv ^ SB_UWORD_C(1)), MULT_K(ctx),
                     MULT_Z(ctx));
    }

    /* If this loop has not created a valid candidate, it means that the DRBG
     * has produced outputs with extremely low probability. */
    err |= SB_ERROR_IF(DRBG_FAILURE, !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(MULT_K(ctx), s)));

    return err;
}
#endif
//// PUBLIC API:

#if !BOOTROM_BUILD
/// FIPS 186-4-style private key generation. Note that this tests a fixed
/// number of candidates.
sb_error_t sb_sw_generate_private_key(sb_sw_context_t ctx[static const 1],
                                      sb_sw_private_t private[static const 1],
                                      sb_hmac_drbg_state_t drbg[static const 1],
                                      sb_sw_curve_id_t const curve,
                                      sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(private);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Avoid modifying the input drbg state if a generate call will fail.
    // It takes SB_SW_FIPS186_4_CANDIDATES generate calls to generate a private
    // key. Note that separate calls to the generate function are used per
    // FIPS 186-4 B.4.2, which specifies an iterative process involving
    // multiple calls to the generate function. When compiled for testing
    // (SB_TEST), it is possible to force the DRBG to generate an all-1s bit
    // pattern for a certain number of generate calls, which also allows
    // verification that the correct number of candidates are tested.
    err |= sb_hmac_drbg_reseed_required(drbg, SB_SW_FIPS186_4_CANDIDATES);

    SB_RETURN_ERRORS(err, ctx);

    for (sb_size_t i = 0; i < SB_SW_FIPS186_4_CANDIDATES; i++) {
        err |= sb_hmac_drbg_generate_additional_dummy
            (drbg, &ctx->param_gen.buf[i * SB_ELEM_BYTES], SB_ELEM_BYTES);
        SB_ASSERT(!err, "Private key generation should never fail.");
    }

    SB_RETURN_ERRORS(err, ctx);

    /* Test and select a candidate from the filled buffer. */
    err |= sb_sw_k_from_buf(ctx, 1, s, e);

    sb_fe_to_bytes(private->bytes, MULT_K(ctx));

    SB_RETURN(err, ctx);
}
#endif

// Private key generation from HKDF expansion.
#if !BOOTROM_BUILD
sb_error_t sb_sw_hkdf_expand_private_key(sb_sw_context_t ctx[static const 1],
                                         sb_sw_private_t private[static const 1],
                                         sb_hkdf_state_t hkdf[static const 1],
                                         const sb_byte_t* const restrict info,
                                         size_t const info_len,
                                         sb_sw_curve_id_t const curve,
                                         sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(private);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the curve is invalid.
    SB_RETURN_ERRORS(err, ctx);

    /* Generate SB_SW_FIPS186_4_CANDIDATES values to test by expanding the
     * given HKDF instance with the given info. */
    sb_hkdf_expand(hkdf, info, info_len, ctx->param_gen.buf,
                   SB_SW_FIPS186_4_CANDIDATES * SB_ELEM_BYTES);

    /* Test and select a candidate from the filled buffer. */
    err |= sb_sw_k_from_buf(ctx, 1, s, e);

    sb_fe_to_bytes(private->bytes, MULT_K(ctx));

    SB_RETURN(err, ctx);
}
#endif

// Helper function for sb_sw_invert_private_key and
// sb_sw_composite_sign_wrap_message_digest.
// Performs a modular inversion of a field element stored in C_X1 using a
// generated blinding factor stored in MULT_K in the montgomery domain and
// stores the result in C_T6. Assumes that curve and field element have both
// already been validated.
#if !BOOTROM_BUILD
static void sb_sw_invert_field_element
                 (sb_sw_context_t ctx[static const 1],
                  const sb_sw_curve_t* s)
{
    /* Perform the scalar inversion. */

    // X1 = blinding factor * R
    sb_fe_mont_convert(C_X1(ctx), MULT_K(ctx), s->n);

    // Y1 = scalar * R
    sb_fe_mont_convert(C_Y1(ctx), MULT_Z(ctx), s->n);

    // T5 = blinding factor * scalar * R
    sb_fe_mont_mult(C_T5(ctx), C_X1(ctx), C_Y1(ctx), s->n);

    // T5 = (blinding factor * scalar)^-1 * R
    sb_fe_mod_inv_r(C_T5(ctx), C_T6(ctx), C_T7(ctx), s->n);

    // T6 = (blinding factor * scalar)^-1 * blinding factor * R
    //    = scalar^-1 * R
    sb_fe_mont_mult(C_T6(ctx), C_T5(ctx), C_X1(ctx), s->n);
}
#endif

#if !BOOTROM_BUILD
sb_error_t sb_sw_invert_private_key(sb_sw_context_t ctx[static const 1],
                                    sb_sw_private_t output[static const 1],
                                    const sb_sw_private_t private[static const 1],
                                    sb_hmac_drbg_state_t* drbg,
                                    sb_sw_curve_id_t const curve,
                                    sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(output);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    /* Scalar inversion blinding factor generation is done in one generate
     * call to the DRBG. */
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    // Bail out early if the curve is invalid or the DRBG needs to be reseeded.
    SB_RETURN_ERRORS(err, ctx);

    /* Generate a random scalar to use as part of blinding. */
    if (drbg != NULL) {
        /* The private key is supplied as additional input to the DRBG in
         * order to mitigate DRBG failure. */

        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            private->bytes
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            SB_ELEM_BYTES
        };

        err |= sb_hmac_drbg_generate_additional_vec(drbg,
                                                    ctx->param_gen.buf,
                                                    SB_SW_FIPS186_4_CANDIDATES *
                                                    SB_ELEM_BYTES,
                                                    add, add_len);
        SB_ASSERT(!err, "Scalar blinding factor generation should never fail.");
    } else {
        sb_hkdf_extract(&ctx->param_gen.hkdf, NULL, 0,
                        private->bytes, SB_ELEM_BYTES);

        const sb_byte_t label[] = "sb_sw_invert_private_key";
        sb_hkdf_expand(&ctx->param_gen.hkdf,
                       label, sizeof(label),
                       ctx->param_gen.buf,
                       SB_SW_FIPS186_4_CANDIDATES * SB_ELEM_BYTES);
    }

    /* Test and select a candidate from the filled buffer. */
    err |= sb_sw_k_from_buf(ctx, 1, s, e);

    /* At this point a possibly-invalid candidate is in MULT_K(ctx). */
    /* Check the supplied private key now. */

    sb_fe_from_bytes(MULT_Z(ctx), private->bytes);
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(MULT_Z(ctx), s)));

    /* Bail out if the private key is invalid or if blinding factor
     * generation failed. */
    SB_RETURN_ERRORS(err, ctx);

    // T6 = scalar^-1 * R
    sb_sw_invert_field_element(ctx, s);

    // T5 = scalar^-1
    sb_fe_mont_reduce(C_T5(ctx), C_T6(ctx), s->n);

    sb_fe_to_bytes(output->bytes, C_T5(ctx));

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_compute_public_key_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     __unused const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context.
    SB_NULLIFY(ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    // Return invalid-curve and DRBG errors immediately.
    SB_RETURN_ERRORS(err, ctx);

    // Generate a Z for projective coordinate randomization.
    static const sb_byte_t label[] = "sb_sw_compute_public_key";
    err |= SB_ERROR_FROM_HARD_ERROR(sb_sw_generate_z(ctx, drbg, s, private->bytes, SB_ELEM_BYTES,
                            NULL, 0, NULL, 0, label, sizeof(label)), DRBG_FAILURE);

    // Validate the private key before performing any operations.

    sb_fe_from_bytes(MULT_K(ctx), private->bytes);
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(MULT_K(ctx), s)));

    // Return DRBG failure and invalid private key errors before performing
    // the point multiplication.
    SB_RETURN_ERRORS(err, ctx);

    *MULT_POINT(ctx) = s->g_r;

    *MULT_STATE(ctx) =
        (sb_sw_context_saved_state_t) {
            .operation = SB_SW_INCREMENTAL_OPERATION_COMPUTE_PUBLIC_KEY,
            .curve_id = sb_sw_id_from_curve(s)
        };

    sb_sw_point_mult_start(ctx, s);

    return err;
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_compute_public_key_continue
    (sb_sw_context_t ctx[static const 1],
     _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_COMPUTE_PUBLIC_KEY);

    SB_RETURN_ERRORS(err, ctx);

    const sb_sw_curve_t* curve = NULL;
    err |= sb_sw_curve_from_id(&curve, MULT_STATE(ctx)->curve_id);
    SB_RETURN_ERRORS(err, ctx);

    *done = sb_sw_point_mult_continue(ctx, curve);

    return err;
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_compute_public_key_finish
    (sb_sw_context_t ctx[static const 1],
     sb_sw_public_t public[static const 1],
     __unused const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the output before doing context validity checks.
    SB_NULLIFY(public);

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_COMPUTE_PUBLIC_KEY);

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(NOT_FINISHED, !sb_sw_point_mult_is_finished(ctx));

    SB_RETURN_ERRORS(err, ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, MULT_STATE(ctx)->curve_id);
    SB_RETURN_ERRORS(err, ctx);

    // The output is quasi-reduced, so the point at infinity is (p, p).
    // This should never occur with valid scalars.
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       (SB_FE_EQ(C_X1(ctx), &s->p->p) &
                        SB_FE_EQ(C_Y1(ctx), &s->p->p)));
    SB_ASSERT(!err, "Montgomery ladder produced the point at infinity from a "
                    "valid scalar.");

    sb_fe_to_bytes(public->bytes, C_X1(ctx));
    sb_fe_to_bytes(public->bytes + SB_ELEM_BYTES, C_Y1(ctx));

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_compute_public_key(sb_sw_context_t ctx[static const 1],
                                    sb_sw_public_t public[static const 1],
                                    const sb_sw_private_t private[static const 1],
                                    sb_hmac_drbg_state_t* const drbg,
                                    const sb_sw_curve_id_t curve,
                                    const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    err |= sb_sw_compute_public_key_start(ctx, private, drbg, curve, e);
    SB_RETURN_ERRORS(err, ctx);

    _Bool done;
    do {
        err |= sb_sw_compute_public_key_continue(ctx, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    err |= sb_sw_compute_public_key_finish(ctx, public, e);

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_valid_private_key(sb_sw_context_t ctx[static const 1],
                                   const sb_sw_private_t private[static const 1],
                                   const sb_sw_curve_id_t curve,
                                   __unused const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    SB_NULLIFY(ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_from_bytes(MULT_K(ctx), private->bytes);

    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(MULT_K(ctx), s)));

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_valid_public_key(sb_sw_context_t ctx[static const 1],
                                  const sb_sw_public_t public[static const 1],
                                  const sb_sw_curve_id_t curve,
                                  __unused const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    SB_NULLIFY(ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_from_bytes(MULT_POINT_X(ctx), public->bytes);
    sb_fe_from_bytes(MULT_POINT_Y(ctx), public->bytes + SB_ELEM_BYTES);

    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID, !SB_WORD_FROM_BOOL(sb_sw_point_validate(ctx, s)));

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_compress_public_key(sb_sw_context_t ctx[static const 1],
                                     sb_sw_compressed_t compressed[static const 1],
                                     _Bool sign[static const 1],
                                     const sb_sw_public_t public[static const 1],
                                     sb_sw_curve_id_t curve,
                                     __unused sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(compressed);
    SB_NULLIFY(sign);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_from_bytes(MULT_POINT_X(ctx), public->bytes);
    sb_fe_from_bytes(MULT_POINT_Y(ctx), public->bytes + SB_ELEM_BYTES);

    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID, !SB_WORD_FROM_BOOL(sb_sw_point_validate(ctx, s)));

    SB_RETURN_ERRORS(err, ctx);

    // Copy the X value to the compressed output.
    memcpy(compressed->bytes, public->bytes, SB_ELEM_BYTES);

    // The "sign" bit is the low order bit of the Y value.
    const sb_word_t sign_w = sb_fe_test_bit(MULT_POINT_Y(ctx), 1);
    *sign = (_Bool) sign_w;

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_decompress_public_key
    (sb_sw_context_t ctx[static const 1],
     sb_sw_public_t public[static const 1],
     const sb_sw_compressed_t compressed[static const 1],
     _Bool sign,
     sb_sw_curve_id_t curve,
     __unused sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(public);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_from_bytes(MULT_POINT_X(ctx), compressed->bytes);
    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID,
                       !sb_sw_point_decompress(ctx, (sb_word_t) sign, s));
    SB_RETURN_ERRORS(err, ctx);

    sb_fe_to_bytes(public->bytes, MULT_POINT_X(ctx));
    sb_fe_to_bytes(public->bytes + SB_ELEM_BYTES, MULT_POINT_Y(ctx));

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
static sb_error_t sb_sw_multiply_shared_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_public_t public[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     __unused const sb_data_endian_t e,
     const sb_sw_incremental_operation_t op)
{
    sb_error_t err = SB_SUCCESS;

    // The context has already been nullified.

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    SB_RETURN_ERRORS(err, ctx);

    // Only the X coordinate of the public key is used as the nonce, since
    // the Y coordinate is not an independent input.
    static const sb_byte_t label[] = "sb_sw_multiply_shared";
    err |= SB_ERROR_FROM_HARD_ERROR(sb_sw_generate_z(ctx, drbg, s, private->bytes, SB_ELEM_BYTES,
                            public->bytes, SB_ELEM_BYTES,
                            NULL, 0, label, sizeof(label)), DRBG_FAILURE);

    sb_fe_from_bytes(MULT_K(ctx), private->bytes);

    sb_fe_from_bytes(MULT_POINT_X(ctx), public->bytes);
    sb_fe_from_bytes(MULT_POINT_Y(ctx), public->bytes + SB_ELEM_BYTES);

    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(MULT_K(ctx), s)));
    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID, !SB_WORD_FROM_BOOL(sb_sw_point_validate(ctx, s)));

    // Return early if the supplied public key does not represent a point on
    // the given curve.
    SB_RETURN_ERRORS(err, ctx);

    // Pre-multiply the point's x and y by R

    *C_X1(ctx) = *MULT_POINT_X(ctx);
    *C_Y1(ctx) = *MULT_POINT_Y(ctx);

    sb_fe_mont_convert(MULT_POINT_X(ctx), C_X1(ctx), s->p);
    sb_fe_mont_convert(MULT_POINT_Y(ctx), C_Y1(ctx), s->p);

    *MULT_STATE(ctx) = (sb_sw_context_saved_state_t) {
        .operation = op,
        .curve_id = sb_sw_id_from_curve(s)
    };

    sb_sw_point_mult_start(ctx, s);

    return err;
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_shared_secret_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_public_t public[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context.
    SB_NULLIFY(ctx);

    err |= sb_sw_multiply_shared_start(ctx, private, public, drbg, curve, e,
                                       SB_SW_INCREMENTAL_OPERATION_SHARED_SECRET);

    return err;
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_shared_secret_continue
    (sb_sw_context_t ctx[static const 1],
     _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* curve = NULL;

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_SHARED_SECRET);

    err |= sb_sw_curve_from_id(&curve, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    *done = sb_sw_point_mult_continue(ctx, curve);

    return err;
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_shared_secret_finish(sb_sw_context_t ctx[static const 1],
                                      sb_sw_shared_secret_t secret[static const 1],
                                      __unused const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* s = NULL;

    // Nullify the output before doing context validity checks.
    SB_NULLIFY(secret);

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_SHARED_SECRET);

    err |= sb_sw_curve_from_id(&s, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(NOT_FINISHED, !sb_sw_point_mult_is_finished(ctx));

    SB_RETURN_ERRORS(err, ctx);

    // This should never occur with a valid private scalar.
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       (SB_FE_EQ(C_X1(ctx), &s->p->p) &
                        SB_FE_EQ(C_Y1(ctx), &s->p->p)));
    SB_ASSERT(!err, "Montgomery ladder produced the point at infinity from a "
                    "valid scalar.");


    sb_fe_to_bytes(secret->bytes, C_X1(ctx));

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_shared_secret(sb_sw_context_t ctx[static const 1],
                               sb_sw_shared_secret_t secret[static const 1],
                               const sb_sw_private_t private[static const 1],
                               const sb_sw_public_t public[static const 1],
                               sb_hmac_drbg_state_t* const drbg,
                               const sb_sw_curve_id_t curve,
                               const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    err |= sb_sw_shared_secret_start(ctx, private, public, drbg, curve, e);
    SB_RETURN_ERRORS(err, ctx);

    _Bool done;
    do {
        err |= sb_sw_shared_secret_continue(ctx, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    err |= sb_sw_shared_secret_finish(ctx, secret, e);

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_point_multiply_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_public_t public[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context.
    SB_NULLIFY(ctx);

    err |= sb_sw_multiply_shared_start(ctx, private, public, drbg, curve, e,
                                       SB_SW_INCREMENTAL_OPERATION_POINT_MULTIPLY);

    return err;
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_point_multiply_continue
    (sb_sw_context_t ctx[static const 1],
     _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* s = NULL;

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_POINT_MULTIPLY);

    err |= sb_sw_curve_from_id(&s, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    *done = sb_sw_point_mult_continue(ctx, s);

    return err;
}
#endif
// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_point_multiply_finish(sb_sw_context_t ctx[static const 1],
                                       sb_sw_public_t output[static const 1],
                                       __unused const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* s = NULL;

    // Nullify the output before doing context validity checks.
    SB_NULLIFY(output);

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_POINT_MULTIPLY);

    err |= sb_sw_curve_from_id(&s, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(NOT_FINISHED, !sb_sw_point_mult_is_finished(ctx));

    SB_RETURN_ERRORS(err, ctx);

    // This should never occur with a valid private scalar.
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       (SB_FE_EQ(C_X1(ctx), &s->p->p) &
                        SB_FE_EQ(C_Y1(ctx), &s->p->p)));
    SB_ASSERT(!err, "Montgomery ladder produced the point at infinity from a "
                    "valid scalar.");

    sb_fe_to_bytes(output->bytes, C_X1(ctx));
    sb_fe_to_bytes(output->bytes + SB_ELEM_BYTES, C_Y1(ctx));

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_point_multiply(sb_sw_context_t ctx[static const 1],
                                sb_sw_public_t output[static const 1],
                                const sb_sw_private_t private[static const 1],
                                const sb_sw_public_t public[static const 1],
                                sb_hmac_drbg_state_t* const drbg,
                                const sb_sw_curve_id_t curve,
                                const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    err |= sb_sw_point_multiply_start(ctx, private, public, drbg, curve, e);
    SB_RETURN_ERRORS(err, ctx);

    _Bool done;
    do {
        err |= sb_sw_point_multiply_continue(ctx, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    err |= sb_sw_point_multiply_finish(ctx, output, e);

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
// Shared message-signing logic; used for normal signing and known-answer test
// cases where the per-message secret is supplied. Assumes that the
// per-message secret and random Z value have already been generated in the
// supplied context.
static sb_error_t sb_sw_sign_message_digest_shared_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     const sb_sw_curve_t s[static const 1],
     __unused const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Validate the private scalar and message.

    sb_fe_from_bytes(SIGN_PRIVATE(ctx), private->bytes);
    sb_fe_from_bytes(SIGN_MESSAGE(ctx), message->bytes);

    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(SIGN_PRIVATE(ctx), s)));

    // Reduce the message modulo N
    sb_fe_mod_reduce(SIGN_MESSAGE(ctx), s->n);

    // Return errors before performing the signature operation.
    SB_RETURN_ERRORS(err, ctx);

    sb_sw_sign_start(ctx, s);

    return err;
}
#endif

#ifdef SB_TEST

// This is an EXTREMELY dangerous method and is not exposed in the public
// header. Do not under any circumstances call this function unless you are
// running NIST CAVP tests.

// NOT USED
sb_error_t sb_sw_sign_message_digest_with_k_beware_of_the_leopard
    (sb_sw_context_t ctx[static const 1],
     sb_sw_signature_t signature[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     const sb_sw_private_t k[static const 1],
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(signature);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Return early if the supplied curve is invalid.
    SB_RETURN_ERRORS(err, ctx);

    // was: sb_fe_from_bytes(MULT_K(ctx), k->bytes, SB_ELEM_BYTES); but surely last parameter is endianity?!
    sb_fe_from_bytes(MULT_K(ctx), k->bytes);

    // Validate the supplied scalar.
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(MULT_K(ctx), s)));

    // Generate a Z value for blinding.
    static const sb_byte_t label[] =
        "sb_sw_sign_message_digest_with_k_beware_of_the_leopard";

    err |= SB_ERROR_FROM_HARD_ERROR(sb_sw_generate_z(ctx, NULL, s, private->bytes, SB_ELEM_BYTES,
                            message->bytes, SB_ELEM_BYTES, NULL, 0, label,
                            sizeof(label)), DRBG_FAILURE);

    // Return if the supplied scalar is invalid or Z generation failed.
    SB_RETURN_ERRORS(err, ctx);

    sb_sw_sign_message_digest_shared_start(ctx, private, message, s, e);

    _Bool done;
    do {
        err |= sb_sw_sign_continue(ctx, s, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    sb_fe_to_bytes(signature->bytes, C_X2(ctx));
    sb_fe_to_bytes(signature->bytes + SB_ELEM_BYTES, C_Y2(ctx));

    SB_RETURN(err, ctx);

}

#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_sign_message_digest_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     sb_hmac_drbg_state_t* const provided_drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context.
    SB_NULLIFY(ctx);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    // It takes SB_SW_FIPS186_4_CANDIDATES calls to generate a per-message
    // secret and one to generate an initial Z
    if (provided_drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(provided_drbg,
                                            SB_SW_FIPS186_4_CANDIDATES + 1);
    }

    SB_RETURN_ERRORS(err, ctx);

    // If a DRBG is provided, FIPS186-4 mode is used. Otherwise, RFC6979
    // deterministic signature generation is used.
    const _Bool fips186_4 = (provided_drbg != NULL);

    // A convenient alias for the actual DRBG being used.
    sb_hmac_drbg_state_t* const drbg =
        (provided_drbg ? provided_drbg : &ctx->param_gen.drbg);

    if (fips186_4) {
        // FIPS 186-4-style per-message secret generation:
        // The private key and message are used (in native endianness) as
        // additional input to the DRBG in order to prevent catastrophic
        // entropy failure.

        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            private->bytes, message->bytes
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            SB_ELEM_BYTES, SB_ELEM_BYTES
        };

        err |= sb_hmac_drbg_generate_additional_vec(provided_drbg,
                                                    &ctx->param_gen.buf[0],
                                                    SB_ELEM_BYTES, add,
                                                    add_len);

        // Provide additional input on each subsequent call in order to
        // ensure backtracking resistance in the DRBG.
        for (sb_size_t i = 1; i < SB_SW_FIPS186_4_CANDIDATES; i++) {
            err |= sb_hmac_drbg_generate_additional_dummy
                (drbg,
                 &ctx->param_gen.buf[i * SB_ELEM_BYTES],
                 SB_ELEM_BYTES);
            SB_ASSERT(!err, "The DRBG should never fail to generate a "
                            "per-message secret.");
        }
    } else {
        // RFC6979 deterministic signature generation requires the scalar and
        // reduced message to be input to the DRBG in big-endian form.
        sb_fe_from_bytes(MULT_K(ctx), private->bytes);
        sb_fe_from_bytes(MULT_Z(ctx), message->bytes);

        // Reduce the message modulo N. Unreduced scalars will be tested later.
        sb_fe_mod_reduce(MULT_Z(ctx), s->n);

        // Convert the private scalar and reduced message back into a
        // big-endian byte string
        sb_fe_to_bytes(&ctx->param_gen.buf[0], MULT_K(ctx));
        sb_fe_to_bytes(&ctx->param_gen.buf[SB_ELEM_BYTES], MULT_Z(ctx));

        err |=
            sb_hmac_drbg_init(&ctx->param_gen.drbg,
                              &ctx->param_gen.buf[0], SB_ELEM_BYTES,
                              &ctx->param_gen.buf[SB_ELEM_BYTES],
                              SB_ELEM_BYTES,
                              NULL,
                              0);
        SB_ASSERT(!err, "DRBG initialization should never fail.");

        // This call to sb_hmac_drbg_generate can't be replaced by a call to
        // sb_hmac_drbg_generate_additional_dummy as it would break
        // compatibility with RFC6979 (and its test vectors).
        for (sb_size_t i = 0; i < SB_SW_FIPS186_4_CANDIDATES; i++) {
            err |= sb_hmac_drbg_generate(drbg,
                                         &ctx->param_gen.buf[i * SB_ELEM_BYTES],
                                         SB_ELEM_BYTES);
            SB_ASSERT(!err, "The DRBG should never fail to generate a "
                            "per-message secret.");
        }
    }

    err |= sb_sw_k_from_buf(ctx, fips186_4, s, e);

    // If the DRBG has failed (produced SB_SW_FIPS186_4_CANDIDATES bad
    // candidates in a row), bail out early.
    SB_RETURN_ERRORS(err, ctx);

    // And now generate an initial Z. This uses the DRBG directly instead of
    // calling sb_sw_generate_z because the private key and message digest
    // have already been supplied as input to the DRBG. Dummy additional
    // input is provided instead in order to ensure backtracking resistance
    // of the DRBG.
    err |= sb_hmac_drbg_generate_additional_dummy(drbg,
                                                  ctx->param_gen.buf,
                                                  4 * SB_ELEM_BYTES);
    SB_ASSERT(!err, "The DRBG should never fail to generate a Z value.");

    if (!fips186_4) {
        // Nullify the RFC6979 DRBG before returning the context.
        SB_NULLIFY(&ctx->param_gen.drbg);
    }

    err |= SB_ERROR_FROM_HARD_ERROR(sb_sw_z_from_buf(ctx, s), DRBG_FAILURE);

    // If the DRBG has failed again, bail out early.
    SB_RETURN_ERRORS(err, ctx);

    // Now that per-message secret and random Z values have been generated,
    // start the message signing.
    return sb_sw_sign_message_digest_shared_start(ctx, private, message, s, e);
}
#endif

// Implemented in sb_sha256.c for sha256 message verification.
extern void
sb_sha256_finish_to_buffer(sb_sha256_state_t sha[static restrict 1]);

// NOT USED
#if !BOOTROM_BUILD
#if !SB_USE_RP2350_SHA256 // no sb_sha256_finish_to_buffer
sb_error_t sb_sw_sign_message_sha256_start
    (sb_sw_context_t ctx[static const 1],
     sb_sha256_state_t sha[static const 1],
     const sb_sw_private_t private[static const 1],
     sb_hmac_drbg_state_t* const provided_drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_sha256_finish_to_buffer(sha);

    // This egregious cast works because sb_sw_message_digest_t is just a struct
    // wrapper for a bunch of bytes.
    const sb_sw_message_digest_t* const digest =
        (const sb_sw_message_digest_t*) (sha->buffer);

    return sb_sw_sign_message_digest_start(ctx, private, digest,
                                           provided_drbg, curve, e);
}
#endif
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_sign_message_digest_continue
    (sb_sw_context_t ctx[static const 1],
     _Bool done[static const 1])
{
    sb_error_t err = SB_SUCCESS;
    const sb_sw_curve_t* curve = NULL;

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_SIGN_MESSAGE_DIGEST);

    err |= sb_sw_curve_from_id(&curve, MULT_STATE(ctx)->curve_id);

    SB_RETURN_ERRORS(err, ctx);

    err |= sb_sw_sign_continue(ctx, curve, done);
    SB_RETURN_ERRORS(err, ctx);

    return err;
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_sign_message_digest_finish
    (sb_sw_context_t ctx[static const 1],
     sb_sw_signature_t signature[static const 1],
     __unused const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the output before doing context validity checks.
    SB_NULLIFY(signature);

    err |= SB_ERROR_IF(INCORRECT_OPERATION,
                       MULT_STATE(ctx)->operation !=
                       SB_SW_INCREMENTAL_OPERATION_SIGN_MESSAGE_DIGEST);

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(NOT_FINISHED, !sb_sw_sign_is_finished(ctx));

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_to_bytes(signature->bytes, C_X2(ctx));
    sb_fe_to_bytes(signature->bytes + SB_ELEM_BYTES, C_Y2(ctx));

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_sign_message_digest
    (sb_sw_context_t ctx[static const 1],
     sb_sw_signature_t signature[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     sb_hmac_drbg_state_t* const provided_drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    err |= sb_sw_sign_message_digest_start(ctx, private, message,
                                           provided_drbg, curve, e);
    SB_RETURN_ERRORS(err, ctx);

    _Bool done;
    do {
        err |= sb_sw_sign_message_digest_continue(ctx, &done);
        SB_RETURN_ERRORS(err, ctx);
    } while (!done);

    err |= sb_sw_sign_message_digest_finish(ctx, signature, e);

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_sign_message_sha256
    (sb_sw_context_t ctx[static const 1],
     sb_sw_message_digest_t digest[static const 1],
     sb_sw_signature_t signature[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_byte_t* const input,
     size_t const input_len,
     sb_hmac_drbg_state_t* const provided_drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    // Compute the message digest and provide it as output.
    sb_sha256_message(&ctx->param_gen.sha, digest->bytes, input, input_len);

    return sb_sw_sign_message_digest(ctx, signature, private, digest,
                                     provided_drbg, curve, e);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_composite_sign_wrap_message_digest
    (sb_sw_context_t ctx[static const 1],
     sb_sw_message_digest_t wrapped[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     const sb_sw_private_t private[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     sb_sw_curve_id_t const curve,
     sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context and output.
    SB_NULLIFY(ctx);
    SB_NULLIFY(wrapped);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    /* Scalar inversion blinding factor generation is done in one generate
     * call to the DRBG. */
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    // Bail out early if the curve is invalid or the DRBG needs to be reseeded.
    SB_RETURN_ERRORS(err, ctx);

    /* Generate a random scalar to use as part of blinding. */
    if (drbg != NULL) {
        /* The private key is supplied as additional input to the DRBG in
         * order to mitigate DRBG failure. */

        // Supply the private scalar and the message as drbg's additional input.
        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            private->bytes, message->bytes
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            SB_ELEM_BYTES, SB_SHA256_SIZE
        };

        err |= sb_hmac_drbg_generate_additional_vec(drbg,
                                                    ctx->param_gen.buf,
                                                    SB_SW_FIPS186_4_CANDIDATES *
                                                    SB_ELEM_BYTES,
                                                    add, add_len);
        SB_ASSERT(!err, "Scalar blinding factor generation should never fail.");
    } else {
        // Update the hkdf with the private scalar and the message.
        sb_hkdf_extract_init(&ctx->param_gen.hkdf, NULL, 0);
        sb_hkdf_extract_update(&ctx->param_gen.hkdf,
                               private->bytes, SB_ELEM_BYTES);
        sb_hkdf_extract_update(&ctx->param_gen.hkdf,
                               message->bytes, SB_SHA256_SIZE);
        sb_hkdf_extract_finish(&ctx->param_gen.hkdf);

        const sb_byte_t label[] = "sb_sw_composite_sign_wrap_message_digest";
        sb_hkdf_expand(&ctx->param_gen.hkdf,
                       label, sizeof(label),
                       ctx->param_gen.buf,
                       SB_SW_FIPS186_4_CANDIDATES * SB_ELEM_BYTES);
    }

    /* Test and select a candidate from the filled buffer. */
    err |= sb_sw_k_from_buf(ctx, 1, s, e);

    /* At this point a possibly-invalid candidate is in MULT_K(ctx). */
    /* Check the supplied private key now. */

    sb_fe_from_bytes(MULT_Z(ctx), private->bytes);
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(MULT_Z(ctx), s)));

    /* Bail out if the private key is invalid or if blinding factor
     * generation failed. */
    SB_RETURN_ERRORS(err, ctx);

    // T6 = scalar^-1 * R
    sb_sw_invert_field_element(ctx, s);

    // T5 = message_digest
    sb_fe_from_bytes(C_T5(ctx), message->bytes);
    sb_fe_mod_reduce(C_T5(ctx), s->n);

    // T7 = (scalar^-1 * R) * message_digest * R^-1
    //    = scalar^-1 * message_digest
    sb_fe_mont_mult(C_T7(ctx), C_T6(ctx), C_T5(ctx), s->n);

    sb_fe_to_bytes(wrapped->bytes, C_T7(ctx));

    SB_RETURN(err, ctx);
}
#endif

// NOT USED
#if !BOOTROM_BUILD
sb_error_t sb_sw_composite_sign_unwrap_signature
    (sb_sw_context_t ctx[static const 1],
     sb_sw_signature_t unwrapped[static const 1],
     const sb_sw_signature_t signature[static const 1],
     const sb_sw_private_t private[static const 1],
     sb_sw_curve_id_t const curve,
     __unused sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context
    SB_NULLIFY(ctx);
    SB_NULLIFY(unwrapped);

    const sb_sw_curve_t* s = NULL;
    err |= sb_sw_curve_from_id(&s, curve);

    // Return errors if curve is invalid
    SB_RETURN_ERRORS(err, ctx);

    // Convert the private scalar to a field element and validate.
    sb_fe_from_bytes(MULT_Z(ctx), private->bytes);
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(MULT_Z(ctx), s)));

    // Convert the signature to field elements and validate.
    sb_fe_from_bytes(VERIFY_QR(ctx), signature->bytes);
    sb_fe_from_bytes(VERIFY_QS(ctx), signature->bytes + SB_ELEM_BYTES);
    sb_fe_mod_reduce(C_T6(ctx), s->n);

    err |= SB_ERROR_IF(SIGNATURE_INVALID,
                       !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(VERIFY_QR(ctx), s)));
    err |= SB_ERROR_IF(SIGNATURE_INVALID,
                       !SB_WORD_FROM_BOOL(sb_sw_scalar_validate(VERIFY_QS(ctx), s)));

    // Return with errors if private key or signature did not validate.
    SB_RETURN_ERRORS(err, ctx);

    // Y1 = private * R
    sb_fe_mont_convert(C_Y1(ctx), MULT_Z(ctx), s->n);

    // T5 = s * private
    sb_fe_mont_mult(C_T5(ctx), C_Y1(ctx), VERIFY_QS(ctx), s->n);

    // Output (r, s)
    sb_fe_to_bytes(unwrapped->bytes, VERIFY_QR(ctx));
    sb_fe_to_bytes(unwrapped->bytes + SB_ELEM_BYTES, C_T5(ctx));

    SB_RETURN(err, ctx);
}
#endif

// NOT USED (inlined)
#if 0
static sb_error_t sb_sw_verify_signature_start
    (sb_sw_context_t ctx[static const 1],
     const sb_sw_signature_t signature[static const 1],
     const sb_sw_public_t public[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_t* s)
{
    sb_error_t err = SB_SUCCESS;

    // Nullify the context.
    SB_NULLIFY(ctx);

    // Bail out early if the DRBG needs to be reseeded
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    SB_RETURN_ERRORS(err, ctx);

    // Only the X coordinate of the public key is used as input to initial Z
    // generation, as the Y coordinate is not an independent input.
#if BOOTROM_BUILD
    #define label (sb_byte_t*)(bootram->always.boot_random.e)
    #define label_len sizeof(bootram->always.boot_random)
#else
    static const sb_byte_t label[] = "sb_sw_verify_signature";
    const int label_len = sizeof(label);
#endif
    err |= sb_sw_generate_z(ctx, drbg, s, public->bytes, SB_ELEM_BYTES,
                            signature->bytes, 2 * SB_ELEM_BYTES,
                            message->bytes, SB_ELEM_BYTES,
                            label, label_len);

    sb_fe_from_bytes(MULT_POINT_X(ctx), public->bytes);
    sb_fe_from_bytes(MULT_POINT_Y(ctx), public->bytes + SB_ELEM_BYTES);
    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID, !sb_sw_point_validate(ctx, s));

    sb_fe_from_bytes(VERIFY_QR(ctx), signature->bytes);
    sb_fe_from_bytes(VERIFY_QS(ctx), signature->bytes + SB_ELEM_BYTES);
    sb_fe_from_bytes(VERIFY_MESSAGE(ctx), message->bytes);

    return err;
}
#endif

// NOT USED
#if !SB_USE_RP2350_SHA256 // no sb_sha256_finish_to_buffer
sb_error_t sb_sw_verify_signature_sha256_start
    (sb_sw_context_t ctx[static const 1],
     sb_sha256_state_t sha[static const 1],
     const sb_sw_signature_t signature[static const 1],
     const sb_sw_public_t public[static const 1],
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
{
    sb_sha256_finish_to_buffer(sha);

    const sb_sw_curve_t* curve = NULL;
    err |= sb_sw_curve_from_id(&curve,c);
    SB_RETURN_ERRORS(err, ctx);

    // This egregious cast works because sb_sw_message_digest_t is just a struct
    // wrapper for a bunch of bytes.
    const sb_sw_message_digest_t* const digest =
        (const sb_sw_message_digest_t*) (sha->buffer);

    return sb_sw_verify_signature_start(ctx, signature, public, digest, drbg,
                                        curve, e);
}
#endif

// USED
sb_verify_result_t sb_sw_verify_signature(sb_sw_context_t ctx[static const 1],
                                  const sb_sw_signature_t signature[static const 1],
                                  const sb_sw_public_t public[static const 1],
                                  const sb_sw_message_digest_t message[static const 1],
                                  sb_hmac_drbg_state_t* const drbg,
                                  const sb_sw_curve_id_t c)
{
    const sb_sw_curve_t *curve;
#if BOOTROM_BUILD
    ((void)c);
    curve = &SB_CURVE_SECP256K1;
#else
    sb_error_t err = SB_SUCCESS;
    SB_SIG_MERGE_ERROR(err, SB_HARD_ERROR_FROM_ERROR(sb_sw_curve_from_id(&curve,c)));
    SB_SIG_RETURN_ERRORS(err, ctx);
#endif

    // --------------------------------------------------------------------------------------------
    // (inlined) err |= sb_sw_verify_signature_start(ctx, signature, public, message, drbg, curve);

    // Nullify the context.
    SB_NULLIFY(ctx);

#if BOOTROM_BUILD
    bootrom_assert(SWEETB, !drbg);
#else
    // Bail out early if the DRBG needs to be reseeded
    if (drbg != NULL) {
        SB_SIG_MERGE_ERROR(err, SB_HARD_ERROR_FROM_ERROR(sb_hmac_drbg_reseed_required(drbg, 1)));
    }

    SB_SIG_RETURN_ERRORS(err, ctx);
#endif

    // Only the X coordinate of the public key is used as input to initial Z
    // generation, as the Y coordinate is not an independent input.
#if BOOTROM_BUILD
#define label (sb_byte_t*)(bootram->always.boot_random.e)
#define label_len sizeof(bootram->always.boot_random)
#else
    static const sb_byte_t label[] = "sb_sw_verify_signature";
    const int label_len = sizeof(label);
#endif
    uint32_t xor_pattern = 0;
    SB_SIG_MERGE_ERROR(err, sb_sw_generate_z(ctx, drbg, curve, public->bytes, SB_ELEM_BYTES,
                                           signature->bytes, 2 * SB_ELEM_BYTES,
                                           message->bytes, SB_ELEM_BYTES,
                                           label, label_len));
    xor_pattern = SB_OPAQUE(xor_pattern) + 0x200;
    sb_fe_from_bytes(MULT_POINT_X(ctx), public->bytes);
    sb_fe_from_bytes(MULT_POINT_Y(ctx), public->bytes + SB_ELEM_BYTES);
    SB_SIG_MERGE_ERROR(err, SB_ERROR_IF_NOT(PUBLIC_KEY_INVALID, sb_sw_point_validate(ctx, curve)));
    xor_pattern = SB_OPAQUE(xor_pattern) + 0x80;
    sb_fe_from_bytes(VERIFY_QR(ctx), signature->bytes);
    sb_fe_from_bytes(VERIFY_QS(ctx), signature->bytes + SB_ELEM_BYTES);
    sb_fe_from_bytes(VERIFY_MESSAGE(ctx), message->bytes);

    SB_SIG_RETURN_ERRORS(err, ctx);
    xor_pattern = SB_OPAQUE(xor_pattern) + 0x01;

    // --------------------------
    // (inlined) err |= SB_ERROR_IF(SIGNATURE_INVALID, !sb_sw_verify_continue_and_finish(ctx, curve));
    //
    // SB_SW_VERIFY_OP_STAGE_INV_S:
    // A signature with either r or s as 0 or N is invalid;
    // see `sb_test_invalid_sig` for a unit test of this
    // check.
    sb_bool_t v0 = sb_sw_scalar_validate(VERIFY_QR(ctx), curve); // state.res &= sb_sw_scalar_validate(VERIFY_QR(v), s);
    sb_bool_t v1 = sb_sw_scalar_validate(VERIFY_QS(ctx), curve);  // state.res &= sb_sw_scalar_validate(VERIFY_QS(v), s);
    if (SB_FE_IS_FALSE(v0) || SB_FE_IS_FALSE(v1)) goto err;
    xor_pattern = SB_OPAQUE(xor_pattern) + 0x02;
    SB_FE_ASSERT_AND_TRUE(v0, v1);

    SB_FE_START(ctx, curve)
    SB_FE_MOD_REDUCE  (O_VERIFY_MESSAGE,1)                    // sb_fe_mod_reduce(VERIFY_MESSAGE(v), s->n);
    SB_FE_MONT_CONVERT(O_C_T5,O_VERIFY_QS,1)                  // sb_fe_mont_convert(C_T5(v), VERIFY_QS(v), s->n); // t5 = s * R
    SB_FE_MOD_INV_R   (O_C_T5,O_C_T6,O_C_T7,1)                // sb_fe_mod_inv_r(C_T5(v), C_T6(v), C_T7(v), s->n); // t5 = s^-1 * R
    SB_FE_MOV         (O_C_T6,O_VERIFY_MESSAGE)               // *C_T6(v) = *VERIFY_MESSAGE(v);
    SB_FE_MONT_MULT   (O_MULT_ADD_KG,O_C_T6,O_C_T5,1)         // sb_fe_mont_mult(MULT_ADD_KG(v), C_T6(v), C_T5(v), s->n); // k_G = m * s^-1
    SB_FE_MONT_MULT   (O_MULT_K,O_VERIFY_QR,O_C_T5,1)         // sb_fe_mont_mult(MULT_K(v), VERIFY_QR(v), C_T5(v), s->n); // k_P = r * s^-1
    SB_FE_STOP

    // A message of zero is also invalid.
    SB_SIG_MERGE_ERROR(err, SB_ERROR_IF_NOT(SIGNATURE_INVALID, SB_FE_HARD_NEQ(VERIFY_MESSAGE(ctx), &curve->n->p)));     // state.res &= !sb_fe_equal(VERIFY_MESSAGE(v), &s->n->p);
    SB_SIG_RETURN_ERRORS(err, ctx);
    xor_pattern = SB_OPAQUE(xor_pattern) + 0x04;

// SB_SW_VERIFY_OP_STAGE_INV_Z, SB_SW_VERIFY_OP_STAGE_LADDER:
    sb_sw_point_mult_add_z_continue(ctx, curve);
    xor_pattern = SB_OPAQUE(xor_pattern) + 0x400;
// SB_SW_VERIFY_OP_STAGE_TEST:
    // This happens when p is some multiple of g that occurs within
    // the ladder, such that additions inadvertently produce a point
    // doubling. When that occurs, the private scalar that generated p is
    // also obvious, so this is bad news. Don't do this.
    v0 = SB_FE_HARD_NEQ(C_X1(ctx), &curve->p->p);
    v1 = SB_FE_HARD_NEQ(C_Y1(ctx), &curve->p->p); // state.res &= !(sb_fe_equal(C_X1(v), &s->p->p) & sb_fe_equal(C_Y1(v), &s->p->p));

    if (!(SB_FE_IS_TRUE(v0) || SB_FE_IS_TRUE(v1))) goto err;
    SB_FE_ASSERT_OR_TRUE(v0, v1);
    xor_pattern = SB_OPAQUE(xor_pattern) + 0x08;

    // qr ==? x mod N, but we don't have x, just x * z^2
    // Given that qr is reduced mod N, if it is >= P - N, then it can be used
    // directly. If it is < P - N, then we need to try to see if the original
    // value was qr or qr + N.

    // Try directly first:
    SB_FE_START(ctx, curve)
    SB_FE_MONT_SQUARE(O_C_T6,O_MULT_Z,0)                                 // sb_fe_mont_square(C_T6(v), MULT_Z(v), s->p); // t6 = Z^2 * R
    SB_FE_MONT_MULT  (O_C_T7,O_VERIFY_QR,O_C_T6,0)                       // sb_fe_mont_mult(C_T7(v), VERIFY_QR(v), C_T6(v), s->p); // t7 = r * Z^2
    SB_FE_STOP

    xor_pattern = SB_OPAQUE(xor_pattern) + 0x10;

    v0 = SB_FE_HARD_NEQ(C_T7(ctx), C_X1(ctx));
    if (SB_FE_IS_FALSE(v0)) {
        xor_pattern = SB_OPAQUE(xor_pattern) + 0x60;
        SB_FE_ASSERT_FALSE(v0);
        goto done;                        // ver |= sb_fe_equal(C_T7(v), C_X1(v));
    }
    // If that didn't work, and qr < P - N, then we need to compare
    // (qr + N) * z^2 against x * z^2

    // If qr = P - N, then we do not compare against (qr + N),
    // because qr + N would be equal to P, and the X component of the
    // point is thus zero and should have been rejected.

    // See the small_r_signature tests, which generate signatures
    // where this path is tested.

    sb_fe_mod_add(C_T5(ctx), VERIFY_QR(ctx), &curve->n->p, curve->p); // t5 = (N + r)

    SB_FE_START(ctx, curve)
    SB_FE_MONT_MULT(O_C_T7,O_C_T5,O_C_T6,0)     // sb_fe_mont_mult(C_T7(v), C_T5(v), C_T6(v), s->p);     // t7 = (N + r) * Z^2
    SB_FE_STOP

    sb_fe_sub(C_T5(ctx), &curve->p->p, &curve->n->p);               // t5 = P - N
    xor_pattern = SB_OPAQUE(xor_pattern) + 0x20;

    // if((sb_fe_lt(VERIFY_QR(v), C_T5(v)) & // r < P - N
    //          sb_fe_equal(C_T7(v), C_X1(v)))) goto sig_ok; // t7 == x
    v0 = SB_FE_HARD_LO(VERIFY_QR(ctx), C_T5(ctx));
    v1 = SB_FE_HARD_EQ(C_T7(ctx), C_X1(ctx));
    if(SB_FE_IS_TRUE(v0) && SB_FE_IS_TRUE(v1)) {
        SB_FE_ASSERT_AND_TRUE(v0, v1);
        xor_pattern = SB_OPAQUE(xor_pattern) + 0x40;
    done:
        xor_pattern -= 0x6ec;
        xor_pattern = xor_pattern | (xor_pattern << 16);
        return SB_VERIFY_TRUE(xor_pattern);
    }
    err:
    return sb_verify_failed();
}

// NOT USED
sb_verify_result_t sb_sw_verify_signature_sha256
    (sb_sw_context_t ctx[static const 1],
     sb_sw_message_digest_t digest[static const 1],
     const sb_sw_signature_t signature[static const 1],
     const sb_sw_public_t public[static const 1],
     const sb_byte_t* const input,
     size_t const input_len,
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     __unused const sb_data_endian_t e)
{
    // Compute the message digest and provide it as output.
    sb_sha256_message(&ctx->param_gen.sha, digest->bytes, input, input_len);

    return sb_sw_verify_signature(ctx, signature, public, digest, drbg,
                                  curve);
}

#ifdef SB_TEST
#define SB_SW_LIB_TESTS_IMPL
#include "sb_sw_lib_tests.c.h"
#endif
