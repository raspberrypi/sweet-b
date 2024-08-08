/** @file sb_sw_curves.h
 *  @brief private definitions of the short Weierstrass curves supported by Sweet B
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

#ifndef SB_SW_CURVES_H
#define SB_SW_CURVES_H

#include "sb_fe.h"
#include "sb_hmac_drbg.h"
#include "sb_sw_lib.h"

// #if defined(SB_TEST) && !(SB_SW_P256_SUPPORT && SB_SW_SECP256K1_SUPPORT)
// #error "Both SB_SW_P256_SUPPORT and SB_SW_SECP256K1_SUPPORT must be enabled for tests!"
// #endif

// An elliptic curve defined in the short Weierstrass form:
// y^2 = x^3 + a*x + b

// In our case, a is -3 or 0. The oddly named minus_a_r_over_three
// is -a * R * 3^-1. For P256, this is just R. For secp256k1,
// this is p.

typedef struct sb_sw_curve_t {
    const sb_prime_field_t* p; // The prime field which the curve is defined over
    const sb_prime_field_t* n; // The prime order of the group, used for scalar computations
    sb_fe_pair_t g_r; // The generator for the group, with X and Y
    // multiplied by R
    sb_fe_pair_t h_r; // H = (2^257 - 1)^-1 * G, with X and Y multiplied by R
    sb_fe_pair_t g_h_r; // G + H, with X and Y multiplied by R
#if SB_SW_P256_SUPPORT
    sb_fe_t minus_a; // -a (3 for P256, 0 for secp256k1)
    const sb_fe_t* minus_a_r_over_three; // R for P256, 0 for secp256k1
    sb_fe_t b; // b ("random" for P256, 7 for secp256k1)
#endif
} sb_sw_curve_t;

extern const sb_sw_curve_t SB_CURVE_P256;
extern const sb_sw_curve_t SB_CURVE_SECP256K1;
extern const sb_prime_field_t SB_CURVE_P256_P;
extern const sb_prime_field_t SB_CURVE_P256_N;
extern const sb_prime_field_padded_t SB_CURVE_SECP256K1_P;
extern const sb_prime_field_t SB_CURVE_SECP256K1_N;

#endif
