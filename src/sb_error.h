/** @file sb_error.h
 *  @brief private error return macros
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

#ifndef SB_ERROR_H
#define SB_ERROR_H

#include "sb_types.h"

#include <string.h>

#if !BOOTROM_BUILD
#define SB_NULLIFY(ptr) do { \
    memset((ptr), 0, sizeof(*(ptr))); \
} while (0)
#else
#include "bootrom.h"
#define SB_NULLIFY(ptr) ({ bootrom_assert(SWEETB, !((sizeof(*(ptr)))&3)); s_native_crit_step_safe_mem_erase_by_words((uintptr_t)(ptr), sizeof(*(ptr))); })
#endif


#define SB_ERROR_IF(err, cond) ((-(sb_error_t) (cond)) & (sb_error_t) \
SB_ERROR_## err)

#if !BOOTROM_BUILD
#define SB_RETURN_ERRORS_2(err, zero_ctx) do { \
    if (err) { \
        SB_NULLIFY(zero_ctx); \
        return err; \
    } \
} while (0)
#else
#define SB_RETURN_ERRORS_2(err, zero_ctx) do { \
    if (err) { \
        /* SB_NULLIFY(zero_ctx); not needed as we don't have any secrets to spill */ \
        return err; \
    } \
} while (0)
#endif

#define SB_RETURN_ERRORS_1(err, unused) do { \
    if (err) { \
        return err; \
    } \
} while (0)

#define SB_RETURN_ERRORS_n(a, b, c, ...) c(a, b)

#define SB_RETURN_ERRORS(...) \
    SB_RETURN_ERRORS_n(__VA_ARGS__, SB_RETURN_ERRORS_2, SB_RETURN_ERRORS_1, \
                       NOT_ENOUGH_ARGUMENTS)

#if !BOOTROM_BUILD
#define SB_RETURN(err, zero_ctx) do { \
    SB_NULLIFY(zero_ctx); \
    return err; \
} while (0)
#else
#define SB_RETURN(err, zero_ctx) do { \
    /* SB_NULLIFY(zero_ctx); */ \
    return err; \
} while (0)
#endif

#define SB_ERRORS_4(err1, err2, err3, err4) \
    (((sb_error_t) (err1)) | ((sb_error_t) (err2)) | ((sb_error_t) (err3)) | \
     ((sb_error_t) (err4)))

#define SB_ERRORS_3(err1, err2, err3, unused) \
    (((sb_error_t) (err1)) | ((sb_error_t) (err2)) | ((sb_error_t) (err3)))

#define SB_ERRORS_2(err1, err2, unused1, unused2) \
    (((sb_error_t) (err1)) | ((sb_error_t) (err2)))

#define SB_ERRORS_1(err1, unused1, unused2, unused3) \
    ((sb_error_t) (err1))

#define SB_ERRORS_n(a, b, c, d, e, ...) e(a, b, c, d)

#define SB_ERRORS(...) \
    SB_ERRORS_n(__VA_ARGS__, SB_ERRORS_4, SB_ERRORS_3, SB_ERRORS_2, \
        SB_ERRORS_1, NOT_ENOUGH_ARGUMENTS)

#endif

#if BOOTROM_HARDENING
// error is hx_false() so (error if not x) == x
#define SB_ERROR_IF_NOT(err, cond) cond
#define SB_FE_IS_FALSE(x) hx_is_false(x)
#define SB_FE_IS_TRUE(x) hx_is_true(x)
#define SB_FE_ASSERT_FALSE(x) hx_assert_false(x)
#define SB_FE_ASSERT_TRUE(x) hx_assert_true(x)
#define SB_RETURN_FALSE_IF_NOT_CHECKED(x) ({ hx_bool b = x; if (hx_is_false(b)) return hx_false(); hx_assert_true(b); })
#define SB_RETURN_FALSE_IF_NOT(x) ({ hx_bool b = x; if (hx_is_false(b)) return hx_false(); })
#define SB_SIG_MERGE_ERROR(err, x) ({ hx_bool b = /* copy in case this is a func call */(x); if (hx_is_false(b)) return hx_sig_verified_false(); hx_assert_true(b); })
#define SB_SIG_RETURN_ERRORS(err, ctx) ((void)0) /* merge_error already does this */
#define SB_MAKE_BOOL(b) make_hx_bool(b)
#define sb_verify_unknown() hx_xbool_invalid()
#define sb_verify_failed() hx_sig_verified_false()
#define SB_FE_ASSERT_AND_TRUE(a, b) hx_assert_and(a, b)
#define SB_FE_ASSERT_OR_TRUE(a, b) hx_assert_or(a, b)
//#define make_hx_small(x) ({ hx_bool rc; rc.v = -x; rc; })
#define make_hx_small(x) make_hx_bool(x)
extern hx_bool sb_fe_hard_lo(const sb_fe_t left[static 1],
                              const sb_fe_t *right);
extern hx_bool sb_fe_hard_eq(const sb_fe_t left[static 1],
                              const sb_fe_t *right);
extern hx_bool sb_fe_hard_neq(const sb_fe_t left[static 1],
                               const sb_fe_t *right);
#define SB_FE_HARD_EQ(x, y) sb_fe_hard_eq(x, y)
#define SB_FE_HARD_NEQ(x, y) sb_fe_hard_neq(x, y)
#define SB_FE_HARD_NEQZ(x) SB_FE_HARD_NEQ(x, 0)
#define SB_FE_HARD_LO(x, y) sb_fe_hard_lo(x, y)
#define SB_VERIFY_TRUE(xor) ({ hx_xbool b = { hx_bit_pattern_true() ^ (xor)}; b; })
#define SB_OPAQUE(x) ({ __compiler_membar(); __get_opaque_value(x); })
#define SB_ERROR_FROM_HARD_ERROR(x, y) ({ hx_bool _save = x; hx_check_bool(_save); hx_is_true(_save) ? SB_SUCCESS : SB_ERROR_ ## y; })
#define SB_HARD_ERROR_FROM_ERROR(x) make_hx_bool(!(x))
#define SB_WORD_FROM_BOOL(x) hx_is_true(x)
#else
#define SB_ERROR_IF_NOT(err, cond) SB_ERROR_IF(err, !(cond))
#define SB_FE_IS_FALSE(x) (!(x))
#define SB_FE_IS_TRUE(x) (x)
#define SB_FE_ASSERT_TRUE(x) SB_ASSERT(x, "expected true")
#define SB_FE_ASSERT_FALSE(x) SB_ASSERT(!(x), "expected false")
#define sb_verify_unknown() SB_ERROR_SIGNATURE_INVALID
#define sb_verify_failed() SB_ERROR_SIGNATURE_INVALID
#define SB_SIG_MERGE_ERROR(err, x) err |= (x)
#define SB_SIG_RETURN_ERRORS(err, ctx) SB_RETURN_ERRORS(err, ctx)
#define SB_MAKE_BOOL(x) x
#define SB_FE_ASSERT_AND_TRUE(a, b) SB_ASSERT((a) && (b), "expect values to be equal")
#define SB_FE_ASSERT_OR_TRUE(a, b) SB_ASSERT((a) | (b), "expect values to be equal")
#define SB_RETURN_FALSE_IF_NOT(b) if (!(b)) return 0
#define SB_RETURN_FALSE_IF_NOT_CHECKED(b) SB_RETURN_FALSE_IF_NOT(b)
#define SB_RETURN_BOOL(b) (b)
#define SB_FE_HARD_EQ(x, y) (SB_FE_EQ(x, y))
#define SB_FE_HARD_NEQ(x, y) (!(SB_FE_EQ(x, y)))
#define SB_FE_HARD_NEQZ(x) (!(SB_FE_EQZ(x)))
#define SB_FE_HARD_LO(x, y) SB_FE_LO(x, y)
#define SB_VERIFY_TRUE(x) SB_SUCCESS
#define SB_OPAQUE(x) x
#define SB_ERROR_FROM_HARD_ERROR(x, y) x
#define SB_HARD_ERROR_FROM_ERROR(x) x
#define SB_WORD_FROM_BOOL(x) x
#define __get_opaque_ptr(x) (x)
#endif