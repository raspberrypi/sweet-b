#pragma once
/** @def SB_SW_P256_SUPPORT
    @brief Define this to 0 to disable NIST P-256 curve support in Sweet B. */
#ifndef SB_SW_P256_SUPPORT
#define SB_SW_P256_SUPPORT 1
#endif

/** @def SB_SW_SECP256K1_SUPPORT
    @brief Define this to 0 to disable SECG secp256k1 curve support in
    Sweet B. */

#ifndef SB_SW_SECP256K1_SUPPORT
#define SB_SW_SECP256K1_SUPPORT 1
#endif

#if !SB_SW_P256_SUPPORT && !SB_SW_SECP256K1_SUPPORT
#error "At least one of SB_SW_P256_SUPPORT or SB_SW_SECP256K1_SUPPORT must be enabled!"
#endif
