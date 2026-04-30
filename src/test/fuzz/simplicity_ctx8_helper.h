// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_SIMPLICITY_CTX8_HELPER_H
#define BITCOIN_TEST_FUZZ_SIMPLICITY_CTX8_HELPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Exercise the SHA-256 CTX8 jet state machine with deterministic valid state.
 *
 * Calls sha_256_ctx_8_init to obtain a genuine initial context, then feeds
 * fuzz-controlled message bytes through sha_256_ctx_8_add_16 (a partial block
 * that exercises the sub-block-fill path in ctx8Pruned.c), and finalises with
 * sha_256_ctx_8_finalize.  Chaining guarantees that the jets receive a valid
 * CTX8 midstate on every run, exercising internal branching that is rarely
 * reached when the source frame is filled with arbitrary random bytes.
 */
void simplicity_fuzz_ctx8(const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* BITCOIN_TEST_FUZZ_SIMPLICITY_CTX8_HELPER_H */
