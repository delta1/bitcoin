// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_SIMPLICITY_JETS_HELPER_H
#define BITCOIN_TEST_FUZZ_SIMPLICITY_JETS_HELPER_H

#include <stddef.h>
#include <stdint.h>
#include <simplicity/bitcoin/env.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Run every jet declared in bitcoinJets.h against the given environment.
 *
 * src_data / src_len supply raw bytes that are consumed sequentially to fill
 * the source frame of each jet call.  Passing the same buffer on repeated
 * calls (with different ix values) is intentional: it exercises the
 * current_* jets for both the no-annex (ix=0) and has-annex (ix=1) cases
 * without inflating the seed size.
 *
 * Precondition: NULL != tx
 *               NULL != tap
 *               ix < tx->numInputs
 */
void bitcoin_fuzz_jets(const bitcoinTransaction* tx, const bitcoinTapEnv* tap,
                       uint_fast32_t ix, const uint8_t* src_data, size_t src_len);

/* Run every env-independent jet declared in jets.h (jets.c and jets-secp256k1.c)
 * against fuzz-controlled src frames.  This covers:
 *   - logic, shift/rotate, and arithmetic jets
 *   - SHA-256 primitives and CTX8 jets
 *   - secp256k1 field, scalar, group, and signature jets
 *   - parse_lock, parse_sequence, tapdata_init
 *
 * src_data / src_len are consumed sequentially across all jet calls so that a
 * single compact corpus entry exercises the whole group.
 */
void simplicity_fuzz_core_jets(const uint8_t* src_data, size_t src_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BITCOIN_TEST_FUZZ_SIMPLICITY_JETS_HELPER_H */
