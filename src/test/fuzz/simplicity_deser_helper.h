// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_SIMPLICITY_DESER_HELPER_H
#define BITCOIN_TEST_FUZZ_SIMPLICITY_DESER_HELPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Build the fixed minimal bitcoinTransaction / bitcoinTapEnv used as the jet
 * environment during evaluation.  Must be called once before any call to
 * simplicity_deser_run.
 */
void simplicity_deser_init(void);

/* Run the Simplicity pipeline on raw program and witness bytes:
 *
 *   decodeMallocDag  →  mallocTypeInference  →  fillWitnessData
 *   →  verifyNoDuplicateIdentityHashes  →  evalTCOExpression
 *
 * The function never asserts or aborts; all error codes are silently
 * discarded so that the fuzzer can keep running.
 *
 * Precondition: simplicity_deser_init() has been called.
 *               NULL != prog || 0 == prog_len
 *               NULL != wit  || 0 == wit_len
 */
void simplicity_deser_run(const uint8_t* prog, size_t prog_len,
                          const uint8_t* wit,  size_t wit_len);

#ifdef __cplusplus
}
#endif

#endif /* BITCOIN_TEST_FUZZ_SIMPLICITY_DESER_HELPER_H */
