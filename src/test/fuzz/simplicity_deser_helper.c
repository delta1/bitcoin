// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* This file is compiled as C so that it can safely include the internal
 * Simplicity headers (which use C99 compound literals and designated
 * initialisers that are only a GCC extension in C++ mode).
 *
 * It exercises the pipeline layers that are hardest to reach through the
 * existing simplicity.cpp / simplicity_tx.cpp targets:
 *
 *   decodeMallocDag  →  mallocTypeInference  →  fillWitnessData
 *   →  verifyNoDuplicateIdentityHashes  →  evalTCOExpression (runTCO)
 *
 * The CMR check performed by execSimplicity is intentionally bypassed so
 * that the fuzzer can reach type inference and evaluation for any program
 * that parses, not just one whose CMR we have pre-computed.
 */

#include "simplicity_deser_helper.h"

#include <simplicity/bitcoin/env.h>
#include <simplicity/bitcoin/primitive.h>  /* simplicity_bitcoin_decodeJet, simplicity_bitcoin_mallocBoundVars */
#include <simplicity/dag.h>
#include <simplicity/deserialize.h>
#include <simplicity/eval.h>
#include <simplicity/errorCodes.h>
#include <simplicity/limitations.h>
#include <simplicity/simplicity_alloc.h>
#include <simplicity/typeInference.h>
#include "../../simplicity/bitcoin/txEnv.h"  /* simplicity_bitcoin_build_txEnv */

static const bitcoinTransaction* g_deser_tx  = NULL;
static const bitcoinTapEnv*      g_deser_tap = NULL;

void simplicity_deser_init(void)
{
    /* All-zero 32-byte value used for txid and zero scriptCMR. */
    static const unsigned char zero32[33] = {0};

    /* Minimal control block: first byte is TAPROOT_LEAF_TAPSIMPLICITY (0xbe),
     * remaining 32 bytes are the all-zero internal key. */
    static const unsigned char ctrl33[33] = {[0] = 0xbe};

    static const rawBitcoinOutput raw_out = {
        .value     = 0,
        .scriptPubKey = {.buf = NULL, .len = 0},
    };
    static const rawBitcoinInput raw_in = {
        .annex     = NULL,
        .prevTxid  = zero32,
        .txo       = {.value = 0, .scriptPubKey = {.buf = NULL, .len = 0}},
        .scriptSig = {.buf = NULL, .len = 0},
        .prevIx    = 0,
        .sequence  = 0,
    };
    static const rawBitcoinTransaction raw_tx = {
        .txid       = zero32,
        .input      = &raw_in,
        .output     = &raw_out,
        .numInputs  = 1,
        .numOutputs = 1,
        .version    = 2,
        .lockTime   = 0,
    };
    static const rawBitcoinTapEnv raw_tap = {
        .controlBlock = ctrl33,
        .scriptCMR    = zero32,  /* zero CMR — CMR check is bypassed anyway */
        .pathLen      = 0,
    };

    g_deser_tx  = simplicity_bitcoin_mallocTransaction(&raw_tx);
    g_deser_tap = simplicity_bitcoin_mallocTapEnv(&raw_tap);
}

void simplicity_deser_run(const uint8_t* prog, size_t prog_len,
                          const uint8_t* wit,  size_t wit_len)
{
    if (NULL == g_deser_tx || NULL == g_deser_tap) return;

    /* 1. Deserialize the program DAG. */
    bitstream prog_stream = initializeBitstream(prog, prog_len);
    dag_node* dag = NULL;
    combinator_counters census;
    int_fast32_t dag_len = simplicity_decodeMallocDag(
        &dag, simplicity_bitcoin_decodeJet, &census, &prog_stream);
    if (dag_len <= 0) return;  /* parse error or empty DAG */

    /* 2. Type inference (exercises typeInference.c, rsort.c, type.c). */
    type* type_dag = NULL;
    simplicity_err err = simplicity_mallocTypeInference(
        &type_dag, simplicity_bitcoin_mallocBoundVars,
        dag, (uint_fast32_t)dag_len, &census);

    if (IS_OK(err) && NULL != type_dag) {
        /* 3. Fill witness data (exercises dag.c:fillWitnessData). */
        bitstream wit_stream = initializeBitstream(wit, wit_len);
        err = simplicity_fillWitnessData(dag, type_dag, (uint_fast32_t)dag_len, &wit_stream);
        if (IS_OK(err)) {
            /* Ignore trailing-byte / illegal-padding errors in the witness
             * stream — we want to continue to evaluation even if the witness
             * has extra trailing bits. */
            simplicity_closeBitstream(&wit_stream);
        }

        /* 4. Verify no duplicate identity hashes
         *    (exercises dag.c:verifyNoDuplicateIdentityHashes). */
        if (IS_OK(err)) {
            sha256_midstate ihr;
            err = simplicity_verifyNoDuplicateIdentityHashes(
                &ihr, dag, type_dag, (uint_fast32_t)dag_len);
        }

        /* 5. Evaluate — only for Simplicity *programs* (type ONE |- ONE).
         *    Type index 0 is always ONE in the Bitcoin application context.
         *    Passing NULL input/output is only valid when bitSize(A) == 0.
         *    This exercises eval.c:runTCO and frame.c:copyBits. */
        if (IS_OK(err) &&
            0 == dag[dag_len - 1].sourceType &&
            0 == dag[dag_len - 1].targetType) {
            txEnv env = simplicity_bitcoin_build_txEnv(g_deser_tx, g_deser_tap, 0);
            static const ubounded budget = BUDGET_MAX;
            simplicity_evalTCOExpression(
                CHECK_ALL, NULL, NULL,
                dag, type_dag, (size_t)dag_len,
                0, &budget, &env);
        }

        simplicity_free(type_dag);
    }

    simplicity_free(dag);
}
