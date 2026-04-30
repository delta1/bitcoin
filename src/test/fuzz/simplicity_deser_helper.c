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

#include <string.h>

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
static const bitcoinTransaction* g_deser_tx2 = NULL; /* 2-in/2-out; input 1 has annex */
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

    /* Build a 2-in/2-out transaction.  Input 1 carries an annex (tag byte
     * 0x50) so that current_annex_hash exercises hasAnnex=true when ix=1,
     * and the multi-input/multi-output paths in env.c are reachable. */
    {
        static const unsigned char annex_tag[1] = {0x50};
        static const rawBitcoinBuffer annex_buf2 = {.buf = annex_tag, .len = 1};
        rawBitcoinInput inputs2[2] = {
            { .annex = NULL,        .prevTxid = zero32,
              .txo = {0, {NULL,0}}, .scriptSig = {NULL,0}, .prevIx = 0, .sequence = 0 },
            { .annex = &annex_buf2, .prevTxid = zero32,
              .txo = {0, {NULL,0}}, .scriptSig = {NULL,0}, .prevIx = 0, .sequence = 0 },
        };
        rawBitcoinOutput outputs2[2] = {
            {.value = 0, .scriptPubKey = {NULL, 0}},
            {.value = 0, .scriptPubKey = {NULL, 0}},
        };
        rawBitcoinTransaction raw_tx2 = {
            .txid = zero32, .input = inputs2, .output = outputs2,
            .numInputs = 2, .numOutputs = 2, .version = 2, .lockTime = 0,
        };
        g_deser_tx2 = simplicity_bitcoin_mallocTransaction(&raw_tx2);
    }
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

        /* 5. Evaluate any well-typed Simplicity expression.
         *    Three passes target distinct uncovered paths in eval.c:
         *
         *    Pass A (CHECK_ALL, full budget, minCost=0):
         *      - Allocates input/output buffers for programs of any type A |- B,
         *        reaching the memcpy paths at eval.c:819 and eval.c:832 that were
         *        previously unreachable (type ONE |- ONE has bitSize 0 for both).
         *      - Seeds the input frame from witness bytes so CASE/ASSERTL/ASSERTR
         *        branch decisions (eval.c:352) vary with fuzz data rather than
         *        always seeing all-zero input.
         *      - Exercises antiDos with CHECK_ALL (normal production check).
         *
         *    Pass B (CHECK_NONE, budget=0, minCost=0):
         *      - budget=0 makes simplicity_analyseBounds return
         *        SIMPLICITY_ERR_EXEC_BUDGET for any program with non-zero cost
         *        (eval.c:742), a path the existing target never reaches.
         *      - CHECK_NONE exercises the fast path in antiDos (eval.c:539).
         *
         *    Pass C (CHECK_EXEC, no budget cap, minCost=BUDGET_MAX):
         *      - minCost=BUDGET_MAX makes simplicity_analyseBounds return
         *        SIMPLICITY_ERR_OVERWEIGHT (eval.c:743) for almost every program
         *        since their cost bound is well below BUDGET_MAX.
         *      - CHECK_EXEC exercises the per-node exec-flag check in antiDos
         *        independently of the case-branch check (eval.c:544).
         */
        if (IS_OK(err)) {
            const ubounded input_bits  = type_dag[dag[dag_len - 1].sourceType].bitSize;
            const ubounded output_bits = type_dag[dag[dag_len - 1].targetType].bitSize;
            const size_t   input_words = ROUND_UWORD(input_bits);
            const size_t   output_words = ROUND_UWORD(output_bits);

            UWORD* input_buf  = input_words  > 0 ? simplicity_calloc(input_words,  sizeof(UWORD)) : NULL;
            UWORD* output_buf = output_words > 0 ? simplicity_calloc(output_words, sizeof(UWORD)) : NULL;

            /* Only proceed if all required allocations succeeded. */
            if ((input_words  == 0 || input_buf)  &&
                (output_words == 0 || output_buf)) {

                /* Seed the input frame from witness bytes.  The witness bytes are
                 * already fuzz-controlled, so reusing them here causes the bit
                 * peeked in CASE/ASSERTL/ASSERTR to vary with the fuzzer input,
                 * exercising both branch directions without growing the corpus. */
                if (input_buf && wit_len > 0) {
                    size_t copy_bytes = input_words * sizeof(UWORD);
                    if (copy_bytes > wit_len) copy_bytes = wit_len;
                    memcpy(input_buf, wit, copy_bytes);
                }

                txEnv env = simplicity_bitcoin_build_txEnv(g_deser_tx, g_deser_tap, 0);

                /* Pass A: normal execution path. */
                static const ubounded full_budget = BUDGET_MAX;
                simplicity_evalTCOExpression(
                    CHECK_ALL, output_buf, input_buf,
                    dag, type_dag, (size_t)dag_len,
                    0, &full_budget, &env);

                /* Pass B: exercises SIMPLICITY_ERR_EXEC_BUDGET (budget=0 < any
                 * non-zero cost) and the CHECK_NONE fast path in antiDos. */
                static const ubounded zero_budget = 0;
                simplicity_evalTCOExpression(
                    CHECK_NONE, output_buf, input_buf,
                    dag, type_dag, (size_t)dag_len,
                    0, &zero_budget, &env);

                /* Pass C: exercises SIMPLICITY_ERR_OVERWEIGHT (minCost=BUDGET_MAX
                 * exceeds almost every program's cost bound) and the CHECK_EXEC
                 * flag in antiDos independent of the case-branch check. */
                simplicity_evalTCOExpression(
                    CHECK_EXEC, output_buf, input_buf,
                    dag, type_dag, (size_t)dag_len,
                    BUDGET_MAX, NULL, &env);

                /* Pass D: 2-in/2-out transaction at input index 1.
                 * Exercises: current_index=1 (non-zero index path in env.c),
                 * multi-input/output bounds checks, and current_annex_hash
                 * hasAnnex=true branch (input 1 carries a 0x50 annex tag). */
                if (g_deser_tx2) {
                    txEnv env2 = simplicity_bitcoin_build_txEnv(g_deser_tx2, g_deser_tap, 1);
                    simplicity_evalTCOExpression(
                        CHECK_ALL, output_buf, input_buf,
                        dag, type_dag, (size_t)dag_len,
                        0, &full_budget, &env2);
                }
            }

            simplicity_free(output_buf);
            simplicity_free(input_buf);
        }

        simplicity_free(type_dag);
    }

    simplicity_free(dag);
}
