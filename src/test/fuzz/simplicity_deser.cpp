// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* Fuzz target for the Simplicity deserialization and evaluation pipeline.
 *
 * Unlike simplicity.cpp / simplicity_tx.cpp, this target does not parse a
 * Bitcoin transaction — the entire input is devoted to Simplicity program and
 * witness bytes.  The simpler format gives the fuzzer a much shorter path to
 * the layers that are hardest to reach with random data:
 *
 *   decodeMallocDag  →  mallocTypeInference  →  fillWitnessData
 *   →  verifyNoDuplicateIdentityHashes  →  evalTCOExpression (runTCO)
 *
 * The CMR check that execSimplicity normally performs is intentionally
 * bypassed (see simplicity_deser_helper.c) so that any parseable program
 * proceeds to type inference and evaluation.
 *
 * Input layout (all little-endian):
 *   [prog_len : uint32]  [prog_len bytes of program]  [remaining bytes = witness]
 */

#include <cstdint>
#include <cstring>

extern "C" {
#include <simplicity/bitcoin/env.h>
}
#include <test/fuzz/fuzz.h>

#include "simplicity_deser_helper.h"

static constexpr uint32_t DESER_MAX_PROG = 1u << 20; /* 1 MiB cap */

void initialize_simplicity_deser()
{
    simplicity_deser_init();
}

FUZZ_TARGET(simplicity_deser, .init = initialize_simplicity_deser)
{
    if (buffer.size() < 4) return;

    /* Decode little-endian program length from the first four bytes. */
    const uint32_t prog_len =
        static_cast<uint32_t>(buffer[0])
        | (static_cast<uint32_t>(buffer[1]) << 8)
        | (static_cast<uint32_t>(buffer[2]) << 16)
        | (static_cast<uint32_t>(buffer[3]) << 24);

    if (prog_len > DESER_MAX_PROG) return;
    if (buffer.size() < static_cast<size_t>(4) + prog_len) return;

    const uint8_t* prog   = buffer.data() + 4;
    const uint8_t* wit    = buffer.data() + 4 + prog_len;
    const size_t   wit_len = buffer.size() - 4 - prog_len;

    simplicity_deser_run(prog, static_cast<size_t>(prog_len), wit, wit_len);
}
