// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* Fuzz target for bitcoinJets.c
 *
 * The existing simplicity_tx target reaches jets only indirectly: the fuzzer
 * must produce input that clears CMR computation, program parsing, type
 * inference, and witness filling before any jet executes.  That chain is too
 * opaque for the fuzzer to penetrate reliably.
 *
 * This target constructs a bitcoinTransaction / bitcoinTapEnv directly from
 * fuzz data, then calls every jet in bitcoinJets.c with fuzz-controlled src
 * frames.  Two passes are made -- ix=0 (no annex) and ix=1 (with annex) --
 * so that both branches of every hasAnnex guard are reachable in a single
 * corpus entry.
 */

#include <cstdint>
#include <cstring>
#include <vector>

extern "C" {
#include <simplicity/bitcoin/env.h>
}
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include "simplicity_jets_helper.h"

FUZZ_TARGET(simplicity_jets)
{
    FuzzedDataProvider fuzzed{buffer.data(), buffer.size()};

    /* Transaction parameters that drive branch conditions inside the jets:
     *
     *  version   -- lockDistance / lockDuration require version >= 2
     *  lockTime  -- lockHeight uses lockTime < 500000000; lockTime jet uses >=
     *  sequences -- isFinal is false when any sequence < 0xffffffff;
     *               lockDistance / lockDuration inspect sequence bits 15:0
     *               and bit 22
     */
    const uint32_t version  = fuzzed.ConsumeIntegral<uint32_t>();
    const uint32_t lockTime = fuzzed.ConsumeIntegral<uint32_t>();

    /* Two inputs so both ix=0 and ix=1 are valid indices for build_txEnv. */
    const uint8_t prevtxid[32] = {};

    /* Input 0: no annex -- exercises hasAnnex=false branches */
    const uint64_t in0_value   = fuzzed.ConsumeIntegral<uint64_t>();
    const uint32_t in0_previx  = fuzzed.ConsumeIntegral<uint32_t>();
    const uint32_t in0_seq     = fuzzed.ConsumeIntegral<uint32_t>();
    const rawBitcoinOutput raw_txo0{in0_value, {nullptr, 0}};
    const rawBitcoinInput  raw_in0{nullptr, prevtxid, raw_txo0,
                                   {nullptr, 0}, in0_previx, in0_seq};

    /* Input 1: with annex (tag byte 0x50) -- exercises hasAnnex=true branches */
    static const uint8_t          annex_bytes[4] = {0x50, 0x00, 0x00, 0x00};
    static const rawBitcoinBuffer  annex_buf{annex_bytes, sizeof(annex_bytes)};
    const uint64_t in1_value   = fuzzed.ConsumeIntegral<uint64_t>();
    const uint32_t in1_previx  = fuzzed.ConsumeIntegral<uint32_t>();
    const uint32_t in1_seq     = fuzzed.ConsumeIntegral<uint32_t>();
    const rawBitcoinOutput raw_txo1{in1_value, {nullptr, 0}};
    const rawBitcoinInput  raw_in1{&annex_buf, prevtxid, raw_txo1,
                                   {nullptr, 0}, in1_previx, in1_seq};

    const rawBitcoinInput  raw_inputs[2] = {raw_in0, raw_in1};

    /* One output (numOutputs=1 means output index >= 1 is out-of-bounds). */
    const uint64_t out_value = fuzzed.ConsumeIntegral<uint64_t>();
    const rawBitcoinOutput raw_out{out_value, {nullptr, 0}};

    const rawBitcoinTransaction raw_tx{
        prevtxid, raw_inputs, &raw_out,
        /*numInputs=*/2, /*numOutputs=*/1,
        version, lockTime
    };

    bitcoinTransaction* tx = simplicity_bitcoin_mallocTransaction(&raw_tx);
    if (!tx) return;

    /* Minimal taproot environment: zero CMR, 33-byte control block,
     * pathLen=0 so any tappath index is out-of-bounds. */
    const uint8_t cmr[32]  = {};
    uint8_t       ctrl[33] = {};
    ctrl[0] = 0xbe; /* TAPROOT_LEAF_TAPSIMPLICITY */
    const rawBitcoinTapEnv raw_tap{ctrl, cmr, /*pathLen=*/0};

    bitcoinTapEnv* tap = simplicity_bitcoin_mallocTapEnv(&raw_tap);
    if (!tap) {
        simplicity_bitcoin_freeTransaction(tx);
        return;
    }

    /* All remaining fuzz bytes are consumed sequentially as src frame data
     * inside bitcoin_fuzz_jets.  The same buffer is reused for both passes
     * so seeds stay compact. */
    const std::vector<uint8_t> src = fuzzed.ConsumeRemainingBytes<uint8_t>();

    /* Pass 1: ix=0, input 0 has no annex.
     * Exercises current_annex_hash hasAnnex=false path. */
    bitcoin_fuzz_jets(tx, tap, 0, src.data(), src.size());

    /* Pass 2: ix=1, input 1 has an annex.
     * Exercises current_annex_hash hasAnnex=true path. */
    bitcoin_fuzz_jets(tx, tap, 1, src.data(), src.size());

    simplicity_bitcoin_freeTapEnv(tap);
    simplicity_bitcoin_freeTransaction(tx);
}
