// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <span>
#include <cstddef>
#include <primitives/transaction.h>
#include <script/sigcache.h>
#include <validation.h>
extern "C" {
#include <simplicity/bitcoin/cmr.h>
#include <simplicity/bitcoin/env.h>
#include <simplicity/bitcoin/exec.h>
}
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/random.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

static CAmount INPUT_VALUE{12345678};

const script_verify_flags VERIFY_FLAGS = SCRIPT_VERIFY_NONE
    | SCRIPT_VERIFY_P2SH
    | SCRIPT_VERIFY_WITNESS
    | SCRIPT_VERIFY_DERSIG
    | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
    | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    | SCRIPT_VERIFY_TAPROOT
    | SCRIPT_VERIFY_NULLDUMMY
    | SCRIPT_VERIFY_SIMPLICITY;

FUZZ_TARGET(simplicity_tx)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    SignatureCache signature_cache{DEFAULT_SIGNATURE_CACHE_BYTES};
    simplicity_err error;

    // 1. (no-op) run through Rust code
    //
    // 2. Construct transaction.
    CMutableTransaction mtx;
    {
        DataStream txds{buffer};
        try {
            txds >> TX_WITH_WITNESS(mtx);
        } catch (const std::ios_base::failure&) {
            return;
        }
        // mtx.witness.vtxoutwit.resize(mtx.vout.size());

        // If no inputs have witnesses, all the code below should continue to work -- we
        // should be able to call `PrecomputedTransactionData::Init` on a legacy transaction
        // without any trouble. In this case it will set txdata.m_simplicity_tx_data to
        // NULL, and we won't be able to go any further, but there should be no crashes
        // or memory issues.
        // if (!mtx.witness.vtxinwit.empty()) {
        //     mtx.witness.vtxinwit.resize(mtx.vin.size());
        //     // This is an assertion in the Simplicity interpreter. It is guaranteed
        //     // to hold for anything on the network since (even if validatepegin is off)
        //     // pegins are validated for well-formedness long before the script interpreter
        //     // is invoked. But in this code we just call the interpreter directly without
        //     // these checks.
        //     for (unsigned i = 0; i < mtx.vin.size(); i++) {
        //         if (mtx.vin[i].m_is_pegin && (mtx.witness.vtxinwit[i].m_pegin_witness.stack.size() < 4 || mtx.witness.vtxinwit[i].m_pegin_witness.stack[2].size() != 32)) {
        //             return;
        //         }
        //     }
        // }

        // We use the first vin as a "random oracle" rather than reading more from
        // the fuzzer, because we want our fuzz seeds to have as simple a structure
        // as possible. This means we must reject 0-input transactions, which are
        // invalid on-chain anyway.
        if (mtx.vin.size() == 0) {
            return;
        }
    }
    const auto& random_bytes = mtx.vin[0].prevout.hash;
    CScript scriptPubKey;

    // 3. Construct `nIn` and `spent_outs` arrays.
    bool expect_simplicity = false;
    std::vector<CTxOut> spent_outs{};
    unsigned char last_cmr[32] = { 0 };
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        // Check for size 4: a Simplicity program will always have a witness, program,
        // CMR, control block and (maybe) annex, in that order. If the annex is present,
        // then checking for size 4 doesn't guarantee that a witness is present, but
        // that is ok at this point. (In fact, it is a useful thing to check.)
        auto& current = mtx.vin[i].scriptWitness.stack;
        if (current.size() >= 4) {
            size_t top = current.size();
            if (!current[top - 1].empty() && current[top - 1][0] == 0x50) {
                --top;
            }
            const auto& control = current[top - 1];
            const auto& program = current[top - 3];

            if (control.size() >= TAPROOT_CONTROL_BASE_SIZE &&
                control.size() <= TAPROOT_CONTROL_MAX_SIZE &&
                (control.size() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE == 0 &&
                (control[0] & 0xfe) == 0xbe) {
                // The fuzzer won't be able to produce a valid CMR on its own, so we compute it
                // and jam it into the witness stack. But we do require the fuzzer give us a
                // place to put it, so we don't have to resize the stack (and so that actual
                // valid transactions will work with this code).
                // Compute CMR and do some sanity checks on it (and the program)
                std::vector<unsigned char> cmr(32, 0);
                assert(simplicity_bitcoin_computeCmr(&error, cmr.data(), program.data(), program.size()));
                if (error == SIMPLICITY_NO_ERROR) {
                    if (memcmp(last_cmr, cmr.data(), sizeof(last_cmr)) == 0) {
                        // If we have already seen this CMR this transaction, try mangling
                        // it to check that this produces a CMR error and not something worse.
                        cmr.data()[1] ^= 1;
                    }
                    memcpy(last_cmr, cmr.data(), sizeof(last_cmr));
                }

                const XOnlyPubKey internal{std::span(control).subspan(1, TAPROOT_CONTROL_BASE_SIZE - 1)};

                const CScript leaf_script{cmr.begin(), cmr.end()};
                const uint256 tapleaf_hash = ComputeTapleafHash(0xbe, leaf_script);
                uint256 merkle_root = ComputeTaprootMerkleRoot(control, tapleaf_hash);
                auto ret = internal.CreateTapTweak(&merkle_root);
                if (ret.has_value()) {
                    expect_simplicity = (error == SIMPLICITY_NO_ERROR);
                    // Just drop the parity; it needs to match the one in the control block,
                    // but we want to test that logic, so we allow them not to match.
                    const XOnlyPubKey output_key = ret->first;
                    // If we made it here, success (aside from parity maybe)
                    current[top - 2] = std::move(cmr);
                    scriptPubKey = CScript() << OP_1 << ToByteVector(output_key);
                }
            }
        }
        // For scripts that we're not using, set them to various witness programs to try to
        // trick the interpreter into treating them as taproot or simplicity outputs. It
        // should fail but shouldn't crash or anything.
        //
        // We don't cover all cases, so this may result in the empty scriptpubkey -- this is
        // impossible on-chain but it shouldn't hurt anything.
        if (scriptPubKey.empty()) {
            if (i < random_bytes.size()) {
                switch(std::to_integer<int>(random_bytes.data()[i]) >> 6) {
                case 0:
                    scriptPubKey << OP_TRUE;
                    break;
                case 1:
                    scriptPubKey << OP_0 << std::vector<unsigned char>(20, 0xab);
                    break;
                case 2:
                    scriptPubKey << OP_0 << std::vector<unsigned char>(32, 0xcd);
                    break;
                case 3:
                    scriptPubKey << OP_1 << std::vector<unsigned char>(32, 0xef);
                    break;
                }
            }
        }

        spent_outs.push_back(CTxOut{INPUT_VALUE, scriptPubKey});
    }
    assert(spent_outs.size() == mtx.vin.size());

    // 4. Test via scriptcheck
    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outs_copy{spent_outs};
    txdata.Init(mtx, std::move(spent_outs_copy));
    if (expect_simplicity) {
        // The converse of this is not true -- if !expect_simplicity, it's still possible
        // that we will allocate Simplicity data. The check for whether to do this is very
        // lax: is this a 34-byte scriptPubKey that starts with OP_1 and does it have a
        // nonempty witness.
        assert(txdata.m_simplicity_tx_data);
    }

    const CTransaction tx{mtx};
    for (unsigned i = 0; i < tx.vin.size(); i++) {
        CScriptCheck check{txdata.m_spent_outputs[i], tx, signature_cache, i, VERIFY_FLAGS, false /* cache */, &txdata};
        // CScriptCheck(const CTxOut& outIn, const CTransaction& txToIn, SignatureCache& signature_cache, unsigned int nInIn, script_verify_flags flags, bool cacheIn, PrecomputedTransactionData* txdataIn)
        check();
    }
}
