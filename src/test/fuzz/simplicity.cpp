// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstdio>
#include <compat/endian.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
extern "C" {
#include <simplicity/bitcoin/cmr.h>
#include <simplicity/bitcoin/env.h>
#include <simplicity/bitcoin/exec.h>
}
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

static CAmount INPUT_VALUE{12345678};
static CScript TAPROOT_SCRIPT_PUB_KEY{};
static std::vector<unsigned char> TAPROOT_CONTROL{};
static std::vector<unsigned char> TAPROOT_ANNEX(99, 0x50);
//CMutableTransaction MTX_TEMPLATE{};

// Defined in simplicity_compute_amr.c
extern "C" {
bool simplicity_bitcoin_computeAmr(simplicity_err* error, unsigned char* amr
                                   , const unsigned char* program, size_t program_len
                                   , const unsigned char* witness, size_t witness_len);
}

void initialize_simplicity()
{
    XOnlyPubKey intkey = XOnlyPubKey{uint256::ONE};
    XOnlyPubKey extkey = XOnlyPubKey{uint256::ONE};
    TAPROOT_SCRIPT_PUB_KEY = CScript{} << OP_1 << std::vector<unsigned char>(extkey.begin(), extkey.end());
    // TODO have control block of nontrivial path length
    TAPROOT_CONTROL.push_back(TAPROOT_LEAF_TAPSIMPLICITY | 1); // 1 is parity
    TAPROOT_CONTROL.insert(TAPROOT_CONTROL.end(), intkey.begin(), intkey.end());
}

uint32_t read_u32(const unsigned char **buf) {
    uint32_t ret;
    memcpy(&ret, *buf, 4);
    *buf += 4;
    return le32toh(ret);
}

#define MAX_LEN (1024 * 1024)

FUZZ_TARGET(simplicity, .init = initialize_simplicity)
{
    const unsigned char *buf = buffer.data();

    uint32_t budget;
    uint32_t tx_data_len;
    uint32_t prog_data_len;
    uint32_t wit_data_len;

    // 1. Sanitize and parse the buffer
    if (buffer.size() < 8) {
        return;
    }
    budget = read_u32(&buf);

    tx_data_len = read_u32(&buf);
    if (tx_data_len > MAX_LEN || buffer.size() < tx_data_len + 12) {
        return;
    }
    const unsigned char *tx_data = buf;
    buf += tx_data_len;

    prog_data_len = read_u32(&buf);
    if (prog_data_len > MAX_LEN || buffer.size() < tx_data_len + prog_data_len + 16) {
        return;
    }
    const unsigned char *prog_data = buf;
    buf += prog_data_len;

    wit_data_len = read_u32(&buf);
    if (wit_data_len > MAX_LEN || buffer.size() != tx_data_len + prog_data_len + wit_data_len + 16) {
        return;
    }
    const unsigned char *wit_data = buf;

    //printf("OK going\n");

    // 2. Parse the transaction (the program and witness are just raw bytes)
    CMutableTransaction mtx;
    // make a vector of tx_data
    std::vector<unsigned char> tx_data_vec{tx_data, tx_data + tx_data_len};

    try {
        DataStream txds(tx_data_vec);
        txds >> TX_WITH_WITNESS(mtx);
        // mtx.witness.vtxinwit.resize(mtx.vin.size());
        // mtx.witness.vtxoutwit.resize(mtx.vout.size());

        // We use the first vin as a "random oracle" rather than reading more from
        // the fuzzer, because we want our fuzz seeds to have as simple a structure
        // as possible. This means we must reject 0-input transactions, which are
        // invalid on-chain anyway.
        if (mtx.vin.size() == 0) {
            return;
        }
    } catch (const std::ios_base::failure&) {
        return;
    }

    // 2a. Pull the program and witness into vectors so they can be pushed onto the stack.
    std::vector<unsigned char> prog_bytes;
    std::vector<unsigned char> wit_bytes;
    prog_bytes.assign(prog_data, prog_data + prog_data_len);
    wit_bytes.assign(wit_data, wit_data + wit_data_len);

    simplicity_err error;
    unsigned char cmr[32];
    unsigned char amr[32];
    assert(simplicity_bitcoin_computeAmr(&error, amr, prog_data, prog_data_len, wit_data, wit_data_len));
    assert(simplicity_bitcoin_computeCmr(&error, cmr, prog_data, prog_data_len));

    // The remainder is just copy/pasted from the original fuzztest

    // 3. Construct `nIn` and `spent_outs` array.
    //
    // Here we extract data from the first input's txid, since the fuzzer already
    // produced that as a random string which has no other meaning. So to avoid
    // complicating our seed encoding beyond "transaction then simplicity code"
    // we just use it as a random source.
    //
    // We do skip the first byte since that has pegin/issuance flag in it and
    // therefore already has semantic information.
    size_t nIn = static_cast<uint8_t>(mtx.vin[0].prevout.hash.data()[1]) % mtx.vin.size();
    std::vector<CTxOut> spent_outs{};
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        CScript scriptPubKey;
        if (i != nIn) {
            // For scriptPubKeys we can use arbitrary scripts. We include the empty
            // script even though in a real transaction this would be impossible,
            // because it shouldn't break anything.
            for (unsigned int j = 0; j < i; j++) {
                scriptPubKey << OP_TRUE;
            }
        } else {
            scriptPubKey = TAPROOT_SCRIPT_PUB_KEY;
        }

        spent_outs.push_back(CTxOut{INPUT_VALUE, scriptPubKey});

        // 4. Set up witness data
        mtx.vin[i].scriptWitness.stack.clear();
        mtx.vin[i].scriptWitness.stack.push_back(prog_bytes);
        mtx.vin[i].scriptWitness.stack.push_back(TAPROOT_CONTROL);
        if (static_cast<uint8_t>(mtx.vin[0].prevout.hash.data()[2]) & 1) {
            mtx.vin[i].scriptWitness.stack.push_back(TAPROOT_ANNEX);
        }
    }
    assert(spent_outs.size() == mtx.vin.size());

    // 5. Set up Simplicity environment and tx environment
    rawBitcoinTapEnv simplicityRawTap;
    simplicityRawTap.controlBlock = TAPROOT_CONTROL.data();
    simplicityRawTap.pathLen = (TAPROOT_CONTROL.size() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    simplicityRawTap.scriptCMR = cmr;

    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outs_copy{spent_outs};
    txdata.Init(mtx, std::move(spent_outs_copy));
    assert(txdata.m_simplicity_tx_data);

    // 4. Main test
    unsigned char imr_out[32];
    unsigned char *imr = (static_cast<uint8_t>(mtx.vin[0].prevout.hash.data()[2]) & 2) ? imr_out : NULL;

    const bitcoinTransaction* tx = txdata.m_simplicity_tx_data.get();
    bitcoinTapEnv* taproot = simplicity_bitcoin_mallocTapEnv(&simplicityRawTap);
    simplicity_bitcoin_execSimplicity(&error, imr, tx, nIn, taproot, 0, budget, amr, prog_bytes.data(), prog_bytes.size(), wit_bytes.data(), wit_bytes.size());

    // 5. Secondary test -- try flipping a bunch of bits and check that this doesn't mess things up
    for (size_t j = 0; j < 8 * prog_bytes.size(); j++) {
        if (j > 32 && j % 23 != 0) continue; // skip most bits so this test doesn't overwhelm the fuzz time
        prog_bytes.data()[j / 8] ^= (1 << (j % 8));
        simplicity_bitcoin_execSimplicity(&error, imr, tx, nIn, taproot, 0, budget, amr, prog_bytes.data(), prog_bytes.size(), wit_bytes.data(), wit_bytes.size());
    }

    // 5b. Flip witness bits against the original program to exercise fillWitnessData
    //     and runTCO branches that depend on witness values.
    for (size_t j = 0; j < 8 * wit_bytes.size(); j++) {
        if (j > 32 && j % 23 != 0) continue;
        wit_bytes.data()[j / 8] ^= (1 << (j % 8));
        simplicity_bitcoin_execSimplicity(&error, imr, tx, nIn, taproot, 0, budget, amr, prog_data, prog_data_len, wit_bytes.data(), wit_bytes.size());
    }

    // 6. Cleanup
    free(taproot);
}
