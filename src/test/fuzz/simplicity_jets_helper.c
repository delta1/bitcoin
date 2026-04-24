// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* This file is compiled as C so that it can safely include the internal
 * Simplicity headers (which use C99 compound literals and designated
 * initialisers that are only a GCC extension in C++ mode).
 */

#include "simplicity_jets_helper.h"

#include <string.h>

/* Internal Simplicity headers -- not part of the public install interface. */
#include "../../simplicity/bitcoin/txEnv.h"
#include "../../simplicity/bitcoin/bitcoinJets.h"
#include "../../simplicity/frame.h"
#include "../../simplicity/uword.h"

/* Upper bound on frame sizes measured in UWORDs.
 *
 * The largest source frame is 1126 bits (outpoint_hash: CTX8 * TWO^256 * TWO^32).
 * The largest destination frame is 838 bits (CTX8).
 *
 * With the smallest possible UWORD_BIT value (16):
 *   ROUND_UWORD(1126) = ceil(1126/16) = 71
 *
 * 80 words gives a comfortable margin and fits easily on the stack.
 */
#define MAX_FRAME_WORDS 80

/* Lightweight byte stream used to consume fuzz data into src frames. */
typedef struct {
    const uint8_t* data;
    size_t         len;
    size_t         pos;
} ByteStream;

static void stream_read(ByteStream* s, void* dst, size_t n)
{
    size_t avail = s->len > s->pos ? s->len - s->pos : 0;
    size_t copy  = n < avail ? n : avail;
    memcpy(dst, s->data + s->pos, copy);
    memset((uint8_t*)dst + copy, 0, n - copy);
    s->pos += copy;
}

/* Call a single jet:
 *   - src frame filled from the byte stream (so the fuzzer controls index
 *     values and SHA-256 context contents)
 *   - dst frame zero-initialised (we only care that jets do not crash)
 */
static void run_jet(jet_ptr jet, size_t src_bits, size_t dst_bits,
                    ByteStream* s, const txEnv* env)
{
    UWORD src_buf[MAX_FRAME_WORDS] = {0};
    UWORD dst_buf[MAX_FRAME_WORDS] = {0};

    stream_read(s, src_buf, ROUND_UWORD(src_bits) * sizeof(UWORD));

    frameItem src_frame = initReadFrame(src_bits, src_buf);
    /* initWriteFrame expects a pointer one-past-the-end of the allocated slice */
    frameItem dst_frame = initWriteFrame(dst_bits, dst_buf + ROUND_UWORD(dst_bits));

    jet(&dst_frame, src_frame, env);
}

void bitcoin_fuzz_jets(const bitcoinTransaction* tx, const bitcoinTapEnv* tap,
                       uint_fast32_t ix, const uint8_t* src_data, size_t src_len)
{
    txEnv env = simplicity_bitcoin_build_txEnv(tx, tap, ix);
    ByteStream s = { .data = src_data, .len = src_len, .pos = 0 };

#define JET(fn, src, dst) run_jet(fn, src, dst, &s, &env)

    /* ---- Transaction-level jets (src = ONE = 0 bits) ---- */
    JET(simplicity_bitcoin_version,            0,  32);
    JET(simplicity_bitcoin_lock_time,          0,  32);
    JET(simplicity_bitcoin_num_inputs,         0,  32);
    JET(simplicity_bitcoin_num_outputs,        0,  32);
    JET(simplicity_bitcoin_tx_is_final,        0,   1);

    /* lockHeight / lockTime branch on tx->lockTime < 500000000 and !isFinal */
    JET(simplicity_bitcoin_tx_lock_height,     0,  32);
    JET(simplicity_bitcoin_tx_lock_time,       0,  32);

    /* lockDistance / lockDuration branch on version >= 2, sequence bits */
    JET(simplicity_bitcoin_tx_lock_distance,   0,  16);
    JET(simplicity_bitcoin_tx_lock_duration,   0,  16);

    JET(simplicity_bitcoin_fee,                0,  64);
    JET(simplicity_bitcoin_total_input_value,  0,  64);
    JET(simplicity_bitcoin_total_output_value, 0,  64);

    /* ---- Taproot / commitment jets ---- */
    JET(simplicity_bitcoin_script_cmr,         0, 256);
    JET(simplicity_bitcoin_transaction_id,     0, 256);
    JET(simplicity_bitcoin_tapleaf_version,    0,   8);
    JET(simplicity_bitcoin_internal_key,       0, 256);
    JET(simplicity_bitcoin_tapleaf_hash,       0, 256);
    JET(simplicity_bitcoin_tappath_hash,       0, 256);
    JET(simplicity_bitcoin_tap_env_hash,       0, 256);
    JET(simplicity_bitcoin_sig_all_hash,       0, 256);

    /* ---- Aggregated hash jets ---- */
    JET(simplicity_bitcoin_output_values_hash,      0, 256);
    JET(simplicity_bitcoin_output_scripts_hash,     0, 256);
    JET(simplicity_bitcoin_outputs_hash,            0, 256);
    JET(simplicity_bitcoin_input_outpoints_hash,    0, 256);
    JET(simplicity_bitcoin_input_values_hash,       0, 256);
    JET(simplicity_bitcoin_input_scripts_hash,      0, 256);
    JET(simplicity_bitcoin_input_utxos_hash,        0, 256);
    JET(simplicity_bitcoin_input_sequences_hash,    0, 256);
    JET(simplicity_bitcoin_input_annexes_hash,      0, 256);
    JET(simplicity_bitcoin_input_script_sigs_hash,  0, 256);
    JET(simplicity_bitcoin_inputs_hash,             0, 256);
    JET(simplicity_bitcoin_tx_hash,                 0, 256);

    /* ---- Current-input jets (env->ix selects which input) ----
     * Called twice by the fuzz target: ix=0 (hasAnnex=false) and
     * ix=1 (hasAnnex=true), so both branches of current_annex_hash are hit.
     */
    JET(simplicity_bitcoin_current_index,           0,  32);
    JET(simplicity_bitcoin_current_prev_outpoint,   0, 288);
    JET(simplicity_bitcoin_current_value,           0,  64);
    JET(simplicity_bitcoin_current_script_hash,     0, 256);
    JET(simplicity_bitcoin_current_sequence,        0,  32);
    JET(simplicity_bitcoin_current_annex_hash,      0, 257);
    JET(simplicity_bitcoin_current_script_sig_hash, 0, 256);

    /* ---- Index-parameterised input jets (src = TWO^32 = 32 bits) ----
     * The 32-bit index in the src frame is filled from the fuzz stream.
     * Values 0 and 1 are in-bounds (numInputs=2); anything >= 2 is
     * out-of-bounds, exercising the else-branch of every bounds guard.
     * input_annex_hash also has an inner hasAnnex branch (index 1 hits it).
     */
    JET(simplicity_bitcoin_input_prev_outpoint,    32, 289);
    JET(simplicity_bitcoin_input_value,            32,  65);
    JET(simplicity_bitcoin_input_script_hash,      32, 257);
    JET(simplicity_bitcoin_input_sequence,         32,  33);
    JET(simplicity_bitcoin_input_annex_hash,       32, 258);
    JET(simplicity_bitcoin_input_script_sig_hash,  32, 257);
    JET(simplicity_bitcoin_input_utxo_hash,        32, 257);
    JET(simplicity_bitcoin_input_hash,             32, 257);

    /* ---- Index-parameterised output jets (src = TWO^32 = 32 bits) ----
     * numOutputs=1, so index 0 is in-bounds and anything >= 1 is out-of-bounds.
     */
    JET(simplicity_bitcoin_output_value,           32,  65);
    JET(simplicity_bitcoin_output_script_hash,     32, 257);
    JET(simplicity_bitcoin_output_hash,            32, 257);

    /* ---- tappath (src = TWO^8 = 8 bits) ----
     * pathLen=0, so any index >= 0 exercises the out-of-bounds branch.
     */
    JET(simplicity_bitcoin_tappath, 8, 257);

    /* ---- check_lock_* jets (dst = ONE = 0 bits; return false on failure) ----
     * The src threshold is filled from the fuzz stream, so both the
     * "condition satisfied" and "condition not satisfied" return paths are
     * exercisable.
     */
    JET(simplicity_bitcoin_check_lock_height,   32, 0);
    JET(simplicity_bitcoin_check_lock_time,     32, 0);
    JET(simplicity_bitcoin_check_lock_distance, 16, 0);
    JET(simplicity_bitcoin_check_lock_duration, 16, 0);

    /* ---- Build jets (env-independent) ---- */
    /* build_tapleaf_simplicity: TWO^256 |- TWO^256 */
    JET(simplicity_bitcoin_build_tapleaf_simplicity, 256, 256);
    /* build_tapbranch: TWO^256 * TWO^256 |- TWO^256 */
    JET(simplicity_bitcoin_build_tapbranch,          512, 256);
    /* build_taptweak: PUBKEY * TWO^256 |- PUBKEY  (can fail for invalid points) */
    JET(simplicity_bitcoin_build_taptweak,           512, 256);

    /* ---- SHA-256 context jets ----
     * CTX8 = 838 bits.
     * outpoint_hash: CTX8 * TWO^256 * TWO^32 |- CTX8  => src=838+256+32=1126
     * annex_hash:    CTX8 * S(TWO^256) |- CTX8         => src=838+1+256=1095
     * The fuzz stream may produce an overflowed context (counter >= 2^55)
     * which exercises the simplicity_read_sha256_context failure path.
     */
    JET(simplicity_bitcoin_outpoint_hash, 1126, 838);
    JET(simplicity_bitcoin_annex_hash,    1095, 838);

#undef JET
}
