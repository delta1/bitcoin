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
#include "../../simplicity/dag.h"     /* simplicity_computeWordCMR, bitstring */
#include "../../simplicity/frame.h"
#include "../../simplicity/jets.h"
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

/* Upper bound for core jets (jets.c / jets-secp256k1.c) with the largest frames.
 *
 * The largest frames belong to the SHA-256 context jets:
 *   sha_256_ctx_8_add_buffer_511: src = CTX8(838) + (TWO^8)^<512(4097) = 4935 bits
 *   sha_256_ctx_8_add_512:        src = CTX8(838) + 512*8(4096) = 4934 bits
 *
 * With the smallest possible UWORD_BIT value (16):
 *   ROUND_UWORD(4935) = ceil(4935/16) = 309
 *
 * 320 words provides a safe margin and covers all jets including the secp256k1
 * double-GEJ jets (src = 2*768 = 1536 bits, ceil(1536/16) = 96).
 */
#define MAX_LARGE_FRAME_WORDS 320

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

/* Like run_jet but uses MAX_LARGE_FRAME_WORDS buffers for jets with frames
 * that exceed 1280 bits (the capacity of MAX_FRAME_WORDS at UWORD_BIT=16).
 */
static void run_jet_large(jet_ptr jet, size_t src_bits, size_t dst_bits,
                           ByteStream* s, const txEnv* env)
{
    UWORD src_buf[MAX_LARGE_FRAME_WORDS] = {0};
    UWORD dst_buf[MAX_LARGE_FRAME_WORDS] = {0};

    stream_read(s, src_buf, ROUND_UWORD(src_bits) * sizeof(UWORD));

    frameItem src_frame = initReadFrame(src_bits, src_buf);
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

    /* ---- tappath (src = TWO^8 = 8 bits, input index) ----
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

    /* ---- computeWordCMR (dag.c) + simplicity_sha256_bitstring (sha256.c) ----
     * WORD CMR computation is triggered during DAG decoding for WORD-tagged
     * nodes, but the fuzzer rarely produces the specific bit encoding needed.
     * Calling it directly here with fuzz-stream data ensures the code is
     * always exercised.
     *
     * n=3: scribe word of 2^3 = 8 bits  (fits in 1 byte)
     * n=6: scribe word of 2^6 = 64 bits (exercises multi-compression path)
     */
    {
        unsigned char word_bytes[8] = {0};
        stream_read(&s, word_bytes, sizeof(word_bytes));
        bitstring val3 = {.arr = word_bytes, .offset = 0, .len = 8};
        simplicity_computeWordCMR(&val3, 3);
        bitstring val6 = {.arr = word_bytes, .offset = 0, .len = 64};
        simplicity_computeWordCMR(&val6, 6);
    }
}

void simplicity_fuzz_core_jets(const uint8_t* src_data, size_t src_len)
{
    ByteStream s = { .data = src_data, .len = src_len, .pos = 0 };

    /* All core jets ignore env; pass NULL throughout. */
#define JET(fn, src, dst)  run_jet(fn, src, dst, &s, NULL)
#define JETL(fn, src, dst) run_jet_large(fn, src, dst, &s, NULL)

    /* ---- Logic group ---- */
    JET(simplicity_verify,          1,   0);
    JET(simplicity_low_1,           0,   1);
    JET(simplicity_low_8,           0,   8);
    JET(simplicity_low_16,          0,  16);
    JET(simplicity_low_32,          0,  32);
    JET(simplicity_low_64,          0,  64);
    JET(simplicity_high_1,          0,   1);
    JET(simplicity_high_8,          0,   8);
    JET(simplicity_high_16,         0,  16);
    JET(simplicity_high_32,         0,  32);
    JET(simplicity_high_64,         0,  64);
    JET(simplicity_complement_1,    1,   1);
    JET(simplicity_complement_8,    8,   8);
    JET(simplicity_complement_16,  16,  16);
    JET(simplicity_complement_32,  32,  32);
    JET(simplicity_complement_64,  64,  64);
    JET(simplicity_and_1,           2,   1);
    JET(simplicity_and_8,          16,   8);
    JET(simplicity_and_16,         32,  16);
    JET(simplicity_and_32,         64,  32);
    JET(simplicity_and_64,        128,  64);
    JET(simplicity_or_1,            2,   1);
    JET(simplicity_or_8,           16,   8);
    JET(simplicity_or_16,          32,  16);
    JET(simplicity_or_32,          64,  32);
    JET(simplicity_or_64,         128,  64);
    JET(simplicity_xor_1,           2,   1);
    JET(simplicity_xor_8,          16,   8);
    JET(simplicity_xor_16,         32,  16);
    JET(simplicity_xor_32,         64,  32);
    JET(simplicity_xor_64,        128,  64);
    /* maj and xor_xor and ch each read 3 values */
    JET(simplicity_maj_1,           3,   1);
    JET(simplicity_maj_8,          24,   8);
    JET(simplicity_maj_16,         48,  16);
    JET(simplicity_maj_32,         96,  32);
    JET(simplicity_maj_64,        192,  64);
    JET(simplicity_xor_xor_1,      3,   1);
    JET(simplicity_xor_xor_8,     24,   8);
    JET(simplicity_xor_xor_16,    48,  16);
    JET(simplicity_xor_xor_32,    96,  32);
    JET(simplicity_xor_xor_64,   192,  64);
    JET(simplicity_ch_1,           3,   1);
    JET(simplicity_ch_8,          24,   8);
    JET(simplicity_ch_16,         48,  16);
    JET(simplicity_ch_32,         96,  32);
    JET(simplicity_ch_64,        192,  64);
    JET(simplicity_some_1,         1,   1);
    JET(simplicity_some_8,         8,   1);
    JET(simplicity_some_16,       16,   1);
    JET(simplicity_some_32,       32,   1);
    JET(simplicity_some_64,       64,   1);
    JET(simplicity_all_8,          8,   1);
    JET(simplicity_all_16,        16,   1);
    JET(simplicity_all_32,        32,   1);
    JET(simplicity_all_64,        64,   1);
    JET(simplicity_eq_1,           2,   1);
    JET(simplicity_eq_8,          16,   1);
    JET(simplicity_eq_16,         32,   1);
    JET(simplicity_eq_32,         64,   1);
    JET(simplicity_eq_64,        128,   1);
    JET(simplicity_eq_256,       512,   1);

    /* ---- Shift / rotate group ----
     * full_{left,right}_shift_N_M: src=N+M, dst=N+M (bit-copy reordering)
     * leftmost_N_M / rightmost_N_M: src=N, dst=M
     * {left,right}_pad_{low,high}_1_M: src=1, dst=M
     * {left,right}_pad_{low,high}_N_M: src=N, dst=M
     * {left,right}_extend_1_M: src=1, dst=M
     * {left,right}_extend_N_M: src=N, dst=M
     * left_shift_with_N: src = 1 + log2(N) + N, dst = N
     *   (log=4 for N=8/16; log=8 for N=32/64)
     * left_shift_N: src = log2(N) + N, dst = N
     * right_shift_with_N / right_shift_N: same bit sizes
     * left_rotate_N / right_rotate_N: src = log2(N) + N, dst = N
     */
    JET(simplicity_full_left_shift_8_1,    9,   9);
    JET(simplicity_full_left_shift_8_2,   10,  10);
    JET(simplicity_full_left_shift_8_4,   12,  12);
    JET(simplicity_full_left_shift_16_1,  17,  17);
    JET(simplicity_full_left_shift_16_2,  18,  18);
    JET(simplicity_full_left_shift_16_4,  20,  20);
    JET(simplicity_full_left_shift_16_8,  24,  24);
    JET(simplicity_full_left_shift_32_1,  33,  33);
    JET(simplicity_full_left_shift_32_2,  34,  34);
    JET(simplicity_full_left_shift_32_4,  36,  36);
    JET(simplicity_full_left_shift_32_8,  40,  40);
    JET(simplicity_full_left_shift_32_16, 48,  48);
    JET(simplicity_full_left_shift_64_1,  65,  65);
    JET(simplicity_full_left_shift_64_2,  66,  66);
    JET(simplicity_full_left_shift_64_4,  68,  68);
    JET(simplicity_full_left_shift_64_8,  72,  72);
    JET(simplicity_full_left_shift_64_16, 80,  80);
    JET(simplicity_full_left_shift_64_32, 96,  96);
    JET(simplicity_full_right_shift_8_1,    9,   9);
    JET(simplicity_full_right_shift_8_2,   10,  10);
    JET(simplicity_full_right_shift_8_4,   12,  12);
    JET(simplicity_full_right_shift_16_1,  17,  17);
    JET(simplicity_full_right_shift_16_2,  18,  18);
    JET(simplicity_full_right_shift_16_4,  20,  20);
    JET(simplicity_full_right_shift_16_8,  24,  24);
    JET(simplicity_full_right_shift_32_1,  33,  33);
    JET(simplicity_full_right_shift_32_2,  34,  34);
    JET(simplicity_full_right_shift_32_4,  36,  36);
    JET(simplicity_full_right_shift_32_8,  40,  40);
    JET(simplicity_full_right_shift_32_16, 48,  48);
    JET(simplicity_full_right_shift_64_1,  65,  65);
    JET(simplicity_full_right_shift_64_2,  66,  66);
    JET(simplicity_full_right_shift_64_4,  68,  68);
    JET(simplicity_full_right_shift_64_8,  72,  72);
    JET(simplicity_full_right_shift_64_16, 80,  80);
    JET(simplicity_full_right_shift_64_32, 96,  96);
    JET(simplicity_leftmost_8_1,    8,   1);
    JET(simplicity_leftmost_8_2,    8,   2);
    JET(simplicity_leftmost_8_4,    8,   4);
    JET(simplicity_leftmost_16_1,  16,   1);
    JET(simplicity_leftmost_16_2,  16,   2);
    JET(simplicity_leftmost_16_4,  16,   4);
    JET(simplicity_leftmost_16_8,  16,   8);
    JET(simplicity_leftmost_32_1,  32,   1);
    JET(simplicity_leftmost_32_2,  32,   2);
    JET(simplicity_leftmost_32_4,  32,   4);
    JET(simplicity_leftmost_32_8,  32,   8);
    JET(simplicity_leftmost_32_16, 32,  16);
    JET(simplicity_leftmost_64_1,  64,   1);
    JET(simplicity_leftmost_64_2,  64,   2);
    JET(simplicity_leftmost_64_4,  64,   4);
    JET(simplicity_leftmost_64_8,  64,   8);
    JET(simplicity_leftmost_64_16, 64,  16);
    JET(simplicity_leftmost_64_32, 64,  32);
    JET(simplicity_rightmost_8_1,    8,   1);
    JET(simplicity_rightmost_8_2,    8,   2);
    JET(simplicity_rightmost_8_4,    8,   4);
    JET(simplicity_rightmost_16_1,  16,   1);
    JET(simplicity_rightmost_16_2,  16,   2);
    JET(simplicity_rightmost_16_4,  16,   4);
    JET(simplicity_rightmost_16_8,  16,   8);
    JET(simplicity_rightmost_32_1,  32,   1);
    JET(simplicity_rightmost_32_2,  32,   2);
    JET(simplicity_rightmost_32_4,  32,   4);
    JET(simplicity_rightmost_32_8,  32,   8);
    JET(simplicity_rightmost_32_16, 32,  16);
    JET(simplicity_rightmost_64_1,  64,   1);
    JET(simplicity_rightmost_64_2,  64,   2);
    JET(simplicity_rightmost_64_4,  64,   4);
    JET(simplicity_rightmost_64_8,  64,   8);
    JET(simplicity_rightmost_64_16, 64,  16);
    JET(simplicity_rightmost_64_32, 64,  32);
    JET(simplicity_left_pad_low_1_8,   1,   8);
    JET(simplicity_left_pad_low_1_16,  1,  16);
    JET(simplicity_left_pad_low_1_32,  1,  32);
    JET(simplicity_left_pad_low_1_64,  1,  64);
    JET(simplicity_left_pad_low_8_16,   8,  16);
    JET(simplicity_left_pad_low_8_32,   8,  32);
    JET(simplicity_left_pad_low_8_64,   8,  64);
    JET(simplicity_left_pad_low_16_32, 16,  32);
    JET(simplicity_left_pad_low_16_64, 16,  64);
    JET(simplicity_left_pad_low_32_64, 32,  64);
    JET(simplicity_left_pad_high_1_8,   1,   8);
    JET(simplicity_left_pad_high_1_16,  1,  16);
    JET(simplicity_left_pad_high_1_32,  1,  32);
    JET(simplicity_left_pad_high_1_64,  1,  64);
    JET(simplicity_left_pad_high_8_16,   8,  16);
    JET(simplicity_left_pad_high_8_32,   8,  32);
    JET(simplicity_left_pad_high_8_64,   8,  64);
    JET(simplicity_left_pad_high_16_32, 16,  32);
    JET(simplicity_left_pad_high_16_64, 16,  64);
    JET(simplicity_left_pad_high_32_64, 32,  64);
    JET(simplicity_left_extend_1_8,   1,   8);
    JET(simplicity_left_extend_1_16,  1,  16);
    JET(simplicity_left_extend_1_32,  1,  32);
    JET(simplicity_left_extend_1_64,  1,  64);
    JET(simplicity_left_extend_8_16,   8,  16);
    JET(simplicity_left_extend_8_32,   8,  32);
    JET(simplicity_left_extend_8_64,   8,  64);
    JET(simplicity_left_extend_16_32, 16,  32);
    JET(simplicity_left_extend_16_64, 16,  64);
    JET(simplicity_left_extend_32_64, 32,  64);
    JET(simplicity_right_pad_low_1_8,   1,   8);
    JET(simplicity_right_pad_low_1_16,  1,  16);
    JET(simplicity_right_pad_low_1_32,  1,  32);
    JET(simplicity_right_pad_low_1_64,  1,  64);
    JET(simplicity_right_pad_low_8_16,   8,  16);
    JET(simplicity_right_pad_low_8_32,   8,  32);
    JET(simplicity_right_pad_low_8_64,   8,  64);
    JET(simplicity_right_pad_low_16_32, 16,  32);
    JET(simplicity_right_pad_low_16_64, 16,  64);
    JET(simplicity_right_pad_low_32_64, 32,  64);
    JET(simplicity_right_pad_high_1_8,   1,   8);
    JET(simplicity_right_pad_high_1_16,  1,  16);
    JET(simplicity_right_pad_high_1_32,  1,  32);
    JET(simplicity_right_pad_high_1_64,  1,  64);
    JET(simplicity_right_pad_high_8_16,   8,  16);
    JET(simplicity_right_pad_high_8_32,   8,  32);
    JET(simplicity_right_pad_high_8_64,   8,  64);
    JET(simplicity_right_pad_high_16_32, 16,  32);
    JET(simplicity_right_pad_high_16_64, 16,  64);
    JET(simplicity_right_pad_high_32_64, 32,  64);
    JET(simplicity_right_extend_8_16,   8,  16);
    JET(simplicity_right_extend_8_32,   8,  32);
    JET(simplicity_right_extend_8_64,   8,  64);
    JET(simplicity_right_extend_16_32, 16,  32);
    JET(simplicity_right_extend_16_64, 16,  64);
    JET(simplicity_right_extend_32_64, 32,  64);
    /* log=4 bits for 8/16-bit data; log=8 bits for 32/64-bit data */
    JET(simplicity_left_shift_with_8,  13,  8);  /* 1+4+8  */
    JET(simplicity_left_shift_with_16, 21, 16);  /* 1+4+16 */
    JET(simplicity_left_shift_with_32, 41, 32);  /* 1+8+32 */
    JET(simplicity_left_shift_with_64, 73, 64);  /* 1+8+64 */
    JET(simplicity_left_shift_8,       12,  8);  /* 4+8  */
    JET(simplicity_left_shift_16,      20, 16);  /* 4+16 */
    JET(simplicity_left_shift_32,      40, 32);  /* 8+32 */
    JET(simplicity_left_shift_64,      72, 64);  /* 8+64 */
    JET(simplicity_right_shift_with_8,  13,  8);
    JET(simplicity_right_shift_with_16, 21, 16);
    JET(simplicity_right_shift_with_32, 41, 32);
    JET(simplicity_right_shift_with_64, 73, 64);
    JET(simplicity_right_shift_8,       12,  8);
    JET(simplicity_right_shift_16,      20, 16);
    JET(simplicity_right_shift_32,      40, 32);
    JET(simplicity_right_shift_64,      72, 64);
    JET(simplicity_left_rotate_8,   12,  8);
    JET(simplicity_left_rotate_16,  20, 16);
    JET(simplicity_left_rotate_32,  40, 32);
    JET(simplicity_left_rotate_64,  72, 64);
    JET(simplicity_right_rotate_8,  12,  8);
    JET(simplicity_right_rotate_16, 20, 16);
    JET(simplicity_right_rotate_32, 40, 32);
    JET(simplicity_right_rotate_64, 72, 64);

    /* ---- Arithmetic group ---- */
    JET(simplicity_one_8,  0,  8);
    JET(simplicity_one_16, 0, 16);
    JET(simplicity_one_32, 0, 32);
    JET(simplicity_one_64, 0, 64);
    /* add_N: src=2N, dst=N+1 (carry bit + N-bit result) */
    JET(simplicity_add_8,   16,   9);
    JET(simplicity_add_16,  32,  17);
    JET(simplicity_add_32,  64,  33);
    JET(simplicity_add_64, 128,  65);
    /* full_add_N: src=2N+1 (carry_in+x+y), dst=N+1 */
    JET(simplicity_full_add_8,   17,   9);
    JET(simplicity_full_add_16,  33,  17);
    JET(simplicity_full_add_32,  65,  33);
    JET(simplicity_full_add_64, 129,  65);
    /* full_increment_N: src=N+1 (carry+value), dst=N+1 */
    JET(simplicity_full_increment_8,   9,   9);
    JET(simplicity_full_increment_16, 17,  17);
    JET(simplicity_full_increment_32, 33,  33);
    JET(simplicity_full_increment_64, 65,  65);
    /* increment_N: src=N, dst=N+1 */
    JET(simplicity_increment_8,   8,   9);
    JET(simplicity_increment_16, 16,  17);
    JET(simplicity_increment_32, 32,  33);
    JET(simplicity_increment_64, 64,  65);
    /* subtract_N: src=2N, dst=N+1 (borrow+result) */
    JET(simplicity_subtract_8,   16,   9);
    JET(simplicity_subtract_16,  32,  17);
    JET(simplicity_subtract_32,  64,  33);
    JET(simplicity_subtract_64, 128,  65);
    /* negate_N: src=N, dst=N+1 */
    JET(simplicity_negate_8,   8,   9);
    JET(simplicity_negate_16, 16,  17);
    JET(simplicity_negate_32, 32,  33);
    JET(simplicity_negate_64, 64,  65);
    /* full_decrement_N: src=N+1, dst=N+1 */
    JET(simplicity_full_decrement_8,   9,   9);
    JET(simplicity_full_decrement_16, 17,  17);
    JET(simplicity_full_decrement_32, 33,  33);
    JET(simplicity_full_decrement_64, 65,  65);
    /* decrement_N: src=N, dst=N+1 */
    JET(simplicity_decrement_8,   8,   9);
    JET(simplicity_decrement_16, 16,  17);
    JET(simplicity_decrement_32, 32,  33);
    JET(simplicity_decrement_64, 64,  65);
    /* full_subtract_N: src=2N+1, dst=N+1 */
    JET(simplicity_full_subtract_8,   17,   9);
    JET(simplicity_full_subtract_16,  33,  17);
    JET(simplicity_full_subtract_32,  65,  33);
    JET(simplicity_full_subtract_64, 129,  65);
    /* multiply_N: src=2N, dst=2N (full product) */
    JET(simplicity_multiply_8,   16,  16);
    JET(simplicity_multiply_16,  32,  32);
    JET(simplicity_multiply_32,  64,  64);
    JET(simplicity_multiply_64, 128, 128);
    /* full_multiply_N: src=4N (x+y+z+w), dst=2N (x*y+z+w) */
    JET(simplicity_full_multiply_8,   32,  16);
    JET(simplicity_full_multiply_16,  64,  32);
    JET(simplicity_full_multiply_32, 128,  64);
    JET(simplicity_full_multiply_64, 256, 128);
    /* comparison / classification */
    JET(simplicity_is_zero_8,   8,  1);
    JET(simplicity_is_zero_16, 16,  1);
    JET(simplicity_is_zero_32, 32,  1);
    JET(simplicity_is_zero_64, 64,  1);
    JET(simplicity_is_one_8,   8,  1);
    JET(simplicity_is_one_16, 16,  1);
    JET(simplicity_is_one_32, 32,  1);
    JET(simplicity_is_one_64, 64,  1);
    JET(simplicity_le_8,   16,  1);
    JET(simplicity_le_16,  32,  1);
    JET(simplicity_le_32,  64,  1);
    JET(simplicity_le_64, 128,  1);
    JET(simplicity_lt_8,   16,  1);
    JET(simplicity_lt_16,  32,  1);
    JET(simplicity_lt_32,  64,  1);
    JET(simplicity_lt_64, 128,  1);
    JET(simplicity_min_8,   16,   8);
    JET(simplicity_min_16,  32,  16);
    JET(simplicity_min_32,  64,  32);
    JET(simplicity_min_64, 128,  64);
    JET(simplicity_max_8,   16,   8);
    JET(simplicity_max_16,  32,  16);
    JET(simplicity_max_32,  64,  32);
    JET(simplicity_max_64, 128,  64);
    /* median_N: src=3N */
    JET(simplicity_median_8,   24,   8);
    JET(simplicity_median_16,  48,  16);
    JET(simplicity_median_32,  96,  32);
    JET(simplicity_median_64, 192,  64);
    /* div_mod_N: src=2N, dst=2N (quotient+remainder; all-ones output if divisor=0) */
    JET(simplicity_div_mod_8,   16,  16);
    JET(simplicity_div_mod_16,  32,  32);
    JET(simplicity_div_mod_32,  64,  64);
    JET(simplicity_div_mod_64, 128, 128);
    JET(simplicity_divide_8,   16,   8);
    JET(simplicity_divide_16,  32,  16);
    JET(simplicity_divide_32,  64,  32);
    JET(simplicity_divide_64, 128,  64);
    JET(simplicity_modulo_8,   16,   8);
    JET(simplicity_modulo_16,  32,  16);
    JET(simplicity_modulo_32,  64,  32);
    JET(simplicity_modulo_64, 128,  64);
    JET(simplicity_divides_8,   16,  1);
    JET(simplicity_divides_16,  32,  1);
    JET(simplicity_divides_32,  64,  1);
    JET(simplicity_divides_64, 128,  1);
    /* div_mod_128_64: TWO^128 * TWO^64 |- TWO^64 * TWO^64 */
    JET(simplicity_div_mod_128_64, 192, 128);

    /* ---- SHA-256 group ---- */
    /* CTX8 = 838 bits; add_N jets: src = CTX8 + N*8 bits */
    JET(simplicity_sha_256_iv,         0, 256);
    /* sha_256_block: TWO^256 * TWO^512 |- TWO^256 */
    JET(simplicity_sha_256_block,    768, 256);
    JET(simplicity_sha_256_ctx_8_init,  0, 838);
    JET(simplicity_sha_256_ctx_8_add_1,   846, 838);
    JET(simplicity_sha_256_ctx_8_add_2,   854, 838);
    JET(simplicity_sha_256_ctx_8_add_4,   870, 838);
    JET(simplicity_sha_256_ctx_8_add_8,   902, 838);
    JET(simplicity_sha_256_ctx_8_add_16,  966, 838);
    JET(simplicity_sha_256_ctx_8_add_32, 1094, 838);
    /* add_64 and above exceed MAX_FRAME_WORDS at 16-bit UWORD */
    JETL(simplicity_sha_256_ctx_8_add_64,          1350, 838);
    JETL(simplicity_sha_256_ctx_8_add_128,         1862, 838);
    JETL(simplicity_sha_256_ctx_8_add_256,         2886, 838);
    JETL(simplicity_sha_256_ctx_8_add_512,         4934, 838);
    /* add_buffer_511: src = CTX8(838) + (TWO^8)^<512(4097) = 4935 bits */
    JETL(simplicity_sha_256_ctx_8_add_buffer_511, 4935, 838);
    JET(simplicity_sha_256_ctx_8_finalize, 838, 256);

    /* ---- secp256k1: FE = 256 bits ---- */
    JET(simplicity_fe_normalize,      256, 256);
    JET(simplicity_fe_negate,         256, 256);
    JET(simplicity_fe_add,            512, 256);
    JET(simplicity_fe_square,         256, 256);
    JET(simplicity_fe_multiply,       512, 256);
    JET(simplicity_fe_multiply_beta,  256, 256);
    JET(simplicity_fe_invert,         256, 256);
    /* fe_square_root: FE |- S(FE) = 1+256 bits */
    JET(simplicity_fe_square_root,    256, 257);
    JET(simplicity_fe_is_zero,        256,   1);
    JET(simplicity_fe_is_odd,         256,   1);

    /* ---- secp256k1: SCALAR = 256 bits ---- */
    JET(simplicity_scalar_normalize,       256, 256);
    JET(simplicity_scalar_negate,          256, 256);
    JET(simplicity_scalar_add,             512, 256);
    JET(simplicity_scalar_square,          256, 256);
    JET(simplicity_scalar_multiply,        512, 256);
    JET(simplicity_scalar_multiply_lambda, 256, 256);
    JET(simplicity_scalar_invert,          256, 256);
    JET(simplicity_scalar_is_zero,         256,   1);

    /* ---- secp256k1: GE = 512 bits, GEJ = 768 bits ---- */
    JET(simplicity_gej_infinity,       0,    768);
    /* gej_rescale: GEJ * FE |- GEJ */
    JET(simplicity_gej_rescale,     1024,    768);
    /* gej_normalize: GEJ |- S(GE) = 1+512 */
    JET(simplicity_gej_normalize,    768,    513);
    JET(simplicity_gej_negate,       768,    768);
    JET(simplicity_ge_negate,        512,    512);
    JET(simplicity_gej_double,       768,    768);
    /* gej_add: GEJ * GEJ |- GEJ (src exceeds MAX_FRAME_WORDS) */
    JETL(simplicity_gej_add,        1536,    768);
    /* gej_ge_add_ex: GEJ * GE |- FE * GEJ */
    JET(simplicity_gej_ge_add_ex,   1280,   1024);
    JET(simplicity_gej_ge_add,      1280,    768);
    JET(simplicity_gej_is_infinity,  768,      1);
    /* gej_equiv: GEJ * GEJ |- TWO (src exceeds MAX_FRAME_WORDS) */
    JETL(simplicity_gej_equiv,      1536,      1);
    JET(simplicity_gej_ge_equiv,    1280,      1);
    /* gej_x_equiv: FE * GEJ |- TWO */
    JET(simplicity_gej_x_equiv,     1024,      1);
    JET(simplicity_gej_y_is_odd,     768,      1);
    JET(simplicity_gej_is_on_curve,  768,      1);
    JET(simplicity_ge_is_on_curve,   512,      1);

    /* ---- secp256k1: scalar multiplication ---- */
    /* off_curve_scale / scale: SCALAR * GEJ |- GEJ */
    JET(simplicity_off_curve_scale,               1024, 768);
    JET(simplicity_scale,                         1024, 768);
    /* generate: SCALAR |- GEJ */
    JET(simplicity_generate,                       256, 768);
    /* linear_combination_1: SCALAR * GEJ * SCALAR |- GEJ */
    JET(simplicity_off_curve_linear_combination_1, 1280, 768);
    JET(simplicity_linear_combination_1,           1280, 768);
    /* linear_verify_1: SCALAR * GE * SCALAR * GE |- ONE (src exceeds MAX_FRAME_WORDS) */
    JETL(simplicity_linear_verify_1,              1536,   0);

    /* ---- secp256k1: point / signature ---- */
    /* decompress: S(FE) |- S(GE) = 1+256 |- 1+512 */
    JET(simplicity_decompress,       257,  513);
    /* point_verify_1: SCALAR*(1+FE)*SCALAR*(1+FE) |- ONE */
    JET(simplicity_point_verify_1,  1026,    0);
    /* bip_0340_verify: PUBKEY*MSG*SIG |- ONE = 256+256+512 */
    JET(simplicity_bip_0340_verify, 1024,    0);
    /* check_sig_verify: PUBKEY*MSG*SIG |- ONE = 256+512+512 */
    JET(simplicity_check_sig_verify, 1280,   0);
    /* swu / hash_to_curve: FE |- GE */
    JET(simplicity_swu,              256,  512);
    JET(simplicity_hash_to_curve,    256,  512);

    /* ---- Parse / tapdata ---- */
    /* parse_lock: TWO^32 |- TWO + TWO^32 = 1+32 bits */
    JET(simplicity_parse_lock,     32,  33);
    /* parse_sequence: TWO^32 |- S(TWO^16 + TWO^16) = 1+1+16 bits */
    JET(simplicity_parse_sequence, 32,  18);
    /* tapdata_init: ONE |- CTX8 */
    JET(simplicity_tapdata_init,    0, 838);

#undef JET
#undef JETL
}
