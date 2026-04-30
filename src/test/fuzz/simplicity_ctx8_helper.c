// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* Compiled as C so that internal Simplicity headers (which use C99 compound
 * literals and designated initialisers) can be included safely.
 *
 * Exercises the SHA-256 CTX8 jet state machine by chaining jets with valid
 * state, rather than passing random bytes as the source frame.  This reaches
 * the internal branching in ctx8Pruned.c / ctx8Unpruned.c that is gated on
 * whether the accumulated byte count crosses a 64-byte block boundary.
 *
 * Pipeline:
 *   sha_256_ctx_8_init  ()  -> CTX8
 *   sha_256_ctx_8_add_16  CTX8 * (TWO^8)^16  -> CTX8
 *   sha_256_ctx_8_finalize  CTX8  -> TWO^256
 */

#include "simplicity_ctx8_helper.h"

#include <string.h>

#include "../../simplicity/frame.h"
#include "../../simplicity/jets.h"
#include "../../simplicity/uword.h"

/* CTX8 = 838 bits (SHA-256 midstate + accumulated-byte counter + padding). */
#define CTX8_BITS      838u
#define CTX8_WORDS     ROUND_UWORD(CTX8_BITS)

/* sha_256_ctx_8_add_16: src = CTX8(838) + 16*8(128) = 966 bits. */
#define ADD16_SRC_BITS  966u
#define ADD16_SRC_WORDS ROUND_UWORD(ADD16_SRC_BITS)

/* sha_256_ctx_8_finalize: dst = TWO^256. */
#define HASH_BITS      256u
#define HASH_WORDS     ROUND_UWORD(HASH_BITS)

void simplicity_fuzz_ctx8(const uint8_t* data, size_t len)
{
    /* ---- Step 1: sha_256_ctx_8_init: UNIT -> CTX8 ----
     *
     * The jet ignores its source frame (UNIT has 0 bits) and always writes the
     * same deterministic initial SHA-256 context.  After this call ctx_buf
     * holds a valid CTX8 state that can be fed to add / finalize jets.
     *
     * initReadFrame(0, ...) with a 1-word dummy buffer is safe: the jet reads
     * zero bits from it, so the buffer contents are irrelevant.
     */
    UWORD ctx_buf[CTX8_WORDS];
    memset(ctx_buf, 0, sizeof ctx_buf);
    {
        UWORD dummy[1] = {0};
        frameItem src = initReadFrame(0, dummy);
        frameItem dst = initWriteFrame(CTX8_BITS, ctx_buf + CTX8_WORDS);
        simplicity_sha_256_ctx_8_init(&dst, src, NULL);
    }
    /* ctx_buf now holds the initial CTX8 state written by the jet.
     * initReadFrame(CTX8_BITS, ctx_buf) addresses the same physical words,
     * making the write-frame output directly readable as a read frame. */

    /* ---- Step 2: sha_256_ctx_8_add_16: CTX8 * (TWO^8)^16 -> CTX8 ----
     *
     * Build the 966-bit source frame by:
     *   (a) copying the 838 CTX8 bits from ctx_buf into a write frame, then
     *   (b) writing 16 fuzz-controlled message bytes (128 bits) after them.
     *
     * simplicity_copyBits advances the *write* frame cursor by CTX8_BITS,
     * leaving exactly 128 bits remaining for the message payload.
     */
    UWORD add_src[ADD16_SRC_WORDS];
    UWORD add_dst[CTX8_WORDS];
    memset(add_src, 0, sizeof add_src);
    memset(add_dst, 0, sizeof add_dst);
    {
        frameItem ctx_read  = initReadFrame(CTX8_BITS, ctx_buf);
        frameItem add_write = initWriteFrame(ADD16_SRC_BITS, add_src + ADD16_SRC_WORDS);
        simplicity_copyBits(&add_write, &ctx_read, CTX8_BITS);

        /* Write 16 message bytes from fuzz data (pad with zero if too short). */
        for (size_t i = 0; i < 16; i++) {
            uint8_t b = (i < len) ? data[i] : 0;
            simplicity_write8(&add_write, b);
        }

        frameItem src = initReadFrame(ADD16_SRC_BITS, add_src);
        frameItem dst = initWriteFrame(CTX8_BITS, add_dst + CTX8_WORDS);
        simplicity_sha_256_ctx_8_add_16(&dst, src, NULL);
    }

    /* ---- Step 3: sha_256_ctx_8_finalize: CTX8 -> TWO^256 ----
     *
     * Feeds the accumulated context from step 2 and computes the final hash.
     * This exercises the block-padding and final-compression paths that are
     * only reachable when the context contains a valid byte-count value.
     */
    {
        UWORD hash_buf[HASH_WORDS];
        memset(hash_buf, 0, sizeof hash_buf);
        frameItem src = initReadFrame(CTX8_BITS, add_dst);
        frameItem dst = initWriteFrame(HASH_BITS, hash_buf + HASH_WORDS);
        simplicity_sha_256_ctx_8_finalize(&dst, src, NULL);
    }
}
