// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* Dedicated fuzz target for the SHA-256 CTX8 jet state machine.
 *
 * The existing simplicity_jets target calls every sha_256_ctx_8_* jet with
 * fuzz-controlled source frames, but random bytes almost never produce a valid
 * CTX8 midstate.  Without a valid state the internal branching inside
 * ctx8Pruned.c / ctx8Unpruned.c -- which gates on the accumulated byte count
 * crossing 64-byte block boundaries -- is never exercised.
 *
 * This target calls sha_256_ctx_8_init to obtain a real context, threads the
 * result through sha_256_ctx_8_add_16 with fuzz-controlled message bytes, and
 * finalises with sha_256_ctx_8_finalize.  The fuzzer can then mutate the 16
 * message bytes to explore all paths through the partial-block fill logic and
 * the final-block padding path.
 *
 * Input layout:
 *   [up to 16 bytes]  message fed to sha_256_ctx_8_add_16
 *   (extra bytes are ignored)
 */

#include <cstddef>
#include <cstdint>

#include <test/fuzz/fuzz.h>

#include <simplicity_ctx8_helper.h>

FUZZ_TARGET(simplicity_ctx8)
{
    simplicity_fuzz_ctx8(buffer.data(), buffer.size());
}
