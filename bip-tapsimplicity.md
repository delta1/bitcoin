```
BIP: ????
Layer: Consensus (soft fork)
Title: TapSimplicity
Author: Byron Hambly <byron.hambly@gmail.com>
Status: Draft
Type: Standards Track
Created: 2026-06-03
Requires: 340, 341, 342
License: BSD-3-Clause
```

## Abstract

This BIP introduces **TapSimplicity**, a new taproot leaf version (`0xbe`) that enables
Simplicity programs to be used as Bitcoin spending conditions. Simplicity is a typed
functional programming language designed for cryptographic applications with formal
semantics, bounded resource usage, and a rich set of bitcoin-specific primitives called
jets. This document specifies the consensus rules for how Simplicity programs are
committed to, serialised in transactions, and evaluated within the Bitcoin taproot
framework.

## Copyright

This document is licensed under the BSD 3-Clause License.

## Motivation

Bitcoin Script has served the network well since inception, but its operational semantics
make formal reasoning difficult and its design limits expressiveness. Several desirable
spending conditions — complex covenant structures, zero-knowledge verifiers, novel
signature schemes — are either impossible to express or require dedicated new opcodes
that must each be analysed for soundness in isolation.

Simplicity addresses these limitations in a principled way:

**Formal specification.** Simplicity has a denotational semantics (what a program
*means*) and an operational semantics (how it *executes*) that are proven equivalent.
This makes it possible to formally verify that a program satisfies a given spending
policy — something that is not feasible for Script today.

**Composability.** Simplicity's combinator-based design makes programs
compositionally correct: if each part is correct, the whole is correct. New primitives can
be added as jets without modifying the core language or re-analysing existing programs.

**Bounded resource usage.** All Simplicity programs terminate. Resource usage
(time and memory) is bounded by a weight budget that is part of the transaction,
enabling reliable worst-case cost analysis and DoS resistance.

**Expressive power.** Simplicity can express any computable function over its type
system. Sophisticated cryptographic protocols, introspection of the spending
transaction, and arbitrary arithmetic are all expressible without consensus changes
beyond this one.

**Soft-fork extensibility via jets.** Recognising subtrees as known jets allows
efficient implementations without changing the language semantics. Future jets can be
added via soft fork and are just optimisations — a node that does not recognise a jet
can still execute its definition correctly.

## Design Overview

### The Simplicity Language

Simplicity is a typed combinator calculus. Every expression has a type of the form
`A → B` where `A` and `B` are types built from the unit type `𝟏`, binary products
`A × B`, and binary sums `A + B`. A *program* is an expression whose type is `𝟏 → 𝟏`.

The core combinators are:

| Combinator | Type | Semantics |
|---|---|---|
| `iden` | `A → A` | Identity |
| `unit` | `A → 𝟏` | Constant unit |
| `injl` | `A → A + B` | Left injection |
| `injr` | `B → A + B` | Right injection |
| `take` | `A × B → A` | First projection |
| `drop` | `A × B → B` | Second projection |
| `comp s t` | `A → C` (given `s: A → B`, `t: B → C`) | Sequential composition |
| `pair s t` | `A → B × C` (given `s: A → B`, `t: A → C`) | Pairing |
| `case s t` | `(A + B) × C → D` (given `s: A × C → D`, `t: B × C → D`) | Case analysis |
| `disconnect s t` | `A × W → B × C` (given `s: A × 2^256 → B × C`) | Disconnect (partial evaluation; `W` is a 256-bit word filled at commitment time) |
| `witness v` | `A → B` | Witness (injects spending-time data of type `B`) |

These eleven combinators form the complete language.

### Program Representation as a DAG

A Simplicity expression is a directed acyclic graph (DAG), not a tree. Shared
sub-expressions are represented once in the DAG and referenced multiple times. This
sharing is explicit: the serialised form encodes back-references so that exponential
blowup from repetition is impossible.

### Commitment Merkle Root

Each node in a Simplicity DAG has a *Commitment Merkle Root* (CMR), a 32-byte hash
that uniquely identifies the program structure. The CMR is computed bottom-up from the
combinators and their children's CMRs; `witness` nodes contribute a constant tag so
that the witness *data* is not committed. This means the same spending policy (same
CMR) can be satisfied by different witness values at spend time.

The CMR serves as the on-chain commitment to the program, analogous to how a
script hash commits to a redeem script. A TapSimplicity leaf's 32-byte script field
holds the CMR of the root of the Simplicity DAG.

### Annotated Merkle Root

The *Annotated Merkle Root* (AMR) commits to the CMR plus type annotations at every
node, providing a complete commitment to both program structure and typing. The
executor verifies that the CMR of the decoded program matches the 32-byte commitment
in the output being spent, and — where applicable — that the AMR matches a
separately committed AMR root.

### Jets

A *jet* is a recognised subtree that can be replaced by a native implementation. A node
implementing a jet has the same CMR as the sub-DAG it optimises, so commitment is
preserved. Jets are how Bitcoin-specific operations are made available: signature
verification, transaction introspection, hash functions, and arithmetic all appear as
jets that map to the corresponding Simplicity definitions.

Jets included in this BIP are specified in the Simplicity specification document
referenced below. Future jets can be added in subsequent soft forks.

### Bitcoin Transaction Environment

Simplicity programs executing within a TapSimplicity leaf have access to a Bitcoin
*environment* — a structured representation of the spending transaction and the output
being spent. This environment is provided as the implicit left component of the
program's input (the full input type is `Environment × 𝟏 → 𝟏` when the environment
is threaded through). Bitcoin-specific jets expose fields of this environment:

- Transaction version, locktime, and input count / output count.
- For the current input: index, sequence number, the outpoint (txid and output index
  of the UTXO being spent), value of the UTXO being spent, script pubkey of the UTXO,
  and the taproot environment (internal key, tapleaf hash, tappath hash).
- All output scriptPubKeys and values.
- Annex (if present).

Signature-checking jets (Schnorr and CHECKSIGADD-equivalent) verify against this
environment.

## Specification

### Definitions

The following terms are used:

- **Script:** The 32-byte script field of a taproot leaf, which for TapSimplicity
  contains the CMR.
- **CMR:** The Commitment Merkle Root of the Simplicity program, a 32-byte value.
- **TapSimplicity leaf:** A taproot leaf with leaf version `0xbe`.
- **Simplicity program bytes:** The serialised Simplicity DAG.
- **Simplicity witness bytes:** The serialised witness values consumed by `witness`
  nodes in the DAG.
- **Padding:** An optional stack item of zero bytes used to adjust the validation budget.
- **Budget:** The maximum allowed execution cost, a non-negative integer measured in
  abstract weight units.
- **minCost:** The minimum execution cost that the program must consume, used to
  enforce padding minimality.
- **`GetSerializeSize(stack)`:** The total byte length of the serialised witness stack,
  including the compact-size length prefix for each item.

### TapSimplicity Leaf Version

A taproot leaf version is identified by applying the mask `0xfe` to the first byte of the
control block. TapSimplicity uses leaf version `0xbe`:

```
TAPROOT_LEAF_MASK         = 0xfe
TAPROOT_LEAF_TAPSCRIPT    = 0xc0   (BIP-342)
TAPROOT_LEAF_TAPSIMPLICITY = 0xbe  (this BIP)
```

### Script Field

For a TapSimplicity leaf, the script field **must** be exactly 32 bytes. This field is
the CMR of the Simplicity program that authorises spending.

If the script field is not exactly 32 bytes, the script path spend is invalid.

### Witness Stack Format

After the standard taproot witness processing defined in BIP-341 (removal of an
optional annex, removal of the control block, removal of the script), the remaining
witness stack items are interpreted as follows.

The remaining stack **must** contain exactly 2 or 3 items. Any other count is
invalid.

Items are consumed from the top of the stack (last item first):

1. **`simplicity_program`** (top of remaining stack): The serialised Simplicity DAG.
   There is no length constraint beyond what is imposed by the validation budget.

2. **`simplicity_witness`** (next item): The serialised witness values for all
   `witness` nodes in the DAG, in a canonical order defined by the Simplicity
   specification.

3. **`padding`** (bottom item, optional): If a third item is present, it **must**
   consist entirely of zero bytes. It **must** be minimal: the same budget would not
   be achievable with one fewer byte of padding (see Budget Calculation below).

Visually, the full witness stack for a TapSimplicity spend without padding is:

```
index  item
─────  ────────────────────────────────────
  0    simplicity_witness
  1    simplicity_program
  2    script (32-byte CMR)          ← popped as taproot script
  3    control_block                 ← popped as taproot control block
       [annex]                       ← popped if present (optional, index 4 or 3)
```

With optional padding:

```
index  item
─────  ────────────────────────────────────
  0    padding  (n bytes, all 0x00)
  1    simplicity_witness
  2    simplicity_program
  3    script (32-byte CMR)
  4    control_block
       [annex]                       ← optional
```

### Budget Calculation

The validation budget is computed from the **full** witness stack (all items,
including control block, script, program, witness, and optional padding) before
any items are removed:

```
VALIDATION_WEIGHT_OFFSET = 50

budget = GetSerializeSize(witness.stack) + VALIDATION_WEIGHT_OFFSET
```

`GetSerializeSize` returns the byte length of the witness stack as it appears on the
wire, including compact-size integer prefixes for each item and for the item count.

#### Padding minimality

When padding is present with byte length `n`:

```
size_n   = GetSerializeSize(n-byte zero item)
size_n1  = GetSerializeSize((n−1)-byte zero item)   # 0 when n = 0 (no item to reduce to)

minCost  = budget − size_n + size_n1
```

For `n = 0` (empty padding item, 0 bytes), `size_n = 1` (compact-size prefix only) and
`size_n1 = 0`, so the formula gives `minCost = budget − 1`.

For `n ≥ 1`, removing one byte of padding decreases the serialised size by exactly 1 byte
(compact-size does not change until crossing a boundary), so `minCost = budget − 1` in
the common case as well.

The executor **must** reject the spend if the program's actual execution cost is less
than `minCost`. This ensures that padding cannot be used to allocate more budget than
the program requires: given the program's actual cost, the smallest valid padding
length produces a budget just sufficient for that cost.

#### Budget constraint

The executor **must** reject the spend if the program's execution cost exceeds
`budget`.

### Validation Algorithm

Given the inputs extracted from the witness stack, a TapSimplicity spend is validated
as follows:

1. **Witness stack count check.** After removing the control block and script from the
   witness stack, verify that exactly 2 or 3 items remain. Fail with
   `SIMPLICITY_WRONG_LENGTH` otherwise.

2. **Budget calculation.** Compute `budget` from the full (unmodified) witness stack as
   described above.

3. **Padding check.** If a third item is present, pop it as the padding item. Verify
   that all its bytes are `0x00`; fail with `SIMPLICITY_PADDING_NONZERO` otherwise.
   Compute `minCost` from `budget` and the padding length as described above. If no
   padding item is present, `minCost = 0`.

4. **Taproot environment construction.** From the control block and script:
   - Extract the internal public key (bytes 1–32 of the control block).
   - Extract the merkle path (remaining bytes of the control block, in 32-byte chunks).
   - Record the path length `pathLen`.
   - The CMR is the 32-byte script field.
   - Compute `tapLeafHash`, `tappathHash`, `tapEnvHash` per the Simplicity
     specification.

5. **Execution.** Pass `simplicity_program`, `simplicity_witness`, the taproot
   environment, `minCost`, and `budget` to the Simplicity evaluator. The evaluator:

   a. Rejects the spend if `budget` exceeds the evaluator's internal maximum allowed
      value. Fail with `SIMPLICITY_OVERWEIGHT`.

   b. Decodes the bitstream into a Simplicity DAG. Fail on any parse error.

   c. Performs type inference. Fail if type inference fails or if the inferred type of
      the root is not a valid program type.

   d. Verifies that the CMR of the decoded root node matches the 32-byte script field.
      Fail with `SIMPLICITY_CMR` otherwise.

   e. Evaluates the program with the Bitcoin transaction environment, tracking
      execution cost (computation) and memory cost (frame stack depth).
      Fail if execution cost exceeds `budget` (`SIMPLICITY_EXEC_BUDGET`) or memory
      exceeds its limit (`SIMPLICITY_EXEC_MEMORY`).

   f. Verifies that execution cost is at least `minCost`. Fail with
      `SIMPLICITY_ANTIDOS` otherwise.

   g. Verification succeeds if and only if the evaluator returns without error.

### Error Conditions

The following error codes are defined for TapSimplicity:

| Error | Condition |
|---|---|
| `SIMPLICITY_WRONG_LENGTH` | Remaining witness stack has fewer than 2 or more than 3 items |
| `SIMPLICITY_PADDING_NONZERO` | Padding item contains non-zero bytes |
| `SIMPLICITY_BITSTREAM_EOF` | Unexpected end of program bitstream |
| `SIMPLICITY_BITSTREAM_TRAILING_BYTES` | Extra bytes after end of program |
| `SIMPLICITY_BITSTREAM_ILLEGAL_PADDING` | Bitstream padding bits are non-zero |
| `SIMPLICITY_WITNESS_EOF` | Unexpected end of witness bitstream |
| `SIMPLICITY_WITNESS_TRAILING_BYTES` | Extra bytes after end of witness |
| `SIMPLICITY_WITNESS_ILLEGAL_PADDING` | Witness bitstream padding bits are non-zero |
| `SIMPLICITY_TYPE_INFERENCE_UNIFICATION` | Type unification conflict during type inference |
| `SIMPLICITY_TYPE_INFERENCE_OCCURS_CHECK` | Occurs-check failure during type inference |
| `SIMPLICITY_TYPE_INFERENCE_NOT_PROGRAM` | Inferred type of root is not `𝟏 → 𝟏` |
| `SIMPLICITY_UNSHARED_SUBEXPRESSION` | A sub-expression appears more than once without sharing |
| `SIMPLICITY_CMR` | Decoded CMR does not match the 32-byte script commitment |
| `SIMPLICITY_AMR` | AMR check failed |
| `SIMPLICITY_DATA_OUT_OF_RANGE` | A data value is outside its valid range |
| `SIMPLICITY_DATA_OUT_OF_ORDER` | Data is not in canonical order |
| `SIMPLICITY_FAIL_CODE` | A `fail` node was reached during execution |
| `SIMPLICITY_RESERVED_CODE` | A reserved codepoint was used |
| `SIMPLICITY_HIDDEN` | A `hidden` node appeared in an invalid position |
| `SIMPLICITY_HIDDEN_ROOT` | The root of the program is a `hidden` node |
| `SIMPLICITY_EXEC_BUDGET` | Execution cost exceeded `budget` |
| `SIMPLICITY_EXEC_MEMORY` | Memory (frame stack) exceeded its limit |
| `SIMPLICITY_EXEC_JET` | An assertion inside a jet failed |
| `SIMPLICITY_EXEC_ASSERT` | A `case`-based assertion failed |
| `SIMPLICITY_ANTIDOS` | Execution cost was less than `minCost` |
| `SIMPLICITY_OVERWEIGHT` | Budget is too large |

## Rationale

### Choice of leaf version 0xbe

BIP-342 assigns leaf version `0xc0` to tapscript. The leaf version is the first
control-block byte with the lowest bit cleared (i.e., `control_block[0] & 0xfe`); the
lowest bit encodes the parity of the output key. Valid leaf versions are therefore the
even bytes from `0x00` to `0xfe`. The value `0xbe` was chosen for TapSimplicity
to be adjacent to tapscript's `0xc0` while leaving `0xc2`–`0xfe` free for future use.
The byte `0xbe` also has the mnemonic property of being one step before `0xbf`, and
its distance from `0xc0` signals "very similar to tapscript but distinct."

### Script field as 32-byte CMR

Taproot leaves commit to an arbitrary script. For TapSimplicity, the script is
restricted to exactly 32 bytes: the CMR of the Simplicity program. This matches the
spirit of pay-to-script-hash constructions — the on-chain commitment is compact
regardless of program size — while enabling the execution to be deferred to spend time.

The CMR uniquely determines the program's computational content (the combinators and
their structure) without revealing the witness values or type annotations. This provides
a compact, privacy-preserving commitment analogous to P2SH or P2WSH.

### Separation of program and witness

The `witness` combinator injects spending-time data into a Simplicity computation. By
separating the serialised program (which is committed by the CMR) from the serialised
witness (which fills in the `witness` nodes at spend time), the protocol achieves a
clean analogue of Bitcoin's scriptSig/scriptPubKey separation. The program encodes the
spending policy; the witness encodes the satisfying data.

This separation also enables the Simplicity type system to ensure that witness data is
used in a type-safe manner — the program's type annotation for each `witness` node
specifies the type of data it expects.

### Budget model

Simplicity's combinator semantics make execution cost easy to bound, but adversarial
inputs could still attempt to maximise memory or computation within that bound. The
budget model, inherited from BIP-342's validation weight framework, ties execution
resources directly to the on-chain cost paid in transaction weight. A program that
consumes more resources must pay more in witness bytes (padding or longer witness
data), creating an economic disincentive for resource exhaustion attacks.

The `VALIDATION_WEIGHT_OFFSET` of 50 weight units accounts for the fixed per-input
overhead of taproot verification (control block hashing, tapleaf hash computation,
tappath verification).

### Padding minimality

Without a minimality requirement, a spender could include arbitrarily large padding to
inflate the budget without using it. This would decouple transaction weight (which
determines fees and block space) from actual validation cost, creating a DoS vector.
The minimality check ensures that the budget is no larger than required: the smallest
padding that still covers the program's execution cost is the only valid padding.

### Relationship to tapscript

TapSimplicity is a sibling leaf version to tapscript, not a replacement. Existing
tapscript leaves remain valid and unaffected. A single taproot output can have leaves
of both types in its Merkle tree.

### Absence of annex processing

This BIP does not define any semantics for the taproot annex in the context of
TapSimplicity. The annex is stripped from the witness stack before the Simplicity
validator sees it, following the same annex handling defined in BIP-342.

## Backwards Compatibility

TapSimplicity is a soft fork. Nodes that do not implement this BIP treat leaf version
`0xbe` as an unknown taproot leaf version, which — under the rules of BIP-341 —
succeeds unconditionally (without `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`
set). Upgraded nodes enforce the Simplicity validation rules.

No existing scripts are affected. No existing transaction output type is reinterpreted.
The new rules apply only to outputs and leaves explicitly created with leaf version
`0xbe` after activation.

## Test Vectors

The following test vector exercises the minimal valid TapSimplicity spend on Bitcoin
regtest/signet.

### Program

The Simplicity program is a single byte `0x24`:

```
simplicity_program = 0x24
```

This encodes the unit combinator, a program of type `𝟏 → 𝟏` that always succeeds
with no computation.

### CMR

The Commitment Merkle Root of the program above:

```
cmr = c40a10263f7436b4160acbef1c36fba4be4d95df181a968afeab5eac247adff7
```

### Control Block

A TapSimplicity control block with no merkle path, using the standard NUMS
(Nothing Up My Sleeve) internal key to disable key-path spending:

```
control_block = be50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
```

Breakdown:

| Bytes | Value | Meaning |
|---|---|---|
| `be` | 0xbe | Leaf version (TapSimplicity), parity bit 0 |
| `50929b74...803ac0` | 32 bytes | Internal public key (NUMS point) |
| (none) | — | Merkle path (empty, depth 0) |

### Witness Stack

```
stack[0] = ""          (simplicity_witness: empty, no witness nodes)
stack[1] = "24"        (simplicity_program: one byte)
stack[2] = "c40a1026...7adff7"  (script: 32-byte CMR)
stack[3] = "be50929b...803ac0"  (control_block)
```

### TapTweak

The tweaked output key corresponding to the above, derivable from the internal key and
the single TapSimplicity leaf, produces the regtest bech32m address:

```
bcrt1pzjehfs3vskwj6022c255hyh948ecjsqzv25fkm29w7gwzazyccfqt8ksnv
```

### Budget

For this spend (no padding), the budget is:

```
budget = GetSerializeSize(witness.stack) + 50
```

The witness stack contains 4 items; their total serialised size determines the budget.
`minCost` is 0 (no padding present).

## Deployment

Deployment follows the "heretical" version-bits framework used in Bitcoin Inquisition
for signet testing (BIN-2026-0004-000):

| Network | Activation |
|---|---|
| regtest | Always active |
| signet | Start: 2026-01-01 (height-based), Timeout: 2036-01-01 |

For mainnet deployment, activation parameters would be specified following established
soft-fork deployment procedures (e.g., BIP-8 or BIP-9).

## Reference Implementation

The reference implementation is maintained in the Bitcoin Inquisition repository:

- [https://github.com/bitcoin-inquisition/bitcoin](https://github.com/bitcoin-inquisition/bitcoin)
  (branch: `simplicity-inquisition`)

Key source files:

- `src/script/interpreter.cpp` — `VerifyWitnessProgram()` (TapSimplicity dispatch),
  `CheckSimplicity()` (execution and error mapping)
- `src/script/interpreter.h` — Leaf version constants and `PrecomputedTransactionData`
- `src/script/script_error.h` — Simplicity error codes
- `src/simplicity/` — The Simplicity C library (program parsing, type inference,
  execution, jets)
- `test/functional/feature_simplicity.py` — Functional activation and spend test

## Specification Reference

The Simplicity language is formally specified in:

> Russell O'Connor, "Simplicity: A New Language for Blockchains,"
> *Proceedings of the 2017 Workshop on Programming Languages and Analysis for Security*
> (PLAS '17). Updated version: [https://blockstream.com/simplicity.pdf](https://blockstream.com/simplicity.pdf)

The specification defines:
- All core combinators and their denotational semantics.
- The type system and type inference algorithm.
- CMR and AMR computation.
- The bitstream serialisation format for programs and witnesses.
- All Bitcoin environment jets and their definitions.
- Execution cost accounting.

Implementations must conform to that specification. This BIP specifies only the
consensus integration layer — how Simplicity programs are committed to, presented in
transactions, and invoked within the Bitcoin taproot framework.

## Acknowledgements

Simplicity was designed by Russell O'Connor at Blockstream. The language draws on
decades of research in type theory and programming language semantics. The Bitcoin
taproot framework (BIPs 340–342) by Pieter Wuille, Jonas Nick, Tim Ruffing, and
Anthony Towns provides the extensibility mechanism that makes TapSimplicity possible
as a soft fork.
