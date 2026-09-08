# Changes in this fork

This document lists all changes made in this fork compared to upstream
[contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs), and the reason
for each.

**Sync point:** upstream tag `c2pa-v0.90.19` (2026-09-04), merged 2026-09-08.

---

## Certificate trust type fix

**Where:** `sdk/src/crypto/raw_signature/openssl/check_certificate_trust.rs`

**Change:** `verify_param.set_time(st.try_into().unwrap())` instead of
`set_time(st)`.

**Why:** Rust type mismatch when building for `i686-linux-android`.

---

## Expose Merkle API

**What:** Public `merkle_utils` module with `compute_merkle_root` /
`compute_merkle_proof`; re-exported `MerkleNode`, `C2PAMerkleTree`.

**Why:** Downstream capture/backend code computes C2PA Merkle roots and
inclusion proofs from pre-hashed leaves without reimplementing the algorithm.

---

## Expose BMFF hash utilities

**What:** `compute_bmff_flat_hash` and `compute_bmff_mdat_merkle_roots` in
`sdk/src/assertions/bmff_hash.rs`, re-exported at crate root.

**Why:** Single-read capture signing and backend attestation need the exact
flat hash and Merkle roots the signer will embed.

---

## Builder: pre-injected BMFF Merkle leaves

**What:** `Builder::set_bmff_mdat_hashes`, plus supporting methods on
`BmffHash` (`add_merkle_placeholder`, `add_mdat_leaf_hashes`,
`add_place_holder_hash`).

**Why:** Capture injects Merkle leaves from a single pass over the input
stream before `sign_file`.

---

## Builder: created assertions

**What:** `Builder::add_created_assertion` / `add_created_assertion_json`.

**Why:** Claims V2 signer-attributed assertions for distributed capture paths.

---

## Builder: dynamic assertion finalization in sign_embeddable

**What:** Finalize dynamic assertions before `sign_manifest` in
`sign_embeddable` (consume-once signers such as CAWG identity).

**Why:** Upstream defers finalization to `sign_manifest`, which re-fetches
dynamic assertions and ships zero placeholders for consume-once signers.

---

## Store: BMFF flat hash after embed with pre-injected leaves

**What:** Always recompute BMFF flat hash post-embed when a BmffHash assertion
is present (removed `needs_hash` gate).

**Why:** Pre-populated Merkle leaves from `set_bmff_mdat_hashes` must get
post-embed binding verification.

---

## Ingredient: synchronous from_memory

**What:** Restored deprecated `Ingredient::from_memory` sync wrapper.

**Why:** Backend signing (`SealSigner`, rendition paths) builds ingredients
from manifest store bytes synchronously; upstream removed the sync API.

---

## Dropped (absorbed by upstream 0.90.19)

- Android `i686` type fix — retained; upstream still uses bare `set_time(st)`.
- BMFF integer-overflow / underflow hardening — upstream merged equivalent fixes.
- Ingredient label collision handling — upstream #2585.
