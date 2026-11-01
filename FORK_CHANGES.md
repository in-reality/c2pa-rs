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

## Experimental BMFF v3 variable mdat leaf rows (t2075)

**Where:** `sdk/src/builder.rs`, `sdk/src/assertions/bmff_hash.rs`,
`sdk/tests/bmff_gop_leaves.rs`.

**What:** `Builder::set_bmff_mdat_variable_hashes` delegates to
`BmffHash::add_mdat_variable_leaf_hashes` to serialize complete ordered
SHA-256 leaf rows and positive, checked `variableBlockSizes`. Counts, sizes,
row lengths and physical mdat indices are checked by the real stream verifier;
variable maps without auxiliary proofs require the full leaf row. Per-mdat
range lookup uses physical indices rather than unordered map iteration.
Tree/digest algorithms are unchanged. One/odd/even rows, individual leaf
tampering and malformed serialized maps have focused regression coverage.

**Why:** The isolated Android/common capture experiment needs exact full-payload
GOP byte ranges without pre-sign remuxing. Roots are computed separately, never
serialized as a nonstandard field or substituted for a multi-leaf row.

**Limits:** The pinned Merkle range implementation still starts at box+16,
which differs from C2PA's actual-payload rule for 8-byte mdat headers; the
capture experiment explicitly rejects those headers. This offset must not be
explained by the distinct offset-16 flat-hash exclusion. The existing fixed
injector/root-only verifier remains available unchanged; preserving it is not
independent proof that its root-only/no-auxiliary-proof representation complies
with the C2PA standard. No platform qualification, production activation or
manifest-lane integration is implied by this isolated change.

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

---

## Resource length preflight without lazy allocation

**Where:** `sdk/src/resource_store.rs`, `manifest.rs`, `ingredient.rs`.

**What:** `ResourceStore::resource_len` inspects resident bytes, confined file
metadata, or borrowed lazy assertion/databox slices without copying payloads.
Databox URI lookup reuses the stored hashed reference (rather than inventing an
empty hash that cannot pass existing databox matching). Hash comparison itself is
unchanged. Resolver precedence matches retrieval, including recognized unsupported flattened
manifest references. Inline tests prove length queries do not invoke retrieval.

**Why:** Portable viewers must omit oversized embedded previews before triggering
lazy materialization. Existing stream writes retrieve a Vec before calling the
output writer; a bounded output writer alone cannot enforce that allocation cap.
No store parsing, signature/trust semantics, or original-media limits change.

---

## Current per-claim validation sideband

**Where:** `sdk/src/manifest.rs`.

**What:** Reader manifests serialize `validation_status` failures from the
current StatusTracker, attributed by claim URI/label before delta de-duplication.
A present empty list means current signature validation observed no failures;
an absent field means no current signature validation/failure was observed.
This computed sideband is ignored when deserializing Manifest JSON.

**Why:** Historical ingredient reports can contain old issuer trust outcomes,
while aggregate reader errors omit unchanged ancestor outcomes. Preview source
context needs the current containing claim's failures/untrusted state without
reinterpreting old reports or changing SDK verification/trust decisions.
