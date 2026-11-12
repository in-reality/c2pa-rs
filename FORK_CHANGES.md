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

## Expose exact salted CBOR assertion hashing

**Where:** `sdk/src/lib.rs` (`cbor_assertion_box_hash`).

**What:** Narrow public wrapper over the existing `UserCbor` conversion and
`Claim::calc_assertion_box_hash`; no new encoder, salt generator or signing path.

**Why:** A remote capture signer must resolve exact public assertion bytes plus
the actual SDK-selected JUMBF salt against a device-composed claim. The public
dynamic-assertion callback supplies that salt while preserving normal SDK
replacement/hash semantics. Upstream 0.91.0/main still keeps this hash helper
private; upgrading alone does not provide the required API. Remove the wrapper
when an upstream equivalent is public and preserves the same byte semantics.

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

---

## Ingredient: credential-only verification with unverified media binding

**Where:** `sdk/src/ingredient.rs`.

**What:** Additive `with_manifest_data_unverified_binding` uses the normal store
verifier without an asset, never reading media/XMP/container trees. It returns
genuine credential-only signature/trust results separately and retains observed
failures/informational results in the same ingredient. Its signed partial record
omits successes and explicitly describes source-media binding as not performed,
so the SDK aggregate cannot promote an unverified source to valid/trusted. The
existing three-state SDK calls that incomplete record `Invalid`; this is not a
claim of observed media invalidity. Callers must distinguish the explicit unknown
binding from actual recorded failures. Original manifests/resources stay intact;
thumbnail references require a genuinely verified assertion hash. No arbitrary
validation-result setter or source-binding success is introduced. Existing normal
media import remains unchanged, with a shared thumbnail-reference helper.

**Why:** Bounded source validation may be unavailable while credential signatures
still contain actionable negatives. Disabling all verification loses those
records and can turn a previously advisory negative into a new mint-gate refusal.
The credential-only seam retains real evidence without expensive media parsing,
false store-as-media binding failures, or weakening the existing output gate.

---

## Reader: manifest-box conflict identity

**Where:** `sdk/src/reader.rs`.

**What:** Additive `Reader::manifest_box_hash(label)` exposes the existing SDK
manifest-box identity used by ingredient conflict resolution. The method rejects
missing labels/unavailable hashes and adds no validation success or trust claim.

**Why:** A media-backed ingredient may receive a governing store separately from
its embedded store. Callers need to recognize an actual same-label claim conflict
without rejecting equivalent governing claims for different surrounding closure
or store padding, or reimplementing SDK identity semantics.
