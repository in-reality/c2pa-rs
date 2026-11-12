# Changes in this fork

This document lists all changes made in this fork compared to upstream
[contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs), and the reason
for each.

**Upstream base:** tag `c2pa-v0.91.11` (2026-11-04), commit
`7bb32d67b984af5cff064ead2a3a538e696ef70d` on the maintained stable release
line. Its binary release is marked pre-release under upstream's pre-1.0
library-release convention. The old 0.90.19 line and this stable line diverged;
the forward merge preserves the selected release's Claim/Store module layout
and upstream security fixes, with only the project additions described below.
Raw signing implementations now come from upstream `c2pa_raw_crypto` 0.3;
there is no private certificate-validation backport.

---

## Certificate trust type fix

**Where:** `sdk/src/crypto/cose/certificate_trust/openssl.rs`

**Change:** `verify_param.set_time(st as _)` adapts the epoch to the platform
OpenSSL time type. The old raw-signature module is removed, as upstream requires.

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

**What:** `Builder::set_bmff_mdat_hashes` delegates to the selected release's
`BmffHash::add_mdat_leaf_hashes`. The existing upstream Merkle construction and
ordered-mdat/proof validation remain authoritative; those supporting methods
are not a second local implementation.

**Why:** Capture injects Merkle leaves from a single pass over the input
stream before `sign_file`.

---

## Builder: created assertions

**What:** `Builder::add_created_assertion` / `add_created_assertion_json`
delegate to upstream's existing `add_assertion_impl` with `created = true`.

**Why:** Claims V2 signer-attributed assertions for distributed capture paths.

---

## Builder: dynamic assertion finalization in sign_embeddable

**What:** Capture dynamic assertions once in `sign_embeddable`, reserve their
slots, and pass that same list to a crate-private Store signing delegate.
The maintained Store writer remains the sole content finalizer.

**Why:** A getter may consume its list, while maintained CAWG signers return
shared or fresh assertions on each call. Re-fetching loses the former;
pre-finalizing and invoking the Store writer signs the latter twice.
The captured-list handoff avoids duplicate key/KMS operations without changing
the normal Store entry or certificate policy.

---

## Store: BMFF flat hash after embed with pre-injected leaves

**Where:** `sdk/src/store/store_io.rs`; the old monolithic `store.rs` is removed.

**What:** Always recompute BMFF flat hash post-embed when a BmffHash assertion
is present (removed `needs_hash` gate). Dynamic finalization visibility lives in
the selected `store/store_core.rs` module.

**Why:** Pre-populated Merkle leaves from `set_bmff_mdat_hashes` must get
post-embed binding verification.

---

## Ingredient: synchronous from_memory

**What:** Restored deprecated `Ingredient::from_memory` sync wrapper.

**Why:** Backend signing (`SealSigner`, rendition paths) builds ingredients
from manifest store bytes synchronously; upstream removed the sync API.

---

## Superseded local changes

- The ZIP dependency pin and entry-name compatibility workaround are replaced by
  upstream's ZIP 9.3-compatible dependency and implementation. Resolved compatible
  dependency versions remain in each consumer lock.
- BMFF integer-overflow / underflow hardening and ingredient label collisions
  were already absorbed upstream. The selected release's later BMFF proof-order
  and payload-pairing hardening is preserved.
- The old Claim, Store and raw-signature module files stay deleted. Required
  project behavior is carried into the selected module locations rather than
  restoring obsolete upstream implementations.
- The Android `i686` time-type adaptation remains local at its new path above.

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

**Where:** `sdk/src/manifest.rs` and `sdk/src/reader.rs`.

**What:** `Reader::current_validation_status` retains the current read's statuses
before historical ingredient de-duplication and is skipped by serialization.
Reader manifests serialize `validation_status` failures from the
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


---

## Remaining upstream issuer-purpose limitation

The integrated Rust-native path rejects non-CA delegation, enforces presented
issuer CA/keyCertSign/path-length constraints and checks intermediate validity.
Explicit manifest/TSA trust lists also remain separate. These protections do
not enforce a presented issuing CA's declared EKU purpose, or the declared
purpose of an issuing anchor omitted from the presented chain. Integration
regressions retain the expected rejections for media-only CAs authorizing
timestamps and timestamp-only CAs authorizing capture. Those cases remain open;
the version upgrade is not their closure, and no local PKIX replacement or
exceptional certificate patch is included.
