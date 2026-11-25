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

## Reader: explicit store-only verification

**Where:** `sdk/src/reader.rs` (`with_manifest_data` and generated async variant).

**What:** Parse supplied JUMBF with the existing context-aware Store reader,
then call the normal store verifier without subject media. Signatures, assertions
and ingredient checks still run; media hashes remain unchecked. The normal
Reader projection and selected-binding accessor are reused. Callers bound bytes
before parsing, as for the paired API.

**Why:** A store-only inspection must not hash its own JUMBF as if it were media
and then discard the resulting failures. Upstream 0.91.11 exposes this combination
only internally. Remove this wrapper when an equivalent upstream Reader API
preserves the same store verification and unperformed binding distinction.
Embedded input continues to use native `with_stream`; paired stores continue to
use `with_manifest_data_and_stream`. Exclusion-boundary tests preserve their
existing embedded/detached distinction without changing the verifier.

---

## Certificate trust type fix

**Where:** `sdk/src/crypto/cose/certificate_trust/openssl.rs`

**Change:** `verify_param.set_time(st as _)` adapts the epoch to the platform
OpenSSL time type. The old raw-signature module is removed, as upstream requires.

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

## Imported signed-history preservation and bounded store decoding

**Where:** `sdk/src/claim/claim_core.rs`, `sdk/src/store/store_core.rs`, and
`src/settings/mod.rs`.

**What:** An imported, uncompressed manifest retains its exact JUMBF box bytes
alongside a fingerprint of the SDK's normalized reconstruction. Serialization
and manifest/signature box hashing reuse those original bytes only while the
fingerprint still matches; a changed claim or signature takes the normal SDK
path. Importing a governing ingredient retains earlier inactive manifests in
their original byte order. The optional aggregate decoded-store cap counts
all manifest output, including inactive compressed boxes and trailing decoded
bytes, before materializing claims. The default remains unbounded at the
aggregate level, with the existing per-manifest limit unchanged.

**Why:** LinkedIn preparation must preserve signed prior history and media bytes
without accepting a stale raw cache after mutation. The opt-in aggregate cap
bounds imported credential decoding before an oversized store allocates memory.
The maintained 0.91.11 module layout and its separate manifest/TSA trust policy
remain in force. Focused tests live in `sdk/src/store/linkedin_test.rs` and
`src/settings/mod.rs`.

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

## Additive Builder databox resources

**Where:** `sdk/src/builder.rs` (`Builder::add_databox`).

**What:** Exposes the existing standard `Claim::add_databox` / `put_databox`
path to Builder callers. Payloads use native CBOR byte strings in the C2PA
`c2pa.databoxes` store; the returned SDK `HashedUri` hashes the salted JUMBF
box, independently of a caller's encoded-payload digest. This is the established
databox mechanism, not the newer EmbeddedData assertion representation.
The actual generated claim label is pinned on first use; subsequent label,
claim-version or hash-algorithm changes fail. Boxes are restored before icons
and ingredients allocate further databox IDs. Builder JSON retains the data,
identity and explicit salt. JUMBF working-store archive emission rejects this
capability because Reader::into_builder does not yet restore arbitrary boxes;
no archive roundtrip is claimed.

**Why:** A custom signed descriptor must reference actual native binary boxes
before the normal final signing/hash step. Builder::add_resource only registers
source bytes, and generic add_assertion serializes custom CBOR assertions;
neither provides this mechanism. Upstream main checked 2026-11-16 still lacks
a public arbitrary Builder databox API. Remove this adapter when upstream
provides an equivalent pre-sign API preserving exact salted references.


## Reader: SDK-selected asset binding

**Where:** `sdk/src/reader.rs`, `sdk/src/store/store_core.rs`, `sdk/src/lib.rs`.

**What:** `Reader::selected_asset_binding(label)` exposes the existing SDK
binding resolver and `Claim::hash_assertions` selection, including update
inheritance, created-versus-gathered filtering, exact version/instance labels,
effective algorithm and signed assertion projection. The resolver now retains
its actual claim path; the verifier still consumes the same selected endpoint.
The typed family supplies its positive status vocabulary. The current result
requires a success at the exact selected assertion URI, with scoped failures
winning; informational or historical statuses cannot supply that success.
Missing/conflicting selection is an error. Selection is not authentication or
source availability. Boxes/collections retain per-entry algorithm overrides.

**Why:** Compound assets contain part hashes and supporting multi-asset maps.
Reader's compact assertions omit some standard bindings; prefix-counting detailed
JSON or rewalking updates in consumers cannot reproduce the SDK's selection.
Consumers can now retain their trust/account/continuity policies over SDK facts.
Remove this accessor when an upstream typed Reader API provides the same exact
selection and current-result scope. Focused selector defenses are in Reader's
`selected_asset_binding_preserves_sdk_selection_and_exact_current_scope` test;
Core integration tests exercise ordinary containers, updates and the exact
owned Pixel compound assets.
