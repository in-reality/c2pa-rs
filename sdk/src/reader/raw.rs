//! Narrow immutable raw-read boundary; no public Store/Claim or validation bypass.
//!
//! Upstream Reader currently exposes display projections which can omit binary
//! assertions and erase CBOR distinctions. Remove this fork API when upstream
//! supplies equivalent exact payload, inventory and original claim access.

use crate::{assertion::AssertionData, Error, Reader, Result};

/// Original assertion encoding, independent of display JSON and label vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawAssertionKind<'a> {
    /// Original JSON text bytes.
    Json,
    /// Original CBOR bytes, retaining byte strings, tags and numeric encodings.
    Cbor,
    /// Binary assertion with its original media type.
    Binary(&'a str),
    /// UUID assertion with its original UUID and content type.
    Uuid {
        uuid: &'a str,
        content_type: &'a str,
    },
}

/// Original signed reference collection; ordering/attribution is never inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawReferenceCollection {
    /// Claim v1 combined assertions.
    Assertions,
    /// Claim v2 signer-created assertions.
    Created,
    /// Claim v2 gathered assertions.
    Gathered,
}

/// One original reference position with SDK URI normalization performed once.
/// This names a syntactic target, never an authenticated/resolved assertion.
#[derive(Debug)]
pub struct RawReference {
    /// Original signed collection.
    pub collection: RawReferenceCollection,
    /// Original array index in that collection.
    pub index: usize,
    /// Original URL, unchanged.
    pub url: String,
    /// Target URI normalized by the existing SDK resolver, without hash checks.
    pub target_uri: String,
}

/// Complete assertion-store inventory entry, including unrecognized payloads.
/// Hash/algorithm/salt describe the original assertion box domain; none establishes
/// validation, reference resolution or signer trust.
#[derive(Debug)]
pub struct RawAssertion<'a> {
    /// Label including the original instance discriminator.
    pub label: String,
    /// Original absolute assertion URI in this claim's namespace.
    pub uri: String,
    /// Exact payload encoding.
    pub kind: RawAssertionKind<'a>,
    /// Original payload bytes, never a reserialization.
    pub data: &'a [u8],
    /// SDK assertion-box hash in its original hash domain.
    pub box_hash: &'a [u8],
    /// Assertion-box hashing algorithm.
    pub hash_algorithm: &'a str,
    /// Original assertion-box salt, if any.
    pub salt: Option<&'a [u8]>,
}

/// Borrowed original signed evidence for one claim. Created/gathered references
/// and unknown claim metadata remain in original_cbor, not a typed reserialization.
#[derive(Debug)]
pub struct RawManifest<'a> {
    /// Selected claim label.
    pub label: &'a str,
    /// Claim's original manifest URI.
    pub uri: String,
    /// Claim version parsed by the SDK from its original label.
    pub claim_version: usize,
    /// Exact original claim CBOR bytes.
    pub original_cbor: &'a [u8],
    /// Exact original signature-box payload.
    pub signature: &'a [u8],
    /// Original reference inventory in collection order, normalized once.
    pub references: Vec<RawReference>,
    /// Every assertion-store entry, without vocabulary/format filtering.
    pub assertions: Vec<RawAssertion<'a>>,
}

impl Reader {
    /// Borrows original payloads after the same SDK read. Fails explicitly when
    /// original claim bytes are unavailable; it never calls Claim::data's
    /// authoring reserialization fallback. Unknown labels are errors. This API
    /// creates no validation successes and changes no SDK validation path.
    pub fn raw_manifest(&self, label: &str) -> Result<RawManifest<'_>> {
        let claim = self
            .store
            .get_claim(label)
            .ok_or_else(|| Error::ResourceNotFound(label.to_owned()))?;
        let original_cbor = claim
            .original_data()
            .ok_or_else(|| Error::OtherError("original claim bytes unavailable".into()))?;
        let mut references = Vec::new();
        if claim.version() == 1 {
            append_references(
                &mut references,
                RawReferenceCollection::Assertions,
                claim.assertions(),
                claim.label(),
            );
        } else {
            append_references(
                &mut references,
                RawReferenceCollection::Created,
                claim.created_assertions(),
                claim.label(),
            );
            if let Some(gathered) = claim.gathered_assertions() {
                append_references(
                    &mut references,
                    RawReferenceCollection::Gathered,
                    gathered,
                    claim.label(),
                );
            }
        }
        let assertions = claim
            .claim_assertion_store()
            .iter()
            .map(|entry| {
                let assertion = entry.assertion();
                let kind = match assertion.decode_data() {
                    AssertionData::Json(_) => RawAssertionKind::Json,
                    AssertionData::Cbor(_) => RawAssertionKind::Cbor,
                    AssertionData::Binary(_) => RawAssertionKind::Binary(assertion.content_type()),
                    AssertionData::Uuid(uuid, _) => RawAssertionKind::Uuid {
                        uuid,
                        content_type: assertion.content_type(),
                    },
                };
                let label = entry.label();
                let uri = claim.assertion_uri(&label);
                RawAssertion {
                    uri,
                    label,
                    kind,
                    data: assertion.data(),
                    box_hash: entry.hash(),
                    hash_algorithm: entry.hash_alg(),
                    salt: entry.salt().as_deref(),
                }
            })
            .collect();
        Ok(RawManifest {
            label: claim.label(),
            uri: claim.uri(),
            claim_version: claim.version(),
            original_cbor,
            signature: claim.signature_val(),
            assertions,
            references,
        })
    }
}

fn append_references(
    out: &mut Vec<RawReference>,
    collection: RawReferenceCollection,
    references: &[crate::HashedUri],
    label: &str,
) {
    out.extend(references.iter().enumerate().map(|(index, reference)| {
        let url = reference.url();
        let target_uri = crate::jumbf::labels::to_absolute_uri(label, &url);
        RawReference {
            collection,
            index,
            url,
            target_uri,
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assertion::{Assertion, AssertionData},
        claim::{Claim, ClaimAssertion, ClaimAssertionType},
        store::Store,
        Context,
    };
    use std::{io::Cursor, sync::Arc};

    #[test]
    fn authored_claim_never_falls_back_to_reserialization() {
        let mut claim = Claim::new("raw-test", None, 2);
        claim.add_claim_generator_info(crate::ClaimGeneratorInfo::new("raw-test"));
        let label = claim.label().to_owned();
        assert!(claim.data().is_ok());
        assert!(claim.original_data().is_none());
        let mut store = Store::new();
        store.insert_restored_claim(label.clone(), claim);
        let mut reader = Reader::default();
        reader.store = Arc::new(store);
        assert!(
            matches!(reader.raw_manifest(&label),Err(Error::OtherError(message)) if message.to_string() == "original claim bytes unavailable")
        );
    }

    #[test]
    fn inventory_does_not_filter_binary_uuid_or_repeated_unknown_instances() {
        // Inventory-only mutation of an SDK fixture. These added assertions are
        // deliberately unreferenced and are not evidence of a historical signer.
        let context=Context::new().with_settings(serde_json::json!({"verify":{
            "verify_after_reading":false,"verify_trust":false,"remote_manifest_fetch":false,"ocsp_fetch":false
        }})).unwrap();
        let mut reader = Reader::from_context(context)
            .with_stream(
                "image/jpeg",
                Cursor::new(include_bytes!("../../tests/fixtures/CA.jpg")),
            )
            .unwrap();
        let label = reader.active_label().unwrap().to_owned();
        let mut claim = reader.store.get_claim(&label).unwrap().clone();
        for (instance, data) in [
            AssertionData::Binary(vec![0, 255, 128]),
            AssertionData::Uuid("00112233445566778899aabbccddeeff".into(), vec![9, 8, 7]),
        ]
        .into_iter()
        .enumerate()
        {
            let assertion = Assertion::new("org.example.unknown", None, data)
                .set_content_type("application/octet-stream");
            claim.put_assertion_store(ClaimAssertion::new(
                assertion,
                instance,
                &[17; 32],
                "sha256",
                Some(vec![3, 4]),
                ClaimAssertionType::Gathered,
            ));
        }
        let mut store = Store::new();
        store.insert_restored_claim(label.clone(), claim);
        reader.store = Arc::new(store);
        let raw = reader.raw_manifest(&label).unwrap();
        let added: Vec<_> = raw
            .assertions
            .iter()
            .filter(|a| a.label.starts_with("org.example.unknown"))
            .collect();
        assert_eq!(added.len(), 2);
        assert_eq!(
            added[0].kind,
            RawAssertionKind::Binary("application/octet-stream")
        );
        assert_eq!(added[0].data, &[0, 255, 128]);
        assert!(matches!(
            added[1].kind,
            RawAssertionKind::Uuid {
                uuid: "00112233445566778899aabbccddeeff",
                ..
            }
        ));
        assert_eq!(added[1].label, "org.example.unknown__1");
        assert_eq!(added[1].data, &[9, 8, 7]);
    }

    #[test]
    fn ten_thousand_original_references_keep_complete_inventory_positions() {
        use c2pa_cbor::Value as C;
        use std::collections::BTreeMap;
        let context=Context::new().with_settings(serde_json::json!({"verify":{
            "verify_after_reading":false,"verify_trust":false,"remote_manifest_fetch":false,"ocsp_fetch":false
        }})).unwrap();
        let mut reader = Reader::from_context(context)
            .with_stream(
                "image/jpeg",
                Cursor::new(include_bytes!("../../tests/fixtures/CA.jpg")),
            )
            .unwrap();
        let label = reader.active_label().unwrap().to_owned();
        let raw = reader.raw_manifest(&label).unwrap();
        let version = raw.claim_version;
        let C::Map(mut original) = c2pa_cbor::from_slice::<C>(raw.original_cbor).unwrap() else {
            panic!()
        };
        let labels: Vec<_> = (0..10_000)
            .map(|index| format!("org.example.volume__{index}"))
            .collect();
        let references = labels
            .iter()
            .map(|name| {
                C::Map(BTreeMap::from([
                    (
                        C::Text("url".into()),
                        C::Text(format!("self#jumbf=c2pa.assertions/{name}")),
                    ),
                    (C::Text("hash".into()), C::Bytes(vec![17; 32])),
                ]))
            })
            .collect();
        original.insert(
            C::Text(
                if version == 1 {
                    "assertions"
                } else {
                    "created_assertions"
                }
                .into(),
            ),
            C::Array(references),
        );
        // Synthetic inventory-only claim: original signature/hash validation is
        // deliberately not claimed. This tests bounded normalization, not trust.
        let encoded = c2pa_cbor::to_vec(&C::Map(original)).unwrap();
        let mut claim = Claim::from_data(&label, &encoded).unwrap();
        for name in &labels {
            claim.put_assertion_store(ClaimAssertion::new(
                Assertion::new(name, None, AssertionData::Json("null".into()))
                    .set_content_type("application/json"),
                0,
                &[17; 32],
                "sha256",
                None,
                ClaimAssertionType::Gathered,
            ));
        }
        let mut store = Store::new();
        store.insert_restored_claim(label.clone(), claim);
        reader.store = Arc::new(store);
        let raw = reader.raw_manifest(&label).unwrap();
        assert_eq!(raw.assertions.len(), labels.len());
        assert!(raw.references.len() >= labels.len());
        assert_eq!(raw.references[0].index, 0);
        assert_eq!(raw.assertions[1].label, labels[1]);
    }
}
