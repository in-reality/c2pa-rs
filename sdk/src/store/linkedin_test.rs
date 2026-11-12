//! Bounded imported-store and exact signed-history regressions.
//! These fixtures use SDK test media and do not establish real-world trust.

use super::*;
use crate::utils::test::{create_test_claim, fixture_path};

// Parser-structure fixtures only. These are not signature/trust positives.
fn aggregate_mixed_parser_fixture(trailing: usize) -> (Vec<u8>, usize) {
    use brotli::enc::BrotliEncoderParams;
    let first = crate::utils::test::create_test_store()
        .unwrap()
        .to_jumbf_internal(0)
        .unwrap();
    let second = crate::utils::test::create_test_store()
        .unwrap()
        .to_jumbf_internal(0)
        .unwrap();
    let one = raw_manifest_boxes(&first).unwrap()[0].to_vec();
    let two = raw_manifest_boxes(&second).unwrap()[0].to_vec();
    let mut decoded = two.clone();
    decoded.extend(std::iter::repeat_n(0x5a, trailing));
    let mut compressed = Vec::new();
    brotli::BrotliCompress(
        &mut Cursor::new(&decoded),
        &mut compressed,
        &BrotliEncoderParams::default(),
    )
    .unwrap();
    let mut wrapper = JUMBFSuperBox::new("aggregate.inactive", Some(CAI_COMPRESSED_MANIFEST_UUID));
    wrapper.add_data_box(Box::new(JUMBFBrotliContentBox::new(compressed)));
    let mut cai = Cai::new();
    cai.add_box(Box::new(wrapper));
    cai.add_box(Box::new(
        BoxReader::read_super_box(&mut Cursor::new(&one)).unwrap(),
    ));
    let mut bytes = Vec::new();
    cai.super_box().write_box(&mut bytes).unwrap();
    (bytes, one.len() + two.len() + trailing)
}

#[test]
fn aggregate_store_mixed_inactive_uncompressed_exact_byte_boundaries() {
    let (bytes, n) = aggregate_mixed_parser_fixture(0);
    for limit in [n - 1, n, n + 1] {
        let parsed = Store::from_jumbf_impl(
            Store::new(),
            &bytes,
            &mut StatusTracker::default(),
            32 * 1024 * 1024,
            Some(limit),
        );
        if limit < n {
            assert!(matches!(parsed, Err(Error::InsufficientMemory)));
        } else {
            assert_eq!(parsed.unwrap().claims().len(), 2);
        }
    }
}

#[test]
fn aggregate_store_counts_all_trailing_decoded_bytes() {
    let (bytes, n) = aggregate_mixed_parser_fixture(7);
    assert!(matches!(
        Store::from_jumbf_impl(
            Store::new(),
            &bytes,
            &mut StatusTracker::default(),
            32 * 1024 * 1024,
            Some(n - 1)
        ),
        Err(Error::InsufficientMemory)
    ));
    assert_eq!(
        Store::from_jumbf_impl(
            Store::new(),
            &bytes,
            &mut StatusTracker::default(),
            32 * 1024 * 1024,
            Some(n)
        )
        .unwrap()
        .claims()
        .len(),
        2
    );
}

#[test]
fn aggregate_counter_zero_overflow_and_failure_before_materialization() {
    use std::io::Write;
    let mut counter = DecodedManifestCounter {
        limit: 3,
        bytes: 0,
        exceeded: false,
    };
    counter.write_all(&[1, 2]).unwrap();
    counter.write_all(&[3]).unwrap();
    assert!(counter.write_all(&[4]).is_err());
    assert_eq!(counter.bytes, 3);
    assert!(counter.exceeded);
    let mut overflow = DecodedManifestCounter {
        limit: usize::MAX,
        bytes: usize::MAX,
        exceeded: false,
    };
    assert!(overflow.write_all(&[1]).is_err());
    assert!(overflow.exceeded);
    // Decoded zero bytes are not a valid manifest: over-budget must reject
    // before CAIManifest/Claim parsing; at-budget must report malformed data.
    let malformed = make_brotli_bomb_jumbf(32);
    assert!(matches!(
        Store::from_jumbf_impl(
            Store::new(),
            &malformed,
            &mut StatusTracker::default(),
            1024,
            Some(31)
        ),
        Err(Error::InsufficientMemory)
    ));
    let parsed = Store::from_jumbf_impl(
        Store::new(),
        &malformed,
        &mut StatusTracker::default(),
        1024,
        Some(32),
    );
    assert!(parsed.is_err() && !matches!(parsed, Err(Error::InsufficientMemory)));
    let (bytes, _) = aggregate_mixed_parser_fixture(0);
    assert!(matches!(
        Store::from_jumbf_impl(
            Store::new(),
            &bytes,
            &mut StatusTracker::default(),
            1024 * 1024,
            Some(0)
        ),
        Err(Error::InsufficientMemory)
    ));
}

#[test]
fn aggregate_none_and_explicit_context_routes_preserve_semantics() {
    let (bytes, _) = aggregate_mixed_parser_fixture(0);
    assert_eq!(
        Store::from_jumbf_impl(
            Store::new(),
            &bytes,
            &mut StatusTracker::default(),
            32 * 1024 * 1024,
            None
        )
        .unwrap()
        .claims()
        .len(),
        2
    );
    let context = Context::new()
        .with_settings(serde_json::json!({"core":{"max_decompressed_store_size_in_mb":0}}))
        .unwrap();
    assert!(matches!(
        Store::from_jumbf_with_context(&bytes, &mut StatusTracker::default(), &context),
        Err(Error::InsufficientMemory)
    ));
    assert_eq!(
        Store::from_jumbf_with_context(&bytes, &mut StatusTracker::default(), &Context::new())
            .unwrap()
            .claims()
            .len(),
        2
    );
}

fn make_brotli_bomb_jumbf(decompressed_size: usize) -> Vec<u8> {
    use brotli::enc::BrotliEncoderParams;

    use crate::jumbf::boxes::{
        BMFFBox, Cai, JUMBFBrotliContentBox, JUMBFSuperBox, CAI_MANIFEST_UUID,
    };

    let payload = vec![0u8; decompressed_size];
    let mut compressed = Vec::new();
    brotli::BrotliCompress(
        &mut Cursor::new(payload.as_slice()),
        &mut compressed,
        &BrotliEncoderParams::default(),
    )
    .expect("brotli compress");

    let brotli_box = JUMBFBrotliContentBox::new(compressed);
    let mut manifest_sbox = JUMBFSuperBox::new("test.manifest", Some(CAI_MANIFEST_UUID));
    manifest_sbox.add_data_box(Box::new(brotli_box));

    let mut cai = Cai::new();
    cai.add_box(Box::new(manifest_sbox));

    let mut bytes = Vec::new();
    cai.super_box()
        .write_box(&mut bytes)
        .expect("serialize cai block");
    bytes
}

#[test]
fn test_preparation_inactive_history_survives_store_resolver() {
    let context = Context::new();
    let mut file = std::fs::File::open(fixture_path("C.jpg")).unwrap();
    let (bytes, _) = Store::load_jumbf_from_stream("image/jpeg", &mut file, &context).unwrap();
    let mut source =
        Store::from_jumbf_with_context(&bytes, &mut StatusTracker::default(), &context).unwrap();
    let governing = source.provenance_claim().unwrap().clone();
    let mut inactive = governing.clone();
    inactive.set_conflict_label("urn:uuid:inactive-history".to_owned());
    source.insert_restored_claim(inactive.label().to_owned(), inactive.clone());
    source.set_provenance_path(&governing);
    let resolved = Store::build_flat_ingredient_store(&source, &governing).unwrap();
    assert!(
        resolved.get_claim(inactive.label()).is_some(),
        "unreferenced history must survive resolution"
    );
    assert_eq!(
        resolved.provenance_claim().unwrap().label(),
        governing.label()
    );
}

#[test]
fn test_preparation_raw_cache_cannot_resurrect_changed_signatures() {
    let context = Context::new();
    let mut file = std::fs::File::open(fixture_path("C.jpg")).unwrap();
    let (bytes, _) = Store::load_jumbf_from_stream("image/jpeg", &mut file, &context).unwrap();
    let mut source =
        Store::from_jumbf_with_context(&bytes, &mut StatusTracker::default(), &context).unwrap();
    let claim = source.provenance_claim_mut().unwrap();
    let mut normalized = Vec::new();
    Store::build_manifest_box(claim, 0)
        .unwrap()
        .write_box(&mut normalized)
        .unwrap();
    assert!(claim.preserved_manifest(&sha256(&normalized)).is_some());
    claim.set_signature_val(vec![0x21; 64]);
    normalized.clear();
    Store::build_manifest_box(claim, 0)
        .unwrap()
        .write_box(&mut normalized)
        .unwrap();
    assert!(claim.preserved_manifest(&sha256(&normalized)).is_none());
    let serialized = source.to_jumbf_internal(0).unwrap();
    let restored =
        Store::from_jumbf_with_context(&serialized, &mut StatusTracker::default(), &context)
            .unwrap();
    assert_eq!(
        restored.provenance_claim().unwrap().signature_val(),
        &vec![0x21; 64]
    );
}

#[test]
fn test_import_preserves_raw_manifest_box_description() {
    // A manifest's optional JUMBF box ID is admitted by the existing parser.
    // It is not part of claim CBOR, so preserving claim.data() is insufficient.
    let context = crate::context::Context::new();
    let mut source = std::fs::File::open(fixture_path("C.jpg")).unwrap();
    let (mut bytes, _) =
        Store::load_jumbf_from_stream("image/jpeg", &mut source, &context).unwrap();
    let size = |data: &[u8], offset: usize| {
        u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize
    };
    // This committed fixture uses 32-bit lengths and one leading store
    // description followed by the first signed manifest superbox.
    let manifest = 8 + size(&bytes, 8);
    assert_eq!(&bytes[manifest + 4..manifest + 8], b"jumb");
    let description = manifest + 8;
    assert_eq!(&bytes[description + 4..description + 8], b"jumd");
    let end = description + size(&bytes, description);
    assert_eq!(bytes[description + 24], 3);
    bytes[description + 24] |= 4;
    bytes.splice(end..end, 0x2105_u32.to_be_bytes());
    for offset in [0, manifest, description] {
        let updated = (size(&bytes, offset) + 4) as u32;
        bytes[offset..offset + 4].copy_from_slice(&updated.to_be_bytes());
    }
    let expected = &bytes[manifest..manifest + size(&bytes, manifest)];
    // Exercise the real Claim import boundary, not Reader JSON equivalence.
    let mut claim = create_test_claim().unwrap();
    Store::load_ingredient_to_claim(&mut claim, &bytes, None, &context).unwrap();
    let mut output = Store::from_context(&context);
    output.commit_claim(claim).unwrap();
    let candidate = output.to_jumbf_internal(4096).unwrap();
    let imported = 8 + size(&candidate, 8);
    assert_eq!(
        &candidate[imported..imported + size(&candidate, imported)],
        expected,
        "ordinary ingredient import must preserve every prior signed manifest box byte"
    );
}

#[test]
fn test_import_preserves_raw_signature_box_description_hash() {
    // Same licensed committed fixture as the outer-manifest regression.
    // A legal optional signature-box ID is outside claim CBOR/COSE, but
    // inside the byte domain of Ingredient_v3's claimSignature hash.
    let context = crate::context::Context::new();
    let mut source = std::fs::File::open(fixture_path("C.jpg")).unwrap();
    let (mut bytes, _) =
        Store::load_jumbf_from_stream("image/jpeg", &mut source, &context).unwrap();
    let size = |data: &[u8], offset: usize| {
        u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize
    };
    let manifest = 8 + size(&bytes, 8);
    let end = manifest + size(&bytes, manifest);
    let mut signature = None;
    let mut at = manifest + 8 + size(&bytes, manifest + 8);
    while at < end {
        let length = size(&bytes, at);
        if &bytes[at + 4..at + 8] == b"jumb" {
            let desc = at + 8;
            let name = bytes[desc + 25..desc + size(&bytes, desc)]
                .split(|byte| *byte == 0)
                .next()
                .unwrap();
            if name == b"c2pa.signature" {
                signature = Some(at);
                break;
            }
        }
        at += length;
    }
    let signature = signature.expect("fixture has a signature superbox");
    let description = signature + 8;
    let insertion = description + size(&bytes, description);
    assert_eq!(bytes[description + 24], 3);
    bytes[description + 24] |= 4;
    bytes.splice(insertion..insertion, 0x2105_u32.to_be_bytes());
    for offset in [0, manifest, signature, description] {
        let updated = (size(&bytes, offset) + 4) as u32;
        bytes[offset..offset + 4].copy_from_slice(&updated.to_be_bytes());
    }
    let expected_raw = &bytes[manifest..manifest + size(&bytes, manifest)];
    let mut loaded =
        Store::from_jumbf_with_context(&bytes, &mut StatusTracker::default(), &context).unwrap();
    let prior = loaded.claims()[0];
    let label = prior.label().to_owned();
    let expected_signature_hash = hash_by_alg(
        prior.alg(),
        &bytes[signature + 8..signature + size(&bytes, signature)],
        None,
    );

    let mut claim = create_test_claim().unwrap();
    Store::load_ingredient_to_claim(&mut claim, &bytes, None, &context).unwrap();
    let mut output = Store::from_context(&context);
    output.commit_claim(claim).unwrap();
    let candidate = output.to_jumbf_internal(4096).unwrap();
    let imported = 8 + size(&candidate, 8);
    assert_eq!(
        &candidate[imported..imported + size(&candidate, imported)],
        expected_raw,
        "the prior signed signature-box description must survive actual import"
    );
    assert_eq!(
        loaded.get_manifest_box_hashes(prior).signature_box_hash,
        expected_signature_hash,
        "loaded claimSignature hash must cover actual raw payload"
    );
    assert_eq!(
        output
            .get_manifest_box_hashes(output.get_claim(&label).unwrap())
            .signature_box_hash,
        expected_signature_hash,
        "imported claimSignature hash must cover the same preserved raw payload"
    );
    let alg = prior.alg().to_owned();
    // The loaded path has a populated cache; the imported Store exercises
    // its fallback. Independently hash the signature payload actually
    // serialized after each mutation, not either implementation helper.
    for store in [&mut loaded, &mut output] {
        store
            .get_claim_mut(&label)
            .unwrap()
            .set_signature_val(vec![0x21; 64]);
        let serialized = store.to_jumbf_internal(0).unwrap();
        let manifest = 8 + size(&serialized, 8);
        let end = manifest + size(&serialized, manifest);
        let mut at = manifest + 8 + size(&serialized, manifest + 8);
        let mut actual_signature_hash = None;
        while at < end {
            let length = size(&serialized, at);
            if &serialized[at + 4..at + 8] == b"jumb" {
                let desc = at + 8;
                let name = serialized[desc + 25..desc + size(&serialized, desc)]
                    .split(|byte| *byte == 0)
                    .next()
                    .unwrap();
                if name == b"c2pa.signature" {
                    actual_signature_hash =
                        Some(hash_by_alg(&alg, &serialized[at + 8..at + length], None));
                    break;
                }
            }
            at += length;
        }
        let expected_changed = actual_signature_hash.unwrap();
        assert_ne!(expected_changed, expected_signature_hash);
        assert_eq!(
            store
                .get_manifest_box_hashes(store.get_claim(&label).unwrap())
                .signature_box_hash,
            expected_changed,
            "loaded/imported hash paths must follow the changed actual signature payload"
        );
    }
}
