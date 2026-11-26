//! Raw boundary regressions over the SDK's existing signed immutable fixture.
use c2pa::{Context, RawAssertionKind, Reader};
use serde_json::json;
use std::io::Cursor;

#[test]
fn signed_fixture_exposes_original_claim_and_every_assertion_instance() {
    let bytes = include_bytes!("fixtures/CA.jpg");
    let context = Context::new().with_settings(json!({"verify":{
        "verify_after_reading":false,"verify_trust":false,"remote_manifest_fetch":false,"ocsp_fetch":false
    }})).unwrap();
    let reader = Reader::from_context(context)
        .with_stream("image/jpeg", Cursor::new(bytes))
        .unwrap();
    for label in reader.manifests().keys() {
        let raw = reader.raw_manifest(label).unwrap();
        assert_eq!(raw.label, label);
        assert!(!raw.original_cbor.is_empty());
        assert!(!raw.signature.is_empty());
        let claim: c2pa_cbor::Value = c2pa_cbor::from_slice(raw.original_cbor).unwrap();
        assert!(matches!(claim, c2pa_cbor::Value::Map(_)));
        assert!(!raw.assertions.is_empty());
        assert!(raw
            .assertions
            .iter()
            .all(|a| !a.data.is_empty() && a.uri.contains(&a.label)));
        assert!(raw
            .assertions
            .iter()
            .any(|a| matches!(a.kind, RawAssertionKind::Cbor)));
        let repeated = reader.raw_manifest(label).unwrap();
        assert!(std::ptr::eq(raw.original_cbor, repeated.original_cbor));
        for (a, b) in raw.assertions.iter().zip(&repeated.assertions) {
            assert_eq!(a.label, b.label);
            assert_eq!(a.kind, b.kind);
            assert!(std::ptr::eq(a.data, b.data));
        }
    }
    assert!(reader.raw_manifest("missing").is_err());
}
