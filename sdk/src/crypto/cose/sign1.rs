// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use async_generic::async_generic;
use c2pa_raw_crypto::SigningAlg;
use coset::{
    cbor::value::Value,
    iana::{self, Algorithm, EnumI64},
    CborSerializable, CoseSign1, Label, RegisteredLabelWithPrivate, TaggedCborSerializable,
};

use crate::{
    crypto::cose::{
        validate_cose_tst_info, validate_cose_tst_info_async, CertificateTrustPolicy, CoseError,
    },
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::CLAIM_SIGNATURE_MISMATCH,
};

/// Inspect an original COSE envelope without replacing its attached payload.
///
/// Accepts tagged Sign1 and the legacy untagged representation. The CBOR
/// decoder requires full consumption and rejects duplicate header labels.
/// This performs no signature, certificate, timestamp or trust verification;
/// use `parse_cose_sign1` for the verifier's detached-payload handling.
pub fn parse_cose_sign1_original(cose_bytes: &[u8]) -> Result<CoseSign1, CoseError> {
    CoseSign1::from_tagged_slice(cose_bytes)
        .or_else(|_| CoseSign1::from_slice(cose_bytes))
        .map_err(|error| CoseError::CborParsingError(error.to_string()))
}

/// Parse a byte slice as a COSE Sign1 data structure.
///
/// Log errors that might occur to the provided [`StatusTracker`].
pub fn parse_cose_sign1(
    cose_bytes: &[u8],
    data: &[u8],
    validation_log: &mut StatusTracker,
) -> Result<CoseSign1, CoseError> {
    let mut sign1 = <coset::CoseSign1 as TaggedCborSerializable>::from_tagged_slice(cose_bytes)
        .map_err(|coset_error| {
            log_item!(
                "Cose_Sign1",
                "could not parse signature",
                "parse_cose_sign1"
            )
            .validation_status(CLAIM_SIGNATURE_MISMATCH)
            .failure_no_throw(
                validation_log,
                CoseError::CborParsingError(coset_error.to_string()),
            );

            CoseError::CborParsingError(coset_error.to_string())
        })?;

    // Temporarily restore the payload into the signature for verification check.
    sign1.payload = Some(data.to_vec());

    Ok(sign1)
}

/// TO DO: Documentation for this function.
pub fn signing_alg_from_sign1(sign1: &coset::CoseSign1) -> Result<SigningAlg, CoseError> {
    let Some(ref alg) = sign1.protected.header.alg else {
        return Err(CoseError::UnsupportedSigningAlgorithm);
    };

    match alg {
        RegisteredLabelWithPrivate::PrivateUse(a) => match a {
            -39 => Ok(SigningAlg::Ps512),
            -38 => Ok(SigningAlg::Ps384),
            -37 => Ok(SigningAlg::Ps256),
            -36 => Ok(SigningAlg::Es512),
            -35 => Ok(SigningAlg::Es384),
            -7 => Ok(SigningAlg::Es256),
            -8 => Ok(SigningAlg::Ed25519),
            _ => Err(CoseError::UnsupportedSigningAlgorithm),
        },

        RegisteredLabelWithPrivate::Assigned(a) => match a {
            Algorithm::PS512 => Ok(SigningAlg::Ps512),
            Algorithm::PS384 => Ok(SigningAlg::Ps384),
            Algorithm::PS256 => Ok(SigningAlg::Ps256),
            Algorithm::ES512 => Ok(SigningAlg::Es512),
            Algorithm::ES384 => Ok(SigningAlg::Es384),
            Algorithm::ES256 => Ok(SigningAlg::Es256),
            Algorithm::EdDSA => Ok(SigningAlg::Ed25519),
            _ => Err(CoseError::UnsupportedSigningAlgorithm),
        },

        _ => Err(CoseError::UnsupportedSigningAlgorithm),
    }
}

/// TO DO: Documentation for this function.
pub fn cert_chain_from_sign1(sign1: &coset::CoseSign1) -> Result<Vec<Vec<u8>>, CoseError> {
    // Check the protected header first.
    let Some(value) = sign1
        .protected
        .header
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("x5chain".to_string())
                || x.0 == Label::Int(iana::HeaderParameter::X5Chain.to_i64())
            {
                Some(x.1.clone())
            } else {
                None
            }
        })
    else {
        // Not there: Also try unprotected header. (This was permitted in older versions
        // of C2PA.)
        return get_unprotected_header_certs(sign1);
    };

    // Certs may be in protected or unprotected header, but not both.
    if get_unprotected_header_certs(sign1).is_ok() {
        return Err(CoseError::MultipleSigningCertificateChains);
    }

    cert_chain_from_cbor_value(value)
}

fn get_unprotected_header_certs(sign1: &coset::CoseSign1) -> Result<Vec<Vec<u8>>, CoseError> {
    let Some(value) = sign1
        .unprotected
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("x5chain".to_string())
                || x.0 == Label::Int(iana::HeaderParameter::X5Chain.to_i64())
            {
                Some(x.1.clone())
            } else {
                None
            }
        })
    else {
        return Err(CoseError::MissingSigningCertificateChain);
    };

    cert_chain_from_cbor_value(value)
}

fn cert_chain_from_cbor_value(value: Value) -> Result<Vec<Vec<u8>>, CoseError> {
    match value {
        Value::Array(cert_chain) => {
            let certs: Vec<Vec<u8>> = cert_chain
                .iter()
                .filter_map(|c| {
                    if let Value::Bytes(der_bytes) = c {
                        Some(der_bytes.clone())
                    } else {
                        None
                    }
                })
                .collect();

            if certs.is_empty() {
                Err(CoseError::MissingSigningCertificateChain)
            } else {
                Ok(certs)
            }
        }

        Value::Bytes(ref der_bytes) => Ok(vec![der_bytes.clone()]),

        _ => Err(CoseError::MissingSigningCertificateChain),
    }
}

/// Return the time of signing for this signature.
///
/// Should not be used for certificate validation.
#[async_generic]
pub fn signing_time_from_sign1(
    sign1: &coset::CoseSign1,
    data: &[u8],
    verify_trust: bool,
) -> Option<chrono::DateTime<chrono::Utc>> {
    // get timestamp info if available

    let mut local_log = StatusTracker::default();
    // allow timestamp reading by using passthrough certificate check
    let local_ctp = CertificateTrustPolicy::passthrough();

    let time_stamp_info = if _sync {
        validate_cose_tst_info(sign1, data, &local_ctp, &mut local_log, verify_trust)
    } else {
        validate_cose_tst_info_async(sign1, data, &local_ctp, &mut local_log, verify_trust).await
    };

    if let Ok(tst_info) = time_stamp_info {
        Some(tst_info.gen_time.into())
    } else {
        None
    }
}

#[cfg(test)]
mod original_material_tests {
    use super::*;

    #[test]
    fn legacy_chain_labels_preserve_der_and_reject_two_header_chains() {
        let expected = vec![vec![0x30, 1], vec![0x30, 2]];
        let value = Value::Array(expected.iter().cloned().map(Value::Bytes).collect());
        for label in [Label::Int(33), Label::Text("x5chain".into())] {
            let mut sign1 = CoseSign1::default();
            sign1.unprotected.rest.push((label, value.clone()));
            assert_eq!(cert_chain_from_sign1(&sign1).unwrap(), expected);
            sign1
                .protected
                .header
                .rest
                .push((Label::Int(33), value.clone()));
            assert!(matches!(
                cert_chain_from_sign1(&sign1),
                Err(CoseError::MultipleSigningCertificateChains)
            ));
        }
    }

    #[test]
    fn original_payload_is_never_replaced_and_trailing_bytes_are_refused() {
        // COSE_Sign1([h'', {}, h'010203', h'ff']) and detached equivalent.
        let attached = [0xd2, 0x84, 0x40, 0xa0, 0x43, 1, 2, 3, 0x41, 0xff];
        let detached = [0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x41, 0xff];
        assert_eq!(
            parse_cose_sign1_original(&attached).unwrap().payload,
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            parse_cose_sign1_original(&attached[1..]).unwrap().payload,
            Some(vec![1, 2, 3])
        );
        assert_eq!(parse_cose_sign1_original(&detached).unwrap().payload, None);
        let checked =
            parse_cose_sign1(&attached, b"replacement", &mut StatusTracker::default()).unwrap();
        assert_eq!(checked.payload.as_deref(), Some(b"replacement".as_slice()));
        let mut trailing = attached.to_vec();
        trailing.push(0);
        assert!(parse_cose_sign1_original(&trailing).is_err());
        assert!(parse_cose_sign1_original(&attached[..attached.len() - 1]).is_err());
        assert!(parse_cose_sign1_original(&[0xd3, 0x84, 0x40, 0xa0, 0xf6, 0x41, 0xff]).is_err());
    }
}
