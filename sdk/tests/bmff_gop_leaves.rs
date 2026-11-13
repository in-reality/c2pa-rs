//! Standard complete leaf rows for explicit, whole-payload BMFF v3 partitions.
//! Codec/GOP and live-device qualification belongs to capture, not this test.
#![allow(clippy::unwrap_used)]

use c2pa::{
    assertions::{BmffHash, MerkleMap},
    Builder, C2PAMerkleTree, MerkleNode,
};
use sha2::{Digest, Sha256};
use std::io::Cursor;

fn fixture(sizes: &[Vec<u64>]) -> (Vec<u8>, Vec<Vec<Vec<u8>>>, Vec<usize>) {
    let mut bytes = Vec::new();
    let mut rows = Vec::new();
    let mut starts = Vec::new();
    for (map, sizes) in sizes.iter().enumerate() {
        let len: u64 = sizes.iter().sum();
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(b"mdat");
        bytes.extend_from_slice(&(len + 16).to_be_bytes());
        starts.push(bytes.len());
        let mut row = Vec::new();
        for (leaf, size) in sizes.iter().enumerate() {
            let payload: Vec<u8> = (0..*size)
                .map(|i| (map * 47 + leaf * 19 + i as usize) as u8)
                .collect();
            row.push(Sha256::digest(&payload).to_vec());
            bytes.extend_from_slice(&payload);
        }
        rows.push(row);
    }
    (bytes, rows, starts)
}

fn assertion(rows: Vec<Vec<Vec<u8>>>, sizes: Vec<Vec<u64>>) -> BmffHash {
    let mut hash = BmffHash::new("GOP contract", "sha256", None);
    hash.set_bmff_version(3);
    hash.set_default_exclusions();
    let mut builder = Builder::default();
    builder.add_assertion("c2pa.hash.bmff.v3", &hash).unwrap();
    builder.set_bmff_mdat_variable_hashes(rows, sizes).unwrap();
    let stored = builder
        .definition
        .assertions
        .iter()
        .find(|a| a.label == "c2pa.hash.bmff.v3")
        .unwrap();
    let hash: BmffHash = c2pa_cbor::from_slice(&c2pa_cbor::to_vec(&stored.data).unwrap()).unwrap();
    // Exercise the serialized field representation, not only an in-memory map.
    let mut decoded: BmffHash = c2pa_cbor::from_slice(&c2pa_cbor::to_vec(&hash).unwrap()).unwrap();
    decoded.set_bmff_version(3);
    decoded
}

fn changed(hash: &BmffHash, f: impl FnOnce(&mut Vec<MerkleMap>)) -> BmffHash {
    let mut hash: BmffHash = c2pa_cbor::from_slice(&c2pa_cbor::to_vec(hash).unwrap()).unwrap();
    hash.set_bmff_version(3);
    let mut maps: Vec<MerkleMap> =
        c2pa_cbor::from_slice(&c2pa_cbor::to_vec(hash.merkle().unwrap()).unwrap()).unwrap();
    f(&mut maps);
    hash.set_merkle(maps);
    hash
}

#[test]
fn exact_serialized_one_odd_even_rows_and_individual_leaf_tamper() {
    for sizes in [
        vec![vec![50]],
        vec![vec![50, 50, 40]],
        vec![vec![30, 30]],
        vec![vec![50, 30], vec![50, 40]],
        vec![vec![607, 308, 31]],
    ] {
        let (bytes, rows, starts) = fixture(&sizes);
        let hash = assertion(rows.clone(), sizes.clone());
        hash.verify_stream_hash(&mut Cursor::new(&bytes), None)
            .unwrap();
        for (index, map) in hash.merkle().unwrap().iter().enumerate() {
            assert_eq!(map.local_id, index);
            assert_eq!(map.count, sizes[index].len());
            assert_eq!(map.hashes.len(), map.count);
            assert_eq!(map.variable_block_sizes.as_ref().unwrap(), &sizes[index]);
            assert!(map.fixed_block_size.is_none() && map.init_hash.is_none());
            for (stored, expected) in map.hashes.iter().zip(&rows[index]) {
                assert_eq!(stored.as_ref(), expected.as_slice());
            }
            let json = serde_json::to_value(map).unwrap();
            assert!(
                json.get("root").is_none()
                    && json.get("fixedBlockSize").is_none()
                    && json.get("initHash").is_none()
            );
            let nodes = rows[index].iter().cloned().map(MerkleNode).collect();
            let tree = C2PAMerkleTree::from_leaves(nodes, "sha256", false);
            let root = tree.get_root().unwrap().clone();
            if map.count == 1 {
                assert_eq!(root, rows[index][0]);
            }
            let mut offset = starts[index];
            for (leaf_index, size) in sizes[index].iter().enumerate() {
                // First/last bytes include prefixes/suffixes of capture-owned ranges.
                for byte in [offset, offset + *size as usize - 1] {
                    let mut bad = bytes.clone();
                    bad[byte] ^= 1;
                    assert!(hash
                        .verify_stream_hash(&mut Cursor::new(bad), None)
                        .is_err());
                }
                let mut altered = rows[index].clone();
                altered[leaf_index][0] ^= 1;
                let bad_tree = C2PAMerkleTree::from_leaves(
                    altered.into_iter().map(MerkleNode).collect(),
                    "sha256",
                    false,
                );
                assert_ne!(*bad_tree.get_root().unwrap(), root);
                offset += *size as usize;
            }
        }
    }
}

#[test]
fn serialized_count_size_row_and_map_inconsistencies_fail() {
    let sizes = vec![vec![50, 50, 40], vec![30, 30]];
    let (bytes, rows, _) = fixture(&sizes);
    let hash = assertion(rows, sizes);
    let rejects = |f: fn(&mut Vec<MerkleMap>)| {
        let bad = changed(&hash, f);
        assert!(bad
            .verify_stream_hash(&mut Cursor::new(&bytes), None)
            .is_err());
    };
    rejects(|m| m[0].variable_block_sizes = Some(vec![49, 51, 40]));
    rejects(|m| m[0].variable_block_sizes = Some(vec![50, 50, 39]));
    rejects(|m| m[0].variable_block_sizes = Some(vec![50, 50, 41]));
    rejects(|m| m[0].variable_block_sizes = Some(vec![0, 100, 40]));
    rejects(|m| m[0].variable_block_sizes = Some(vec![u64::MAX, 1, 1]));
    rejects(|m| m[0].variable_block_sizes = Some(vec![50, 90]));
    rejects(|m| m[0].count = 2);
    rejects(|m| {
        m[0].hashes.0.pop();
    });
    rejects(|m| {
        m[0].hashes.0.swap(0, 1);
    });
    rejects(|m| {
        let extra = m[0].hashes.0[2].clone();
        m[0].hashes.0.push(extra);
    });
    rejects(|m| {
        m[0].hashes.0[1] = vec![0u8; 32].into();
    });
    rejects(|m| {
        m[0].hashes.0 = vec![vec![0u8; 32].into()];
    });
    rejects(|m| m[0].local_id = 1);
    rejects(|m| {
        m.pop();
    });
    rejects(|m| {
        let extra: MerkleMap = c2pa_cbor::from_slice(&c2pa_cbor::to_vec(&m[0]).unwrap()).unwrap();
        m.push(extra);
    });
    rejects(|m| m[0].fixed_block_size = Some(50));
    rejects(|m| m[0].init_hash = Some(vec![0u8; 32].into()));
}

#[test]
fn injection_rejects_inconsistent_or_overflowing_inputs() {
    for (rows, sizes) in [
        (vec![], vec![]),
        (vec![vec![vec![0; 32]]], vec![vec![0]]),
        (vec![vec![vec![0; 31]]], vec![vec![1]]),
        (vec![vec![vec![0; 32]]], vec![vec![1, 2]]),
        (
            vec![vec![vec![0; 32], vec![0; 32]]],
            vec![vec![u64::MAX, 1]],
        ),
    ] {
        let mut hash = BmffHash::new("bad", "sha256", None);
        hash.set_bmff_version(3);
        assert!(hash.add_mdat_variable_leaf_hashes(rows, sizes).is_err());
        assert!(hash.merkle().is_none());
    }
}
