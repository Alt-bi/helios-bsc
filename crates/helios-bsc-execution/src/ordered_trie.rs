//! Ordered hexary Patricia trie root (geth `DeriveSha` / yellow-paper tx & receipt lists).
//!
//! Keys are `RLP(uint index)`; values are the raw item bytes (already RLP-encoded).
//! Empty list → [`EMPTY_TRIE_ROOT`] (`keccak256(0x80)`).

use crate::mpt::{bytes_to_nibbles, EMPTY_TRIE_ROOT};
use crate::rlp::{encode_bytes, encode_list, encode_uint};
use helios_bsc_types::keccak256;

/// Intended cap for tx/receipt lists. Extra items are ignored.
pub const MAX_ORDERED_TRIE_ITEMS: usize = 4096;

/// Root of the hexary trie of `items[i]` at key `RLP(i)`.
pub fn ordered_trie_root(items: &[Vec<u8>]) -> [u8; 32] {
    let items = &items[..items.len().min(MAX_ORDERED_TRIE_ITEMS)];
    if items.is_empty() {
        return EMPTY_TRIE_ROOT;
    }
    let mut pairs: Vec<(Vec<u8>, &[u8])> = items
        .iter()
        .enumerate()
        .map(|(i, item)| (bytes_to_nibbles(&encode_uint(i as u64)), item.as_slice()))
        .collect();
    // RLP(0)=0x80 sorts after 1..=127; grouping by nibble needs lexicographic keys.
    pairs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    keccak256(&encode_node(&pairs, 0))
}

fn encode_node(input: &[(Vec<u8>, &[u8])], pre_len: usize) -> Vec<u8> {
    if input.is_empty() {
        return encode_bytes(&[]);
    }

    let key = input[0].0.as_slice();
    let value = input[0].1;

    if input.len() == 1 {
        let hp = hex_prefix_encode(&key[pre_len..], true);
        return encode_list(&[encode_bytes(&hp), encode_bytes(value)]);
    }

    let mut shared = key.len();
    for (k, _) in &input[1..] {
        shared = shared.min(shared_prefix_len(key, k));
    }

    if shared > pre_len {
        let hp = hex_prefix_encode(&key[pre_len..shared], false);
        let child = encode_node(input, shared);
        return encode_list(&[encode_bytes(&hp), child_ref(&child)]);
    }

    let mut children = Vec::with_capacity(17);
    let mut begin = usize::from(pre_len == key.len());
    for nibble in 0u8..16 {
        let len = input[begin..]
            .iter()
            .take_while(|(k, _)| k[pre_len] == nibble)
            .count();
        if len == 0 {
            children.push(encode_bytes(&[]));
        } else {
            let child = encode_node(&input[begin..begin + len], pre_len + 1);
            children.push(child_ref(&child));
        }
        begin += len;
    }
    if pre_len == key.len() {
        children.push(encode_bytes(value));
    } else {
        children.push(encode_bytes(&[]));
    }
    encode_list(&children)
}

/// Inlined if `RLP(node) < 32` bytes (yellow paper); otherwise `keccak256` as a 32-byte string.
fn child_ref(encoded: &[u8]) -> Vec<u8> {
    if encoded.len() < 32 {
        encoded.to_vec()
    } else {
        encode_bytes(&keccak256(encoded))
    }
}

fn shared_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()))
}

/// Hex-prefix (compact) encoding: oddness = bit 0, leaf/terminator = bit 1.
fn hex_prefix_encode(nibbles: &[u8], leaf: bool) -> Vec<u8> {
    let odd = nibbles.len() % 2;
    let mut first = (u8::from(odd == 1) + 2 * u8::from(leaf)) << 4;
    if odd == 1 {
        first |= nibbles[0];
    }
    let rest = &nibbles[odd..];
    let mut out = Vec::with_capacity(1 + rest.len() / 2);
    out.push(first);
    for chunk in rest.chunks(2) {
        out.push((chunk[0] << 4) | chunk[1]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpt::hex_prefix_decode;
    use crate::rlp::{encode_bytes, encode_list};
    use helios_bsc_types::decode_hex_fixed;

    #[test]
    fn empty_is_empty_trie_root() {
        assert_eq!(ordered_trie_root(&[]), EMPTY_TRIE_ROOT);
        assert_eq!(keccak256(&[0x80]), EMPTY_TRIE_ROOT);
    }

    #[test]
    fn mutating_one_item_changes_root() {
        let a = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec()];
        let mut b = a.clone();
        b[1][0] ^= 1;
        assert_ne!(ordered_trie_root(&a), ordered_trie_root(&b));
    }

    #[test]
    fn different_lists_differ() {
        let a = vec![b"one".to_vec()];
        let b = vec![b"one".to_vec(), b"two".to_vec()];
        let c = vec![b"two".to_vec()];
        assert_ne!(ordered_trie_root(&a), ordered_trie_root(&b));
        assert_ne!(ordered_trie_root(&a), ordered_trie_root(&c));
        assert_ne!(ordered_trie_root(&b), ordered_trie_root(&c));
    }

    #[test]
    fn single_item_is_hashed_leaf() {
        let item = b"hello".to_vec();
        let hp = hex_prefix_encode(&[0x08, 0x00], true);
        assert_eq!(hp, vec![0x20, 0x80]);
        let leaf = encode_list(&[encode_bytes(&hp), encode_bytes(&item)]);
        let root = ordered_trie_root(std::slice::from_ref(&item));
        assert_eq!(root, keccak256(&leaf));
        assert_eq!(root.len(), 32);
        assert_ne!(root, EMPTY_TRIE_ROOT);
    }

    #[test]
    fn extras_beyond_max_ignored() {
        let mut items: Vec<Vec<u8>> = (0..MAX_ORDERED_TRIE_ITEMS).map(|i| vec![i as u8]).collect();
        let capped = ordered_trie_root(&items);
        items.push(vec![0xff]);
        assert_eq!(ordered_trie_root(&items), capped);
    }

    #[test]
    fn known_vector_doe_reindeer() {
        // triehash `ordered_trie_root(["doe", "reindeer"])`.
        let items = vec![b"doe".to_vec(), b"reindeer".to_vec()];
        let want = decode_hex_fixed::<32>(
            "0xe766d5d51b89dc39d981b41bda63248d7abce4f0225eefd023792a540bcffee3",
        )
        .unwrap();
        assert_eq!(ordered_trie_root(&items), want);
    }

    #[test]
    fn known_vector_secure_trie_example() {
        // geth / triehash: keys "doe","dog","dogglesworth" (not index-encoded).
        let pairs = [
            (b"doe".to_vec(), b"reindeer".as_slice()),
            (b"dog".to_vec(), b"puppy".as_slice()),
            (b"dogglesworth".to_vec(), b"cat".as_slice()),
        ];
        let mut nibbles: Vec<(Vec<u8>, &[u8])> = pairs
            .iter()
            .map(|(k, v)| (bytes_to_nibbles(k), *v))
            .collect();
        nibbles.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let root = keccak256(&encode_node(&nibbles, 0));
        let want = decode_hex_fixed::<32>(
            "0x8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3",
        )
        .unwrap();
        assert_eq!(root, want);
    }

    #[test]
    fn known_vector_single_long_value() {
        let pairs = [(
            b"A".to_vec(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
        )];
        let nibbles: Vec<(Vec<u8>, &[u8])> = pairs
            .iter()
            .map(|(k, v)| (bytes_to_nibbles(k), *v))
            .collect();
        let root = keccak256(&encode_node(&nibbles, 0));
        let want = decode_hex_fixed::<32>(
            "0xd23786fb4a010da3ce639d66d5e904a11dbc02746d1ce25029e53290cabf28ab",
        )
        .unwrap();
        assert_eq!(root, want);
    }

    #[test]
    fn hex_prefix_roundtrip() {
        let cases: &[&[u8]] = &[&[0, 0, 1, 2, 3, 4, 5], &[1, 2, 3, 4, 5], &[4, 1], &[]];
        for nibs in cases {
            for leaf in [false, true] {
                if nibs.is_empty() && !leaf {
                    continue;
                }
                let enc = hex_prefix_encode(nibs, leaf);
                let (got, is_leaf) = hex_prefix_decode(&enc).unwrap();
                assert_eq!(got, *nibs);
                assert_eq!(is_leaf, leaf);
            }
        }
    }

    #[test]
    fn crosses_rlp_index_0x80() {
        let items: Vec<Vec<u8>> = (0..200).map(|i| vec![i as u8, 0xaa]).collect();
        let root = ordered_trie_root(&items);
        assert_eq!(root.len(), 32);
        assert_ne!(root, EMPTY_TRIE_ROOT);
        let mut mutated = items.clone();
        mutated[0][0] ^= 1;
        assert_ne!(ordered_trie_root(&mutated), root);
        mutated[0] = items[0].clone();
        mutated[128][1] ^= 1;
        assert_ne!(ordered_trie_root(&mutated), root);
    }
}
