//! Ethereum account-trie Merkle proof verification (EIP-1186).

use crate::rlp::{decode, Rlp, RlpError};
use helios_bsc_types::keccak256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MptError {
    #[error(transparent)]
    Rlp(#[from] RlpError),
    #[error("proof node hash mismatch")]
    HashMismatch,
    #[error("proof path mismatch at node {index} (remaining {remaining} nibbles, compact path {path_len})")]
    PathMismatch {
        index: usize,
        remaining: usize,
        path_len: usize,
    },
    #[error("unexpected empty child")]
    EmptyChild,
    #[error("proof exhausted before leaf")]
    Exhausted,
    #[error("extra proof nodes")]
    ExtraNodes,
    #[error("invalid account leaf")]
    BadAccount,
    #[error("key leftover after leaf")]
    KeyLeftover,
    #[error("storage leaf is not rlp(uint256)")]
    BadStorageLeaf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: Vec<u8>,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

/// keccak256([]) — EOA / empty bytecode.
pub const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// keccak256(RLP empty string `0x80`) — empty storage trie.
pub const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// Walk an MPT proof. `hashed_key` is already keccak256(address) or keccak256(slot).
///
/// `Ok(None)` is a verified **exclusion** (account/slot absent). Hashes still chain
/// from `root`; a neighbor leaf or empty branch child is not a silent skip.
/// Children shorter than 32 bytes (or nested lists) are **inlined** — they are
/// part of the parent hash and are not a separate proof entry.
pub fn verify_trie_proof(
    root: &[u8; 32],
    hashed_key: &[u8; 32],
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, MptError> {
    verify_nibble_proof(root, bytes_to_nibbles(hashed_key), proof)
}

fn verify_nibble_proof(
    root: &[u8; 32],
    mut nibbles: Vec<u8>,
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, MptError> {
    if proof.is_empty() {
        return Err(MptError::Exhausted);
    }
    let mut rest = proof;
    consume_hashed(&mut rest, root, &mut nibbles)
}

fn consume_hashed(
    rest: &mut &[Vec<u8>],
    expected: &[u8],
    nibbles: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, MptError> {
    let Some(raw) = rest.first() else {
        return Err(MptError::Exhausted);
    };
    if node_ref(raw) != expected {
        return Err(MptError::HashMismatch);
    }
    *rest = &rest[1..];
    let decoded = decode(raw)?;
    walk_items(decoded.as_list()?, rest, nibbles)
}

fn walk_items(
    items: &[Rlp<'_>],
    rest: &mut &[Vec<u8>],
    nibbles: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, MptError> {
    match items.len() {
        17 => {
            if nibbles.is_empty() {
                return follow_child(&items[16], rest, nibbles, true);
            }
            let nibble = nibbles.remove(0) as usize;
            follow_child(&items[nibble], rest, nibbles, false)
        }
        2 => {
            let path_bytes = items[0].as_bytes()?;
            let (path, is_leaf) = hex_prefix_decode(path_bytes)?;
            if nibbles.len() < path.len() || nibbles[..path.len()] != path[..] {
                if rest.is_empty() {
                    return Ok(None);
                }
                return Err(MptError::PathMismatch {
                    index: 0,
                    remaining: nibbles.len(),
                    path_len: path.len(),
                });
            }
            nibbles.drain(..path.len());
            if is_leaf {
                if !nibbles.is_empty() {
                    return Err(MptError::KeyLeftover);
                }
                if !rest.is_empty() {
                    return Err(MptError::ExtraNodes);
                }
                Ok(Some(items[1].as_bytes()?.to_vec()))
            } else {
                follow_child(&items[1], rest, nibbles, false)
            }
        }
        _ => Err(MptError::Rlp(RlpError::Invalid)),
    }
}

/// `branch_value` is the 17th slot of a branch (the node *is* the value).
fn follow_child(
    item: &Rlp<'_>,
    rest: &mut &[Vec<u8>],
    nibbles: &mut Vec<u8>,
    branch_value: bool,
) -> Result<Option<Vec<u8>>, MptError> {
    match item {
        Rlp::Bytes([]) => {
            if rest.is_empty() {
                Ok(None)
            } else {
                Err(MptError::EmptyChild)
            }
        }
        Rlp::Bytes(b) if branch_value => {
            if !rest.is_empty() {
                return Err(MptError::ExtraNodes);
            }
            Ok(Some(b.to_vec()))
        }
        Rlp::Bytes(b) if b.len() >= 32 => consume_hashed(rest, b, nibbles),
        Rlp::Bytes(b) => {
            let decoded = decode(b)?;
            walk_items(decoded.as_list()?, rest, nibbles)
        }
        Rlp::List(v) => walk_items(v, rest, nibbles),
    }
}

fn empty_account() -> Account {
    Account {
        nonce: 0,
        balance: Vec::new(),
        storage_root: EMPTY_TRIE_ROOT,
        code_hash: EMPTY_CODE_HASH,
    }
}

pub fn verify_account_proof(
    state_root: &[u8; 32],
    address: &[u8; 20],
    proof: &[Vec<u8>],
) -> Result<Account, MptError> {
    let key = keccak256(address);
    match verify_trie_proof(state_root, &key, proof)? {
        None => Ok(empty_account()),
        Some(value) => decode_account(&value),
    }
}

pub fn verify_storage_proof(
    storage_root: &[u8; 32],
    slot: &[u8; 32],
    proof: &[Vec<u8>],
) -> Result<Vec<u8>, MptError> {
    if storage_root == &EMPTY_TRIE_ROOT {
        return Ok(Vec::new());
    }
    let key = keccak256(slot);
    match verify_trie_proof(storage_root, &key, proof)? {
        // Verified exclusion: the slot is unset, which is the zero word.
        None => Ok(Vec::new()),
        Some(raw) => decode_storage_leaf(&raw),
    }
}

/// Storage trie leaves hold `rlp(uint256)` — geth stores a `uint256.Int`, so the
/// decoded word is at most 32 bytes.
///
/// This used to fall back to `raw.to_vec()` on any decode failure, which is a silent
/// wrong answer rather than a refusal: the caller pads to 32 bytes with [`crate::pad32`],
/// which keeps the *low* 32 bytes, so an over-long or non-RLP leaf would be quietly
/// truncated into a plausible-looking storage value. The leaf is hash-bound to the
/// storage root so this is not reachable from a lying upstream today, but "cannot
/// happen" is a reason to error, not a reason to guess.
fn decode_storage_leaf(raw: &[u8]) -> Result<Vec<u8>, MptError> {
    match decode(raw) {
        Ok(Rlp::Bytes(b)) if b.len() <= 32 => Ok(b.to_vec()),
        _ => Err(MptError::BadStorageLeaf),
    }
}

pub fn verify_bytecode(code: &[u8], expected_hash: &[u8; 32]) -> Result<(), MptError> {
    if &keccak256(code) != expected_hash {
        return Err(MptError::HashMismatch);
    }
    Ok(())
}

fn node_ref(node: &[u8]) -> Vec<u8> {
    if node.len() < 32 {
        node.to_vec()
    } else {
        keccak256(node).to_vec()
    }
}

pub(crate) fn bytes_to_nibbles(b: &[u8]) -> Vec<u8> {
    let mut n = Vec::with_capacity(b.len() * 2);
    for x in b {
        n.push(x >> 4);
        n.push(x & 0x0f);
    }
    n
}

pub(crate) fn hex_prefix_decode(path: &[u8]) -> Result<(Vec<u8>, bool), MptError> {
    if path.is_empty() {
        return Err(MptError::PathMismatch {
            index: 0,
            remaining: 0,
            path_len: 0,
        });
    }
    let flag = path[0] >> 4;
    let odd = flag & 1 == 1;
    let is_leaf = flag & 2 == 2;
    let mut nibs = bytes_to_nibbles(path);
    if odd {
        nibs.remove(0);
    } else {
        if nibs.len() < 2 {
            return Err(MptError::PathMismatch {
                index: 0,
                remaining: 0,
                path_len: 0,
            });
        }
        nibs.drain(..2);
    }
    Ok((nibs, is_leaf))
}

fn decode_account(value: &[u8]) -> Result<Account, MptError> {
    let decoded = decode(value)?;
    let items = decoded.as_list().map_err(|_| MptError::BadAccount)?;
    if items.len() != 4 {
        return Err(MptError::BadAccount);
    }
    let nonce = rlp_uint(items[0].as_bytes().map_err(|_| MptError::BadAccount)?)?;
    let balance = items[1]
        .as_bytes()
        .map_err(|_| MptError::BadAccount)?
        .to_vec();
    // geth's `types.StateAccount.Balance` is a `uint256.Int`, so RLP decoding rejects
    // anything wider. Ours reached `pad32`, which keeps the low 32 bytes — a silent
    // truncation into a plausible balance rather than a refusal.
    if balance.len() > 32 {
        return Err(MptError::BadAccount);
    }
    let storage = items[2].as_bytes().map_err(|_| MptError::BadAccount)?;
    let code = items[3].as_bytes().map_err(|_| MptError::BadAccount)?;
    if storage.len() != 32 || code.len() != 32 {
        return Err(MptError::BadAccount);
    }
    let mut storage_root = [0u8; 32];
    let mut code_hash = [0u8; 32];
    storage_root.copy_from_slice(storage);
    code_hash.copy_from_slice(code);
    Ok(Account {
        nonce,
        balance,
        storage_root,
        code_hash,
    })
}

fn rlp_uint(b: &[u8]) -> Result<u64, MptError> {
    if b.len() > 8 {
        return Err(MptError::BadAccount);
    }
    let mut n = 0u64;
    for x in b {
        n = (n << 8) | u64::from(*x);
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rlp_bytes(b: &[u8]) -> Vec<u8> {
        if b.len() == 1 && b[0] < 0x80 {
            return b.to_vec();
        }
        assert!(b.len() <= 55);
        let mut o = vec![0x80 + b.len() as u8];
        o.extend_from_slice(b);
        o
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for i in items {
            payload.extend_from_slice(i);
        }
        assert!(payload.len() <= 55);
        let mut o = vec![0xc0 + payload.len() as u8];
        o.extend(payload);
        o
    }

    fn branch_with_child(nibble: usize, child: Vec<u8>) -> Vec<u8> {
        let mut kids = vec![rlp_bytes(&[]); 17];
        kids[0] = rlp_bytes(&[0x11u8; 32]);
        kids[nibble] = child;
        rlp_list(&kids)
    }

    /// The leaf is hash-bound, so these shapes are unreachable from a lying upstream —
    /// but the old fallback answered them with `raw.to_vec()`, which `pad32` then trims
    /// to its low 32 bytes. A wrong storage value is worse than a refusal.
    #[test]
    fn malformed_storage_leaf_refuses_rather_than_truncating() {
        assert_eq!(
            decode_storage_leaf(&rlp_bytes(&[0x07])).unwrap(),
            vec![0x07]
        );
        let word = [0xabu8; 32];
        assert_eq!(decode_storage_leaf(&rlp_bytes(&word)).unwrap(), word);

        // 33 bytes: wider than a uint256. Previously kept the low 32 and looked fine.
        let mut wide = vec![0xb8u8, 33];
        wide.extend_from_slice(&[0xcd; 33]);
        assert!(matches!(
            decode_storage_leaf(&wide),
            Err(MptError::BadStorageLeaf)
        ));

        // A list where a word belongs, and trailing bytes after a valid word.
        assert!(decode_storage_leaf(&rlp_list(&[rlp_bytes(&[1])])).is_err());
        let mut trailing = rlp_bytes(&word);
        trailing.push(0x00);
        assert!(decode_storage_leaf(&trailing).is_err());
    }

    /// An account list is always long-form (two 32-byte hashes alone exceed 55 bytes).
    fn rlp_list_long(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        assert!(payload.len() > 55 && payload.len() < 256);
        let mut o = vec![0xf8u8, payload.len() as u8];
        o.extend(payload);
        o
    }

    #[test]
    fn account_balance_wider_than_uint256_rejected() {
        let ok = rlp_list_long(&[
            rlp_bytes(&[0x01]),
            rlp_bytes(&[0x02]),
            rlp_bytes(&EMPTY_TRIE_ROOT),
            rlp_bytes(&EMPTY_CODE_HASH),
        ]);
        assert_eq!(decode_account(&ok).unwrap().balance, vec![0x02]);

        // Same account with a 33-byte balance, spelled canonically (`0x80+33`) so the
        // RLP layer has no objection and the width check is what has to catch it.
        // `pad32` would otherwise have kept its low 32 bytes and looked like a balance.
        let wide = rlp_list_long(&[
            rlp_bytes(&[0x01]),
            rlp_bytes(&[0xff; 33]),
            rlp_bytes(&EMPTY_TRIE_ROOT),
            rlp_bytes(&EMPTY_CODE_HASH),
        ]);
        assert!(matches!(decode_account(&wide), Err(MptError::BadAccount)));

        // The non-canonical long-form spelling of the same thing is refused one layer
        // earlier, by the RLP reader itself.
        let mut long_form = vec![0xb8u8, 33];
        long_form.extend_from_slice(&[0xff; 33]);
        let non_canon = rlp_list_long(&[
            rlp_bytes(&[0x01]),
            long_form,
            rlp_bytes(&EMPTY_TRIE_ROOT),
            rlp_bytes(&EMPTY_CODE_HASH),
        ]);
        assert!(matches!(
            decode_account(&non_canon),
            Err(MptError::Rlp(RlpError::NonCanonical))
        ));
    }

    #[test]
    fn inlined_leaf_as_nested_list() {
        // even-leaf, empty remaining path, value 0x07
        let leaf = rlp_list(&[rlp_bytes(&[0x20]), rlp_bytes(&[0x07])]);
        let branch = branch_with_child(0x0a, leaf);
        let root_v = node_ref(&branch);
        let mut root = [0u8; 32];
        root.copy_from_slice(&root_v);
        let got = verify_nibble_proof(&root, vec![0x0a], &[branch]).unwrap();
        assert_eq!(got, Some(vec![0x07]));
    }

    #[test]
    fn inlined_leaf_as_byte_string() {
        let leaf = rlp_list(&[rlp_bytes(&[0x20]), rlp_bytes(&[0x07])]);
        let branch = branch_with_child(0x0a, rlp_bytes(&leaf));
        let root_v = node_ref(&branch);
        let mut root = [0u8; 32];
        root.copy_from_slice(&root_v);
        let got = verify_nibble_proof(&root, vec![0x0a], &[branch]).unwrap();
        assert_eq!(got, Some(vec![0x07]));
    }
}
