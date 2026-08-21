//! Bind untrusted raw txs to a sealed `transactionsRoot` (geth `DeriveSha`).
//!
//! Trie values are the raw item bytes (already RLP / EIP-2718), not pre-hashed
//! tx hashes. Empty list → [`crate::EMPTY_TRIE_ROOT`].

use crate::ordered_trie::{ordered_trie_root, MAX_ORDERED_TRIE_ITEMS};
use helios_bsc_types::keccak256;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TxListError {
    #[error("tx list exceeds 4096 items")]
    TooMany,
    #[error("transactionsRoot mismatch")]
    RootMismatch,
}

/// Keccak each raw item and require `ordered_trie_root(raws) == transactions_root`.
pub fn verify_tx_list(
    raws: &[Vec<u8>],
    transactions_root: &[u8; 32],
) -> Result<Vec<[u8; 32]>, TxListError> {
    if raws.len() > MAX_ORDERED_TRIE_ITEMS {
        return Err(TxListError::TooMany);
    }
    if &ordered_trie_root(raws) != transactions_root {
        return Err(TxListError::RootMismatch);
    }
    Ok(raws.iter().map(|r| keccak256(r)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpt::EMPTY_TRIE_ROOT;

    #[test]
    fn empty_matches_empty_trie_root() {
        assert_eq!(
            verify_tx_list(&[], &EMPTY_TRIE_ROOT).unwrap(),
            Vec::<[u8; 32]>::new()
        );
    }

    #[test]
    fn empty_rejects_nonzero_root() {
        assert_eq!(
            verify_tx_list(&[], &[0x11u8; 32]).unwrap_err(),
            TxListError::RootMismatch
        );
    }

    #[test]
    fn hashes_are_keccak_of_raws() {
        let raws = vec![b"doe".to_vec(), b"reindeer".to_vec()];
        let root = ordered_trie_root(&raws);
        let hashes = verify_tx_list(&raws, &root).unwrap();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], keccak256(b"doe"));
        assert_eq!(hashes[1], keccak256(b"reindeer"));
    }

    #[test]
    fn lying_list_rejected() {
        let raws = vec![b"aaa".to_vec(), b"bbb".to_vec()];
        let root = ordered_trie_root(&raws);
        let mut lying = raws.clone();
        lying[1][0] ^= 1;
        assert_eq!(
            verify_tx_list(&lying, &root).unwrap_err(),
            TxListError::RootMismatch
        );
        assert_eq!(
            verify_tx_list(&[], &root).unwrap_err(),
            TxListError::RootMismatch
        );
    }

    #[test]
    fn does_not_hash_trie_hashes() {
        let raws = vec![b"aaa".to_vec()];
        let root = ordered_trie_root(&raws);
        let as_hashes = vec![keccak256(&raws[0]).to_vec()];
        assert_ne!(ordered_trie_root(&as_hashes), root);
        assert_eq!(
            verify_tx_list(&as_hashes, &root).unwrap_err(),
            TxListError::RootMismatch
        );
    }

    #[test]
    fn too_many_rejected() {
        let raws = vec![vec![1u8]; MAX_ORDERED_TRIE_ITEMS + 1];
        assert_eq!(
            verify_tx_list(&raws, &EMPTY_TRIE_ROOT).unwrap_err(),
            TxListError::TooMany
        );
    }
}
