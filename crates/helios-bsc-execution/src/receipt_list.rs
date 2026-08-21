//! Verify RLP-encoded receipts against a header `receiptsRoot`.
//!
//! Empty list → [`crate::mpt::EMPTY_TRIE_ROOT`]. Lists longer than
//! [`MAX_ORDERED_TRIE_ITEMS`] are rejected (fail-closed; `ordered_trie_root`
//! would ignore extras).

use crate::ordered_trie::{ordered_trie_root, MAX_ORDERED_TRIE_ITEMS};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReceiptListError {
    #[error("too many receipt list items")]
    TooManyItems,
    #[error("receiptsRoot mismatch")]
    RootMismatch,
}

/// Check that `ordered_trie_root(receipt_rlps)` equals `receipts_root`.
pub fn verify_receipt_list(
    receipt_rlps: &[Vec<u8>],
    receipts_root: &[u8; 32],
) -> Result<(), ReceiptListError> {
    if receipt_rlps.len() > MAX_ORDERED_TRIE_ITEMS {
        return Err(ReceiptListError::TooManyItems);
    }
    if &ordered_trie_root(receipt_rlps) != receipts_root {
        return Err(ReceiptListError::RootMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpt::EMPTY_TRIE_ROOT;

    #[test]
    fn empty_matches_empty_trie_root() {
        assert_eq!(verify_receipt_list(&[], &EMPTY_TRIE_ROOT), Ok(()));
    }

    #[test]
    fn empty_rejects_nonzero_root() {
        assert_eq!(
            verify_receipt_list(&[], &[0x11u8; 32]),
            Err(ReceiptListError::RootMismatch)
        );
    }

    #[test]
    fn mutated_item_rejected() {
        let items = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec()];
        let root = ordered_trie_root(&items);
        assert_eq!(verify_receipt_list(&items, &root), Ok(()));
        let mut mutated = items;
        mutated[1][0] ^= 1;
        assert_eq!(
            verify_receipt_list(&mutated, &root),
            Err(ReceiptListError::RootMismatch)
        );
    }
}
