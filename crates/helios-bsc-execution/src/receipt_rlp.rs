<<<<<<< HEAD
//! Consensus receipt RLP (geth `types.Receipt` London+ / yellow paper).
//!
//! Body is RLP([status, cumulativeGasUsed, logsBloom, logs]). Typed receipts
//! (tx type 1..=4) prefix `type_byte`; legacy type 0 is the body alone.
//! Pre-Byzantium `postState` receipts are not encoded.
=======
//! Consensus receipt RLP (geth `Receipts.EncodeIndex` / DeriveSha values).
//!
//! Legacy (type 0): `RLP([status, cumulativeGasUsed, logsBloom, logs])`.
//! Typed 0x01–0x04: `type || RLP([...])` (not an extra RLP string wrap).
>>>>>>> 37a7cbc (feat: receiptsRoot-bound receipts and single-block eth_getLogs)

use crate::rlp::{encode_bytes, encode_list, encode_uint};
use thiserror::Error;

<<<<<<< HEAD
/// DoS cap; not a protocol constant.
const MAX_LOGS: usize = 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReceiptRlpError {
    #[error("receipt status must be 0 or 1")]
    InvalidStatus,
    #[error("receipt tx type exceeds 4")]
    InvalidTxType,
    #[error("too many receipt logs")]
    TooManyLogs,
}

=======
/// Same cap as header-bound receipt `logs[]`.
pub const MAX_RECEIPT_LOGS: usize = 1024;
/// EIP-778 log topics.
pub const MAX_LOG_TOPICS: usize = 4;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReceiptRlpError {
    #[error("unknown receipt type 0x{0:02x}")]
    UnknownType(u8),
    #[error("receipt status is not 0x0 or 0x1")]
    InvalidStatus,
    #[error("too many receipt logs")]
    TooManyLogs,
    #[error("too many log topics")]
    TooManyTopics,
}

/// One consensus log (`address`, `topics`, `data`).
>>>>>>> 37a7cbc (feat: receiptsRoot-bound receipts and single-block eth_getLogs)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

<<<<<<< HEAD
=======
/// Fields hashed into `receiptsRoot` (status post-Byzantium).
>>>>>>> 37a7cbc (feat: receiptsRoot-bound receipts and single-block eth_getLogs)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusReceipt {
    pub status: u64,
    pub cumulative_gas_used: u64,
    pub logs_bloom: [u8; 256],
    pub logs: Vec<ConsensusLog>,
<<<<<<< HEAD
    pub tx_type: u8,
}

/// Encode a London+ consensus receipt for the receipts trie (`receiptsRoot`).
pub fn encode_consensus_receipt(r: &ConsensusReceipt) -> Result<Vec<u8>, ReceiptRlpError> {
    if r.status > 1 {
        return Err(ReceiptRlpError::InvalidStatus);
    }
    if r.tx_type > 4 {
        return Err(ReceiptRlpError::InvalidTxType);
    }
    if r.logs.len() > MAX_LOGS {
        return Err(ReceiptRlpError::TooManyLogs);
    }

    let logs: Vec<Vec<u8>> = r.logs.iter().map(encode_log).collect();
    let body = encode_list(&[
        encode_uint(r.status),
        encode_uint(r.cumulative_gas_used),
        encode_bytes(&r.logs_bloom),
        encode_list(&logs),
    ]);

    if r.tx_type == 0 {
        Ok(body)
    } else {
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(r.tx_type);
        out.extend_from_slice(&body);
        Ok(out)
    }
}

fn encode_log(log: &ConsensusLog) -> Vec<u8> {
    let topics: Vec<Vec<u8>> = log.topics.iter().map(|t| encode_bytes(t)).collect();
=======
    /// `0` = legacy (no prefix); `1..=4` = EIP-2718 type byte.
    pub tx_type: u8,
}

/// Encode one receipt as an ordered-trie value.
pub fn encode_consensus_receipt(r: &ConsensusReceipt) -> Result<Vec<u8>, ReceiptRlpError> {
    if r.tx_type > 4 {
        return Err(ReceiptRlpError::UnknownType(r.tx_type));
    }
    if r.status > 1 {
        return Err(ReceiptRlpError::InvalidStatus);
    }
    if r.logs.len() > MAX_RECEIPT_LOGS {
        return Err(ReceiptRlpError::TooManyLogs);
    }
    for log in &r.logs {
        if log.topics.len() > MAX_LOG_TOPICS {
            return Err(ReceiptRlpError::TooManyTopics);
        }
    }
    let encoded_logs: Vec<Vec<u8>> = r.logs.iter().map(encode_log).collect();
    let payload = encode_list(&[
        encode_uint(r.status),
        encode_uint(r.cumulative_gas_used),
        encode_bytes(&r.logs_bloom),
        encode_list(&encoded_logs),
    ]);
    if r.tx_type == 0 {
        return Ok(payload);
    }
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(r.tx_type);
    out.extend_from_slice(&payload);
    Ok(out)
}

fn encode_log(log: &ConsensusLog) -> Vec<u8> {
    let topics: Vec<Vec<u8>> = log
        .topics
        .iter()
        .map(|t| encode_bytes(t.as_slice()))
        .collect();
>>>>>>> 37a7cbc (feat: receiptsRoot-bound receipts and single-block eth_getLogs)
    encode_list(&[
        encode_bytes(&log.address),
        encode_list(&topics),
        encode_bytes(&log.data),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpt::EMPTY_TRIE_ROOT;
    use crate::ordered_trie::ordered_trie_root;
    use crate::receipt_list::verify_receipt_list;
<<<<<<< HEAD
    use crate::rlp::{decode, Rlp};

    fn sample(status: u64, gas: u64, tx_type: u8) -> ConsensusReceipt {
=======

    fn empty_typed(ty: u8, status: u64, gas: u64) -> ConsensusReceipt {
>>>>>>> 37a7cbc (feat: receiptsRoot-bound receipts and single-block eth_getLogs)
        ConsensusReceipt {
            status,
            cumulative_gas_used: gas,
            logs_bloom: [0u8; 256],
<<<<<<< HEAD
            logs: vec![],
            tx_type,
        }
    }

    fn body(encoded: &[u8], tx_type: u8) -> &[u8] {
        if tx_type == 0 {
            encoded
        } else {
            &encoded[1..]
=======
            logs: Vec::new(),
            tx_type: ty,
>>>>>>> 37a7cbc (feat: receiptsRoot-bound receipts and single-block eth_getLogs)
        }
    }

    #[test]
<<<<<<< HEAD
    fn empty_encoded_list_roots_empty_trie() {
        assert_eq!(verify_receipt_list(&[], &EMPTY_TRIE_ROOT), Ok(()));
    }

    #[test]
    fn two_receipts_differ() {
        let a = encode_consensus_receipt(&sample(1, 21_000, 0)).unwrap();
        let b = encode_consensus_receipt(&sample(0, 21_000, 2)).unwrap();
        assert_ne!(a, b);
        let list_a = [a];
        let list_b = [b];
        let ra = ordered_trie_root(&list_a);
        let rb = ordered_trie_root(&list_b);
        assert_ne!(ra, rb);
        assert_eq!(verify_receipt_list(&list_a, &ra), Ok(()));
        assert_eq!(
            verify_receipt_list(&list_b, &ra),
            Err(crate::receipt_list::ReceiptListError::RootMismatch)
        );
        assert_eq!(
            verify_receipt_list(&list_a, &rb),
            Err(crate::receipt_list::ReceiptListError::RootMismatch)
        );
    }

    #[test]
    fn legacy_is_rlp_list_of_four() {
        let enc = encode_consensus_receipt(&sample(1, 21_000, 0)).unwrap();
        let Rlp::List(items) = decode(&enc).unwrap() else {
            panic!("legacy receipt must be an RLP list");
        };
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].as_bytes().unwrap(), &[1]);
        assert_eq!(items[1].as_bytes().unwrap(), &21_000u64.to_be_bytes()[6..]);
        assert_eq!(items[2].as_bytes().unwrap().len(), 256);
        assert!(items[3].as_list().unwrap().is_empty());
    }

    #[test]
    fn typed_prefixes_type_byte() {
        for ty in 1u8..=4 {
            let enc = encode_consensus_receipt(&sample(1, 42, ty)).unwrap();
            assert_eq!(enc[0], ty);
            let Rlp::List(items) = decode(body(&enc, ty)).unwrap() else {
                panic!("typed body must be an RLP list");
            };
            assert_eq!(items.len(), 4);
            assert_eq!(items[0].as_bytes().unwrap(), &[1]);
=======
    fn typed_prefix_is_raw_type_byte() {
        let enc = encode_consensus_receipt(&empty_typed(2, 1, 21_000)).unwrap();
        assert_eq!(enc[0], 0x02);
        assert!(enc[1] >= 0xc0, "payload is an RLP list");
    }

    #[test]
    fn legacy_has_no_type_prefix() {
        let enc = encode_consensus_receipt(&empty_typed(0, 1, 0)).unwrap();
        assert!(enc[0] >= 0xc0, "legacy starts with RLP list: {enc:?}");
    }

    #[test]
    fn types_1_through_4_prefix() {
        for ty in 1u8..=4 {
            let enc = encode_consensus_receipt(&empty_typed(ty, 0, 1)).unwrap();
            assert_eq!(enc[0], ty);
>>>>>>> 37a7cbc (feat: receiptsRoot-bound receipts and single-block eth_getLogs)
        }
    }

    #[test]
<<<<<<< HEAD
    fn failed_status_is_empty_rlp_uint() {
        let enc = encode_consensus_receipt(&sample(0, 0, 0)).unwrap();
        let Rlp::List(items) = decode(&enc).unwrap() else {
            panic!("expected list");
        };
        assert_eq!(items[0].as_bytes().unwrap(), &[] as &[u8]);
        assert_eq!(items[1].as_bytes().unwrap(), &[] as &[u8]);
    }

    #[test]
    fn log_fields_roundtrip_structure() {
        let topic = [0x11u8; 32];
        let r = ConsensusReceipt {
            status: 1,
            cumulative_gas_used: 50_000,
            logs_bloom: [0xabu8; 256],
            logs: vec![ConsensusLog {
                address: [0x22; 20],
                topics: vec![topic],
                data: vec![0xde, 0xad],
            }],
            tx_type: 2,
        };
        let enc = encode_consensus_receipt(&r).unwrap();
        assert_eq!(enc[0], 2);
        let Rlp::List(items) = decode(&enc[1..]).unwrap() else {
            panic!("expected list");
        };
        assert_eq!(items[2].as_bytes().unwrap(), &[0xabu8; 256]);
        let logs = items[3].as_list().unwrap();
        assert_eq!(logs.len(), 1);
        let log = logs[0].as_list().unwrap();
        assert_eq!(log[0].as_bytes().unwrap(), &[0x22; 20]);
        let topics = log[1].as_list().unwrap();
        assert_eq!(topics.len(), 1);
        assert_eq!(topics[0].as_bytes().unwrap(), &topic);
        assert_eq!(log[2].as_bytes().unwrap(), &[0xde, 0xad]);
    }

    #[test]
    fn rejects_invalid_status_type_and_log_cap() {
        let mut r = sample(2, 1, 0);
        assert_eq!(
            encode_consensus_receipt(&r).unwrap_err(),
            ReceiptRlpError::InvalidStatus
        );
        r.status = 1;
        r.tx_type = 5;
        assert_eq!(
            encode_consensus_receipt(&r).unwrap_err(),
            ReceiptRlpError::InvalidTxType
        );
        r.tx_type = 0;
        r.logs = vec![
            ConsensusLog {
                address: [0; 20],
                topics: vec![],
                data: vec![],
            };
            MAX_LOGS + 1
=======
    fn unknown_type_rejected() {
        assert_eq!(
            encode_consensus_receipt(&empty_typed(5, 1, 0)).unwrap_err(),
            ReceiptRlpError::UnknownType(5)
        );
    }

    #[test]
    fn invalid_status_rejected() {
        assert_eq!(
            encode_consensus_receipt(&empty_typed(0, 2, 0)).unwrap_err(),
            ReceiptRlpError::InvalidStatus
        );
    }

    #[test]
    fn too_many_logs_rejected() {
        let mut r = empty_typed(0, 1, 0);
        r.logs = vec![
            ConsensusLog {
                address: [0u8; 20],
                topics: Vec::new(),
                data: Vec::new(),
            };
            MAX_RECEIPT_LOGS + 1
>>>>>>> 37a7cbc (feat: receiptsRoot-bound receipts and single-block eth_getLogs)
        ];
        assert_eq!(
            encode_consensus_receipt(&r).unwrap_err(),
            ReceiptRlpError::TooManyLogs
        );
    }
<<<<<<< HEAD
=======

    #[test]
    fn encoded_list_matches_receipts_root() {
        let a = encode_consensus_receipt(&empty_typed(2, 1, 21_000)).unwrap();
        let mut with_log = empty_typed(0, 1, 42_000);
        with_log.logs.push(ConsensusLog {
            address: [0x11u8; 20],
            topics: vec![[0x22u8; 32]],
            data: vec![0x33],
        });
        let b = encode_consensus_receipt(&with_log).unwrap();
        let items = vec![a, b];
        let root = ordered_trie_root(&items);
        assert_ne!(root, EMPTY_TRIE_ROOT);
        assert_eq!(verify_receipt_list(&items, &root), Ok(()));
        let mut lying = items.clone();
        lying[0][1] ^= 1;
        assert!(verify_receipt_list(&lying, &root).is_err());
    }

    #[test]
    fn failed_status_is_rlp_empty_uint() {
        let enc = encode_consensus_receipt(&empty_typed(0, 0, 0)).unwrap();
        // RLP list payload starts after the list prefix; first item is status 0 → 0x80.
        let prefix = enc[0];
        let skip = if prefix <= 0xf7 {
            1
        } else {
            1 + (prefix - 0xf7) as usize
        };
        assert_eq!(enc[skip], 0x80);
    }
>>>>>>> 37a7cbc (feat: receiptsRoot-bound receipts and single-block eth_getLogs)
}
