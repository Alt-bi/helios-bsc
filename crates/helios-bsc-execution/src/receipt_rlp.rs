//! Consensus receipt RLP (geth `types.Receipt` London+ / yellow paper).
//!
//! Body is RLP([status, cumulativeGasUsed, logsBloom, logs]). Typed receipts
//! (tx type 1..=4) prefix `type_byte`; legacy type 0 is the body alone.
//! Pre-Byzantium `postState` receipts are not encoded.

use crate::rlp::{encode_bytes, encode_list, encode_uint};
use thiserror::Error;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusReceipt {
    pub status: u64,
    pub cumulative_gas_used: u64,
    pub logs_bloom: [u8; 256],
    pub logs: Vec<ConsensusLog>,
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
    use crate::rlp::{decode, Rlp};

    fn sample(status: u64, gas: u64, tx_type: u8) -> ConsensusReceipt {
        ConsensusReceipt {
            status,
            cumulative_gas_used: gas,
            logs_bloom: [0u8; 256],
            logs: vec![],
            tx_type,
        }
    }

    fn body(encoded: &[u8], tx_type: u8) -> &[u8] {
        if tx_type == 0 {
            encoded
        } else {
            &encoded[1..]
        }
    }

    #[test]
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
        }
    }

    #[test]
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
        ];
        assert_eq!(
            encode_consensus_receipt(&r).unwrap_err(),
            ReceiptRlpError::TooManyLogs
        );
    }
}
