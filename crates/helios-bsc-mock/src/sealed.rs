//! Synthetic chains whose headers carry **real** Parlia seals.
//!
//! The synthetic helpers next door build headers with an all-zero `extraData`, which is
//! enough for the lookback path and useless for the snapshot one: `Snapshot::apply_header`
//! starts with `verify_seal_coinbase`, so an unsigned header never reaches the parent-link
//! check, the sealing-set check or `SignRecently`. That is why the whole checkpoint path —
//! the one `--checkpoint` uses, and the documented way to run this client — could only be
//! tested against the five captured mainnet headers, and why nothing could test what
//! happens to it during a **reorg**: forging an alternative branch of mainnet would mean
//! forging validator signatures.
//!
//! So sign a synthetic one instead. Twenty-one deterministic keys stand in for the
//! sealing set, every header is sealed over its real `seal_hash`, and the result passes
//! the same `verify_seal_coinbase` as a captured header because it is valid rather than
//! excused. Nothing here weakens a check: [`SealedChain::snapshot`] turns off only
//! `enforce_inturn`, which the live code path already turns off for padded sets and which
//! [`walk_from_checkpoint_inturn`](../../../bin/helios-bsc/src/sync.rs) exposes for the
//! same reason — a synthetic set cannot match the chain's real turn schedule.

use anyhow::{ensure, Result};
use helios_bsc_config::{params_at, EXTRA_SEAL, EXTRA_VANITY};
use helios_bsc_consensus::{
    header_hash, milli_timestamp, seal_hash, Snapshot, VerifiedBlock, EMPTY_UNCLE_HASH,
};
use helios_bsc_execution::EMPTY_TRIE_ROOT;
use helios_bsc_types::{
    decode_hex_fixed, decode_u64, format_address, keccak256, Checkpoint, RpcBlockHeader,
    BSC_MAINNET_CHAIN_ID,
};
use secp256k1::{Message, PublicKey, SecretKey, SECP256K1};

/// Validators in the synthetic sealing set. Mainnet's `N`, so `minerHistoryCheckLen` and
/// the Safe threshold behave the way they do in production.
const VALIDATORS: usize = 21;

/// Constant across the chain, so the `|delta| < parent/1024` bound is satisfied by zero.
const GAS_LIMIT: u64 = 140_000_000;

/// Where synthetic chains live: inside one epoch of the fixture era, far enough above the
/// boundary at 116_664_000 that a few hundred blocks cannot reach the next one. Epoch
/// blocks carry a validator set in `extraData` and would have to be built differently;
/// [`sealed_chain`] refuses to produce one rather than emitting something subtly wrong.
pub const SEALED_CHAIN_START: u64 = 116_664_100;

/// Deterministic stand-in validator keys.
fn keys() -> Vec<SecretKey> {
    (1..=VALIDATORS)
        .map(|i| {
            let mut b = [0u8; 32];
            b[31] = i as u8;
            b[0] = 0x11;
            SecretKey::from_byte_array(b).expect("valid test key")
        })
        .collect()
}

fn address_of(sk: &SecretKey) -> [u8; 20] {
    let pk = PublicKey::from_secret_key(SECP256K1, sk);
    let uncompressed = pk.serialize_uncompressed();
    let h = keccak256(&uncompressed[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[12..]);
    out
}

/// A synthetic chain with valid seals, and the checkpoint that roots it.
pub struct SealedChain {
    /// Trusted root. Its block is **not** in `headers`: a checkpoint is believed, not
    /// verified, exactly as on the live path.
    pub checkpoint: Checkpoint,
    /// Sealed headers, `checkpoint.number + 1 ..=` tip, ascending.
    pub headers: Vec<RpcBlockHeader>,
    /// Millisecond timestamp of the checkpoint block, so a fork can continue the clock.
    root_milli: u64,
}

impl SealedChain {
    pub fn tip(&self) -> u64 {
        self.headers
            .last()
            .and_then(|h| decode_u64(&h.number).ok())
            .unwrap_or(self.checkpoint.number)
    }

    /// The checkpoint block as a `VerifiedBlock`, for seeding a chain vector.
    pub fn root_block(&self) -> Result<VerifiedBlock> {
        Ok(VerifiedBlock {
            number: self.checkpoint.number,
            hash: decode_hex_fixed::<32>(&self.checkpoint.hash)?,
            state_root: decode_hex_fixed::<32>(&self.checkpoint.state_root)?,
            miner: [0u8; 20],
            milli_timestamp: self.root_milli,
            gas_limit: GAS_LIMIT,
            header: None,
        })
    }

    /// Snapshot at the checkpoint, ready to walk `headers`.
    ///
    /// `enforce_inturn` is off for the reason the live path turns it off for padded sets:
    /// a synthetic validator order cannot reproduce the chain's real turn schedule. Every
    /// other check — seal recovery, coinbase match, header hash, parent link, sealing-set
    /// membership, `SignRecently`, the Ramanujan floor, the gas-limit bound — is on.
    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut snap = Snapshot::from_checkpoint(&self.checkpoint)?;
        snap.enforce_inturn = false;
        Ok(snap)
    }

    /// A branch sharing every block up to and including `at`, and diverging after it.
    ///
    /// The divergence is real: blocks above `at` get a different `stateRoot`, so their
    /// hashes differ and a client following the original branch fails the parent-link
    /// check on the first header of this one — which is what a reorg looks like from here.
    pub fn forked_after(&self, at: u64, len: u64) -> Result<SealedChain> {
        ensure!(
            at >= self.checkpoint.number && at <= self.tip(),
            "fork point {at} is outside {}..={}",
            self.checkpoint.number,
            self.tip()
        );
        let mut prefix: Vec<RpcBlockHeader> = Vec::new();
        let mut root_hash = decode_hex_fixed::<32>(&self.checkpoint.hash)?;
        let mut root_milli = self.root_milli;
        for h in &self.headers {
            if decode_u64(&h.number)? > at {
                break;
            }
            root_hash = decode_hex_fixed::<32>(&h.hash)?;
            root_milli = milli_timestamp(h)?;
            prefix.push(h.clone());
        }
        let mut headers = prefix;
        headers.extend(build(at, root_hash, root_milli, len, 0x5a)?);
        Ok(SealedChain {
            checkpoint: self.checkpoint.clone(),
            headers,
            root_milli: self.root_milli,
        })
    }
}

/// A sealed chain of `len` headers above [`SEALED_CHAIN_START`].
pub fn sealed_chain(len: u64) -> Result<SealedChain> {
    let start = SEALED_CHAIN_START;
    // The clock runs backwards from a few seconds ago, so no header is in the future and
    // none is so old that a reader would mistake it for a fixture. 600 s of room covers a
    // chain and a longer fork on top of it.
    let base_milli = (helios_bsc_consensus::unix_now().saturating_sub(600)) * 1000;
    let root_hash = keccak256(b"helios-bsc sealed chain root");
    let sks = keys();
    let checkpoint = Checkpoint {
        chain_id: BSC_MAINNET_CHAIN_ID,
        number: start,
        hash: format!("0x{}", hex::encode(root_hash)),
        parent_hash: format!("0x{}", hex::encode([0u8; 32])),
        state_root: format!("0x{}", hex::encode([7u8; 32])),
        timestamp: base_milli / 1000,
        fork_id: "fermi".into(),
        sealing_set: sks.iter().map(|k| format_address(&address_of(k))).collect(),
        vote_keys: None,
        attestation: None,
    };
    let headers = build(start, root_hash, base_milli, len, 0)?;
    Ok(SealedChain {
        checkpoint,
        headers,
        root_milli: base_milli,
    })
}

/// Seal `len` headers above `(root_number, root_hash, root_milli)`.
fn build(
    root_number: u64,
    root_hash: [u8; 32],
    root_milli: u64,
    len: u64,
    salt: u8,
) -> Result<Vec<RpcBlockHeader>> {
    let sks = keys();
    let interval = params_at(root_number, root_milli / 1000).block_interval_ms;
    let epoch_length = params_at(root_number, root_milli / 1000).epoch_length;
    let mut out = Vec::with_capacity(len as usize);
    let mut parent = root_hash;
    let mut milli = root_milli;
    for i in 1..=len {
        let number = root_number + i;
        // An epoch block publishes a validator set in `extraData` and would need a
        // different layout. Refusing is the honest answer: a chain that silently walked
        // past one would be testing something other than what it claims to.
        ensure!(
            !number.is_multiple_of(epoch_length),
            "synthetic chain reached epoch block {number}; move SEALED_CHAIN_START or shorten it"
        );
        milli += interval;
        // Round-robin so `SignRecently` is satisfied the way it is on the real chain, and
        // so 15 distinct sealers accumulate and a Safe head exists.
        let sk = &sks[(i as usize) % VALIDATORS];
        let header = seal_one(number, parent, milli, sk, salt)?;
        parent = decode_hex_fixed::<32>(&header.hash)?;
        out.push(header);
    }
    Ok(out)
}

fn seal_one(
    number: u64,
    parent: [u8; 32],
    milli: u64,
    sk: &SecretKey,
    salt: u8,
) -> Result<RpcBlockHeader> {
    let mut mix = [0u8; 32];
    let ms = (milli % 1000) as u16;
    mix[30..32].copy_from_slice(&ms.to_be_bytes());
    // `stateRoot` is what a fork varies: it is inside the sealed hash, so two branches
    // built over the same parent get different hashes and a genuine parent-link break.
    let mut state_root = [0u8; 32];
    state_root[0] = salt;
    state_root[24..32].copy_from_slice(&number.to_be_bytes());
    let mut h = RpcBlockHeader {
        hash: format!("0x{}", hex::encode([0u8; 32])),
        parent_hash: format!("0x{}", hex::encode(parent)),
        sha3_uncles: format!("0x{}", hex::encode(EMPTY_UNCLE_HASH)),
        miner: format_address(&address_of(sk)),
        state_root: format!("0x{}", hex::encode(state_root)),
        transactions_root: format!("0x{}", hex::encode(EMPTY_TRIE_ROOT)),
        receipts_root: format!("0x{}", hex::encode(EMPTY_TRIE_ROOT)),
        logs_bloom: format!("0x{}", hex::encode([0u8; 256])),
        // In-turn. `enforce_inturn` is off, so this is only range-checked -- and an
        // in-turn header is the case where geth's `backOffTime` is zero, which keeps the
        // Ramanujan floor exactly `parent + BlockInterval`.
        difficulty: "0x2".into(),
        number: format!("0x{number:x}"),
        gas_limit: format!("0x{GAS_LIMIT:x}"),
        gas_used: "0x0".into(),
        timestamp: format!("0x{:x}", milli / 1000),
        extra_data: format!("0x{}", hex::encode(vec![0u8; EXTRA_VANITY + EXTRA_SEAL])),
        mix_hash: format!("0x{}", hex::encode(mix)),
        nonce: format!("0x{}", hex::encode([0u8; 8])),
        // Parlia's constant, and it is inside the sealed hash.
        base_fee_per_gas: Some("0x0".into()),
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        // Bohr+ requires the field, and requires it zero.
        parent_beacon_block_root: Some(format!("0x{}", hex::encode([0u8; 32]))),
        requests_hash: None,
    };

    // `seal_hash` covers the header with the last 65 `extraData` bytes removed, so the
    // signature can be written back into them without changing what was signed.
    let digest = seal_hash(&h, BSC_MAINNET_CHAIN_ID)?;
    let sig = SECP256K1.sign_ecdsa_recoverable(Message::from_digest(digest), sk);
    let (rec_id, compact) = sig.serialize_compact();
    let mut extra = vec![0u8; EXTRA_VANITY];
    extra.extend_from_slice(&compact);
    extra.push(i32::from(rec_id) as u8);
    h.extra_data = format!("0x{}", hex::encode(&extra));

    h.hash = format!("0x{}", hex::encode(header_hash(&h)?));
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_bsc_consensus::verify_seal_coinbase;

    #[test]
    fn every_sealed_header_verifies_like_a_captured_one() {
        let sc = sealed_chain(24).expect("sealed chain");
        assert_eq!(sc.headers.len(), 24);
        for h in &sc.headers {
            let signer =
                verify_seal_coinbase(h).unwrap_or_else(|e| panic!("block {} seal: {e}", h.number));
            assert_eq!(format_address(&signer), h.miner);
        }
    }

    #[test]
    fn the_walk_a_checkpoint_run_does_accepts_it() {
        let sc = sealed_chain(24).expect("sealed chain");
        let mut snap = sc.snapshot().expect("snapshot");
        for h in &sc.headers {
            snap.apply_header(h)
                .unwrap_or_else(|e| panic!("apply {}: {e}", h.number));
        }
        assert_eq!(snap.number, sc.tip());
    }

    /// The point of the fork helper: the branches share a prefix and then genuinely
    /// diverge, so a client on one fails the parent link on the other.
    #[test]
    fn a_fork_diverges_where_it_says_it_does() {
        let sc = sealed_chain(24).expect("sealed chain");
        let at = SEALED_CHAIN_START + 16;
        let fork = sc.forked_after(at, 12).expect("fork");
        let same: Vec<&RpcBlockHeader> = sc
            .headers
            .iter()
            .zip(&fork.headers)
            .take_while(|(a, b)| a.hash == b.hash)
            .map(|(a, _)| a)
            .collect();
        assert_eq!(
            decode_u64(&same.last().expect("shared prefix").number).unwrap(),
            at,
            "branches must share exactly up to the fork point"
        );
        assert_eq!(fork.tip(), at + 12);
        // And the divergent block is itself valid: a reorg is two honest branches, not
        // one honest and one malformed.
        let first_new = &fork.headers[same.len()];
        verify_seal_coinbase(first_new).expect("forked header is sealed too");
    }
}
