//! In-process adversarial JSON-RPC upstream (no network).
//!
//! Serves captured fixtures or mutated/synthetic responses so consensus and
//! execution verification stay fail-closed on lying headers and proofs.

use std::path::PathBuf;

use anyhow::{Context, Result};
use helios_bsc_config::{mainnet_n_seal, params_at, parse_extra, ExtraDataVersion, EXTRA_SEAL};
use helios_bsc_consensus::{
    decode_vote_attestation, header_hash, sealing_set_from_activated_epoch,
    vote_keys_from_activated_epoch, VerifiedBlock, VoteAttestation, BLS_SIGNATURE_LEN,
};
use helios_bsc_execution::{EthAccountProof, EMPTY_TRIE_ROOT};
use helios_bsc_types::{
    decode_hex, decode_hex_fixed, decode_u64, format_address, Checkpoint, RpcBlockHeader,
    BSC_MAINNET_CHAIN_ID,
};
use serde::Deserialize;
use serde_json::{json, Value};

const HEADER_FILES: [&str; 5] = [
    "header_116663998.json",
    "header_116663999.json",
    "header_116664000.json",
    "header_116664001.json",
    "header_116664002.json",
];

/// Epoch header carrying the BLS vote keys that govern every fixture block (it activates
/// at +87 = 116663087). Without these keys `check_attestation` returns early and every
/// forged attestation below would be silently ignored rather than rejected.
const VOTE_KEY_EPOCH_FILE: &str = "header_116663000.json";

/// Voters left after [`Scenario::DowngradedQuorum`] — one short of the `ceil(2*21/3)` = 14
/// super-majority.
pub const DOWNGRADED_VOTES: u32 = 13;

/// First fixture index whose attestation [`Scenario::StrippedAttestation`] removes.
/// Everything below it keeps a real attestation, so finality is established first and
/// then has somewhere to stall.
const STRIP_ATTESTATION_FROM: usize = 3;

/// WBNB (from `fixtures/mainnet/proof_wbnb_tip.json`).
pub const WBNB_ADDRESS: &str = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c";

/// Address used by [`Scenario::WrongAddress`].
pub const WRONG_ADDRESS: [u8; 20] = [0x11; 20];

/// stateRoot used by [`Scenario::WrongStateRoot`].
pub const WRONG_STATE_ROOT: [u8; 32] = [0x11; 32];

const ERR_METHOD: i64 = -32601;
const ERR_PARAMS: i64 = -32602;
const ERR_INVALID: i64 = -32600;

/// Adversarial (or honest) upstream behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// Five captured headers + WBNB `eth_getProof`.
    HonestFixtures,
    /// XOR the last `extraData` byte (invalid seal).
    MutatedSeal,
    /// Flip `miner`, keep the original seal bytes.
    CoinbaseMismatch,
    /// Header N+1 `parentHash` does not match hash of N.
    BrokenParent,
    /// Claimed `balance` = `0x1`; `accountProof` unchanged.
    LyingBalance,
    /// Proof is honest; verification should use [`WRONG_STATE_ROOT`].
    WrongStateRoot,
    /// WBNB account proof presented for [`WRONG_ADDRESS`].
    WrongAddress,
    /// Fixture headers only — too few distinct miners for Safe.
    TruncatedHistory,
    /// Synthetic chain with only 14 distinct miners.
    FourteenSealers,
    /// Each header carries the *next* header's aggregate BLS signature: a genuine,
    /// well-formed signature over somebody else's `VoteData`.
    ForgedAttestationSignature,
    /// Attestation `TargetHash` no longer names the direct parent.
    ForgedAttestationTarget,
    /// Attestation removed from [`STRIP_ATTESTATION_FROM`] onwards. Legal per BEP-126 —
    /// the headers must still be accepted, and finality must simply stop advancing.
    StrippedAttestation,
    /// `VoteAddressSet` thinned to [`DOWNGRADED_VOTES`] voters, below the super-majority.
    DowngradedQuorum,
}

/// In-memory JSON-RPC dispatcher.
#[derive(Debug, Clone)]
pub struct MockRpc {
    scenario: Scenario,
    headers: Vec<RpcBlockHeader>,
    proof: Value,
    proof_state_root: [u8; 32],
    proof_address: [u8; 20],
}

impl MockRpc {
    pub fn new(scenario: Scenario) -> Self {
        Self::try_new(scenario).expect("load mainnet fixtures")
    }

    pub fn try_new(scenario: Scenario) -> Result<Self> {
        let (mut headers, mut proof, proof_state_root, proof_address) = load_fixtures()?;
        match scenario {
            Scenario::HonestFixtures | Scenario::WrongStateRoot | Scenario::TruncatedHistory => {}
            Scenario::MutatedSeal => {
                for h in &mut headers {
                    mutate_seal(h)?;
                }
            }
            Scenario::CoinbaseMismatch => {
                for h in &mut headers {
                    flip_miner(h)?;
                }
            }
            Scenario::BrokenParent => {
                if headers.len() >= 2 {
                    headers[1].parent_hash = format!("0x{}", hex::encode([0x11u8; 32]));
                }
            }
            Scenario::LyingBalance => {
                proof["balance"] = json!("0x1");
            }
            Scenario::WrongAddress => {
                proof["address"] = json!(format_address(&WRONG_ADDRESS));
            }
            Scenario::FourteenSealers => {
                headers = synthetic_headers(20, 14);
            }
            Scenario::ForgedAttestationSignature => replay_foreign_signatures(&mut headers)?,
            Scenario::ForgedAttestationTarget => {
                for h in &mut headers {
                    splice_attestation(h, |att| forge_target_hash(att))?;
                }
            }
            Scenario::StrippedAttestation => {
                for h in headers.iter_mut().skip(STRIP_ATTESTATION_FROM) {
                    splice_attestation(h, |att| {
                        att.clear();
                        Ok(())
                    })?;
                }
            }
            Scenario::DowngradedQuorum => {
                for h in &mut headers {
                    splice_attestation(h, |att| downgrade_quorum(att))?;
                }
            }
        }
        Ok(Self {
            scenario,
            headers,
            proof,
            proof_state_root,
            proof_address,
        })
    }

    pub fn scenario(&self) -> Scenario {
        self.scenario
    }

    pub fn headers(&self) -> &[RpcBlockHeader] {
        &self.headers
    }

    /// Fixture stateRoot the WBNB proof was captured against.
    pub fn fixture_state_root(&self) -> [u8; 32] {
        self.proof_state_root
    }

    /// WBNB address from the captured proof (not the lying claim).
    pub fn wbnb_address(&self) -> [u8; 20] {
        self.proof_address
    }

    /// Root the client should verify against for this scenario.
    pub fn verification_state_root(&self) -> [u8; 32] {
        match self.scenario {
            Scenario::WrongStateRoot => WRONG_STATE_ROOT,
            _ => self.proof_state_root,
        }
    }

    pub fn account_proof(&self) -> Result<EthAccountProof> {
        serde_json::from_value(self.proof.clone()).context("eth_getProof JSON")
    }

    pub fn proof_json(&self) -> Value {
        self.proof.clone()
    }

    pub fn verified_chain(&self) -> Result<Vec<VerifiedBlock>> {
        self.headers.iter().map(header_to_verified).collect()
    }

    /// Checkpoint at `headers[0]` with a 21-member sealing set covering miners.
    pub fn checkpoint(&self) -> Result<Checkpoint> {
        let h = self.headers.first().context("no headers")?;
        Ok(Checkpoint {
            chain_id: BSC_MAINNET_CHAIN_ID,
            number: decode_u64(&h.number)?,
            hash: h.hash.clone(),
            parent_hash: h.parent_hash.clone(),
            state_root: h.state_root.clone(),
            timestamp: decode_u64(&h.timestamp)?,
            fork_id: "fermi".into(),
            sealing_set: sealing_set_for(&self.headers),
            vote_keys: None,
            attestation: Some("mock".into()),
        })
    }

    /// Checkpoint at `headers[0]` carrying the **real** epoch sealing set and its BLS vote
    /// keys, so fast finality is actually armed.
    ///
    /// [`MockRpc::checkpoint`] pads a synthetic set to 21 addresses, which is enough for
    /// the confirmation-depth scenarios but has no vote keys — and a snapshot without vote
    /// keys skips every attestation, turning a forged-finality test into a no-op that
    /// passes for the wrong reason.
    pub fn finality_checkpoint(&self) -> Result<Checkpoint> {
        let h = self.headers.first().context("no headers")?;
        let number = decode_u64(&h.number)?;
        let epoch = load_header(VOTE_KEY_EPOCH_FILE)?;
        let sealing_set = sealing_set_from_activated_epoch(&epoch, number)?;
        let vote_keys = vote_keys_from_activated_epoch(&epoch, number)?;
        Ok(Checkpoint {
            chain_id: BSC_MAINNET_CHAIN_ID,
            number,
            hash: h.hash.clone(),
            parent_hash: h.parent_hash.clone(),
            state_root: h.state_root.clone(),
            timestamp: decode_u64(&h.timestamp)?,
            fork_id: "fermi".into(),
            sealing_set,
            vote_keys: None,
            attestation: Some("mock".into()),
        }
        .with_vote_keys(vote_keys))
    }

    /// Raw attestation RLP this scenario serves for `headers[index]` — empty when the
    /// scenario stripped it.
    pub fn attestation_rlp(&self, index: usize) -> Result<Vec<u8>> {
        let h = self.headers.get(index).context("header index")?;
        let (extra, span) = attestation_region(h)?;
        Ok(extra[span].to_vec())
    }

    pub fn tip_number(&self) -> Result<u64> {
        let h = self.headers.last().context("no headers")?;
        Ok(decode_u64(&h.number)?)
    }

    /// JSON-RPC 2.0 envelope. No network.
    pub fn handle(&self, req: Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let Some(method) = req.get("method").and_then(Value::as_str) else {
            return rpc_err(id, ERR_INVALID, "invalid request");
        };
        let params = match req.get("params") {
            Some(Value::Array(a)) => a.as_slice(),
            None => &[],
            Some(_) => return rpc_err(id, ERR_PARAMS, "params must be an array"),
        };
        match method {
            "eth_blockNumber" => match self.tip_number() {
                Ok(n) => rpc_ok(id, json!(qty(n))),
                Err(e) => rpc_err(id, ERR_PARAMS, &e.to_string()),
            },
            "eth_getBlockByNumber" => {
                let tag = params.first().and_then(Value::as_str);
                match self.block_by_number(tag) {
                    Ok(v) => rpc_ok(id, v),
                    Err(e) => rpc_err(id, ERR_PARAMS, &e.to_string()),
                }
            }
            "eth_getBlockByHash" => {
                let hash = params.first().and_then(Value::as_str);
                match self.block_by_hash(hash) {
                    Ok(v) => rpc_ok(id, v),
                    Err(e) => rpc_err(id, ERR_PARAMS, &e.to_string()),
                }
            }
            "eth_getProof" => rpc_ok(id, self.proof.clone()),
            "eth_getCode" => rpc_ok(id, json!("0x")),
            _ => rpc_err(id, ERR_METHOD, "method not found"),
        }
    }

    fn block_by_number(&self, tag: Option<&str>) -> Result<Value> {
        let h = match tag {
            None | Some("latest") | Some("safe") | Some("finalized") => {
                self.headers.last().context("no headers")?
            }
            Some(t) => {
                let n = decode_u64(t)?;
                match self
                    .headers
                    .iter()
                    .find(|h| decode_u64(&h.number).ok() == Some(n))
                {
                    Some(h) => h,
                    None => return Ok(Value::Null),
                }
            }
        };
        Ok(serde_json::to_value(h)?)
    }

    fn block_by_hash(&self, hash: Option<&str>) -> Result<Value> {
        let want = hash.context("missing block hash")?;
        match self
            .headers
            .iter()
            .find(|h| h.hash.eq_ignore_ascii_case(want))
        {
            Some(h) => Ok(serde_json::to_value(h)?),
            None => Ok(Value::Null),
        }
    }
}

/// Parent + `distinct` subsequent unique miners (`newest_safe` needs 15 subsequent).
pub fn distinct_sealer_chain(distinct: u32) -> Vec<VerifiedBlock> {
    let mut chain = Vec::with_capacity(distinct as usize + 1);
    chain.push(synthetic_verified(0, 0));
    for i in 1..=distinct {
        chain.push(synthetic_verified(i as u64, i as u8));
    }
    relink_dummy_chain(&mut chain);
    chain
}

/// Cycling `n_miners` distinct coinbases (never reaches 15 for `n_miners` < 15).
pub fn cycling_sealer_chain(len: u64, n_miners: u32) -> Vec<VerifiedBlock> {
    let mut chain: Vec<VerifiedBlock> = (0..len)
        .map(|i| {
            let miner = (i % u64::from(n_miners.max(1))) as u8 + 1;
            synthetic_verified(i, miner)
        })
        .collect();
    relink_dummy_chain(&mut chain);
    chain
}

/// Recompute `VerifiedBlock.hash` = geth `Header.Hash()` of the dummy header recipe.
/// Call after mutating `state_root` so getBlock re-fetch still binds.
pub fn relink_dummy_chain(chain: &mut [VerifiedBlock]) {
    let mut parent = [0u8; 32];
    for b in chain.iter_mut() {
        let mut h = dummy_header(b.number, parent, b.miner);
        h.state_root = format!("0x{}", hex::encode(b.state_root));
        let hash = header_hash(&h).expect("dummy header rlp");
        b.hash = hash;
        parent = hash;
    }
}

pub fn n_seal() -> u32 {
    mainnet_n_seal()
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/mainnet")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofFixtureFile {
    address: String,
    state_root: String,
    proof: Value,
}

type LoadedFixtures = (Vec<RpcBlockHeader>, Value, [u8; 32], [u8; 20]);

fn load_header(name: &str) -> Result<RpcBlockHeader> {
    let path = fixtures_dir().join(name);
    let raw = std::fs::read_to_string(&path).with_context(|| format!("{path:?}"))?;
    serde_json::from_str(&raw).with_context(|| format!("{name} json"))
}

fn load_fixtures() -> Result<LoadedFixtures> {
    let dir = fixtures_dir();
    let mut headers = Vec::with_capacity(HEADER_FILES.len());
    for name in HEADER_FILES {
        headers.push(load_header(name)?);
    }
    let proof_path = dir.join("proof_wbnb_tip.json");
    let raw = std::fs::read_to_string(&proof_path).with_context(|| format!("{proof_path:?}"))?;
    let f: ProofFixtureFile = serde_json::from_str(&raw).context("proof fixture json")?;
    let state_root = decode_hex_fixed::<32>(&f.state_root)?;
    let address = decode_hex_fixed::<20>(&f.address)?;
    Ok((headers, f.proof, state_root, address))
}

fn mutate_seal(h: &mut RpcBlockHeader) -> Result<()> {
    let mut extra = decode_hex(&h.extra_data)?;
    anyhow::ensure!(!extra.is_empty(), "empty extraData");
    let last = extra.len() - 1;
    extra[last] ^= 0x01;
    h.extra_data = format!("0x{}", hex::encode(extra));
    Ok(())
}

// ---------------------------------------------------------------------------
// Forged fast-finality attestations (BEP-126).
//
// Every edit below is spliced back into `extraData` in place and the header `hash` is
// left as the fixture's. That is deliberate on both counts:
//
// * An upstream that rewrites a sealed header cannot repair the ECDSA seal, so a forged
//   attestation always arrives inside a header whose seal is already broken. The tests
//   drive `Snapshot::apply_verified` with the fixture's own `miner` for exactly that
//   reason — a seal failure would mask the attestation check under test.
// * Keeping the fixture hashes keeps the parent links, and therefore the honest
//   `TargetHash` values, intact. Recomputing them would move the goalposts and the
//   rejection could no longer be attributed to the forgery.
//
// The edits are also length-preserving wherever the client's own checks care, so each
// scenario fails at one named check rather than at RLP framing.
// ---------------------------------------------------------------------------

/// `extraData` plus the byte range holding the attestation RLP.
///
/// The attestation sits immediately before the 65-byte seal, so its start is fixed by its
/// own decoded length — no need to re-derive the epoch validator records.
fn attestation_region(h: &RpcBlockHeader) -> Result<(Vec<u8>, std::ops::Range<usize>)> {
    let extra = decode_hex(&h.extra_data)?;
    let number = decode_u64(&h.number)?;
    let timestamp = decode_u64(&h.timestamp)?;
    let is_epoch = number % params_at(number, timestamp).epoch_length == 0;
    let parsed = parse_extra(&extra, ExtraDataVersion::Bohr, is_epoch)?;
    let end = extra
        .len()
        .checked_sub(EXTRA_SEAL)
        .context("extraData shorter than the seal")?;
    let start = end
        .checked_sub(parsed.attestation.len())
        .context("attestation overruns extraData")?;
    Ok((extra, start..end))
}

fn attestation_of(h: &RpcBlockHeader) -> Result<VoteAttestation> {
    let (extra, span) = attestation_region(h)?;
    decode_attestation(&extra[span])
}

fn decode_attestation(raw: &[u8]) -> Result<VoteAttestation> {
    decode_vote_attestation(raw)?.context("fixture header carries no vote attestation")
}

/// Rewrite the attestation bytes of `h` in place, leaving vanity, validator records and
/// seal byte-for-byte alone.
fn splice_attestation(
    h: &mut RpcBlockHeader,
    edit: impl FnOnce(&mut Vec<u8>) -> Result<()>,
) -> Result<()> {
    let (extra, span) = attestation_region(h)?;
    let mut att = extra[span.clone()].to_vec();
    edit(&mut att)?;
    let mut out = Vec::with_capacity(extra.len());
    out.extend_from_slice(&extra[..span.start]);
    out.extend_from_slice(&att);
    out.extend_from_slice(&extra[span.end..]);
    h.extra_data = format!("0x{}", hex::encode(out));
    Ok(())
}

/// Offset of the **only** occurrence of `needle`.
///
/// A second match would make the edit ambiguous, and which byte got corrupted decides
/// which error the client reports — a scenario that cannot say where it wrote proves
/// nothing about why the header was rejected.
fn unique_span(haystack: &[u8], needle: &[u8]) -> Result<usize> {
    anyhow::ensure!(!needle.is_empty(), "empty needle");
    let mut found = None;
    for (i, w) in haystack.windows(needle.len()).enumerate() {
        if w == needle {
            anyhow::ensure!(found.is_none(), "needle occurs more than once");
            found = Some(i);
        }
    }
    found.context("needle not present in the attestation RLP")
}

/// Canonical RLP for a `u64` — big-endian, no leading zeros, single small bytes bare,
/// zero as the empty string. Must agree byte-for-byte with the encoder that produced the
/// fixture, or the replacement would not be found where the original was.
fn rlp_uint(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x80];
    }
    let be = v.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let body = &be[start..];
    if body.len() == 1 && body[0] < 0x80 {
        return body.to_vec();
    }
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(0x80 + body.len() as u8);
    out.extend_from_slice(body);
    out
}

/// Give every header the *next* header's aggregate signature.
///
/// Corrupting the signature bytes instead would usually fail at G2 deserialization, which
/// only proves blst rejects garbage. A real signature over a different `VoteData` is what
/// an upstream replaying yesterday's finality would actually send, and it can fail at one
/// place only: `FastAggregateVerify`.
fn replay_foreign_signatures(headers: &mut [RpcBlockHeader]) -> Result<()> {
    let sigs = headers
        .iter()
        .map(|h| attestation_of(h).map(|a| a.agg_signature))
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(sigs.len() > 1, "need two headers to swap signatures");
    for (i, h) in headers.iter_mut().enumerate() {
        let replacement = sigs[(i + 1) % sigs.len()];
        splice_attestation(h, move |att| {
            let mine = decode_attestation(att)?.agg_signature;
            anyhow::ensure!(mine != replacement, "signature swap is a no-op");
            let at = unique_span(att, &mine)?;
            att[at..at + BLS_SIGNATURE_LEN].copy_from_slice(&replacement);
            Ok(())
        })?;
    }
    Ok(())
}

/// Flip one bit of `TargetHash` so it stops naming the direct parent.
fn forge_target_hash(att: &mut [u8]) -> Result<()> {
    let target = decode_attestation(att)?.data.target_hash;
    let at = unique_span(att, &target)?;
    att[at] ^= 0x01;
    Ok(())
}

/// Clear the lowest set bits of `VoteAddressSet` down to [`DOWNGRADED_VOTES`] voters.
///
/// Clearing from the bottom keeps the highest bit, so the RLP integer keeps its byte width
/// and stays canonical — the splice is length-preserving and the client reaches the quorum
/// check instead of tripping on framing.
fn downgrade_quorum(att: &mut [u8]) -> Result<()> {
    let old = decode_attestation(att)?.vote_address_set;
    anyhow::ensure!(
        old.count_ones() > DOWNGRADED_VOTES,
        "fixture already votes below the downgrade target"
    );
    let mut set = old;
    while set.count_ones() > DOWNGRADED_VOTES {
        set &= set - 1;
    }
    let (old_rlp, new_rlp) = (rlp_uint(old), rlp_uint(set));
    anyhow::ensure!(
        old_rlp.len() == new_rlp.len(),
        "downgrade changed the bit set's RLP width"
    );
    let at = unique_span(att, &old_rlp)?;
    att[at..at + new_rlp.len()].copy_from_slice(&new_rlp);
    Ok(())
}

fn flip_miner(h: &mut RpcBlockHeader) -> Result<()> {
    let mut miner = decode_hex_fixed::<20>(&h.miner)?;
    miner[0] ^= 0x01;
    h.miner = format_address(&miner);
    Ok(())
}

fn header_to_verified(h: &RpcBlockHeader) -> Result<VerifiedBlock> {
    Ok(VerifiedBlock {
        number: decode_u64(&h.number)?,
        hash: decode_hex_fixed::<32>(&h.hash)?,
        state_root: decode_hex_fixed::<32>(&h.state_root)?,
        miner: decode_hex_fixed::<20>(&h.miner)?,
        header: Some(h.clone()),
        ..Default::default()
    })
}

fn sealing_set_for(headers: &[RpcBlockHeader]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut set = Vec::new();
    for h in headers {
        if let Ok(addr) = decode_hex_fixed::<20>(&h.miner) {
            if seen.insert(addr) {
                set.push(format_address(&addr));
            }
        }
    }
    let mut i = 1u32;
    while set.len() < 21 {
        let addr = sealer(i as u8);
        if seen.insert(addr) {
            set.push(format_address(&addr));
        }
        i = i.wrapping_add(1);
        if i == 0 {
            break;
        }
    }
    set
}

fn sealer(i: u8) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[19] = i;
    a
}

fn placeholder_root(n: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = 0xab;
    h[24..].copy_from_slice(&n.to_be_bytes());
    h
}

fn synthetic_verified(number: u64, miner: u8) -> VerifiedBlock {
    let root = placeholder_root(number);
    VerifiedBlock {
        number,
        hash: root,
        state_root: root,
        miner: sealer(miner),
        ..Default::default()
    }
}

/// Header whose hash / number / stateRoot / miner match `block` (no valid seal).
pub fn header_from_verified(block: &VerifiedBlock, parent: [u8; 32]) -> RpcBlockHeader {
    let mut h = dummy_header(block.number, parent, block.miner);
    h.state_root = format!("0x{}", hex::encode(block.state_root));
    finalize_dummy_hash(&mut h);
    h
}

pub fn headers_from_chain(chain: &[VerifiedBlock]) -> Vec<RpcBlockHeader> {
    let mut parent = [0u8; 32];
    let mut out = Vec::with_capacity(chain.len());
    for b in chain {
        out.push(header_from_verified(b, parent));
        parent = b.hash;
    }
    out
}

fn dummy_header(number: u64, parent: [u8; 32], miner: [u8; 20]) -> RpcBlockHeader {
    RpcBlockHeader {
        hash: format!("0x{}", hex::encode([0u8; 32])),
        parent_hash: format!("0x{}", hex::encode(parent)),
        sha3_uncles: format!("0x{}", hex::encode([0u8; 32])),
        miner: format_address(&miner),
        state_root: format!("0x{}", hex::encode([0u8; 32])),
        transactions_root: format!("0x{}", hex::encode(EMPTY_TRIE_ROOT)),
        receipts_root: format!("0x{}", hex::encode(EMPTY_TRIE_ROOT)),
        logs_bloom: format!("0x{}", hex::encode([0u8; 256])),
        difficulty: "0x2".into(),
        number: qty(number),
        gas_limit: "0x1".into(),
        gas_used: "0x0".into(),
        timestamp: "0x696b9e29".into(),
        extra_data: format!("0x{}", hex::encode([0u8; 32 + 65])),
        mix_hash: format!("0x{}", hex::encode([0u8; 32])),
        nonce: format!("0x{}", hex::encode([0u8; 8])),
        base_fee_per_gas: None,
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
    }
}

fn finalize_dummy_hash(h: &mut RpcBlockHeader) {
    let hash = header_hash(h).expect("dummy header rlp");
    h.hash = format!("0x{}", hex::encode(hash));
}

fn synthetic_headers(len: usize, n_miners: u32) -> Vec<RpcBlockHeader> {
    let mut parent = [0x11u8; 32];
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let number = i as u64 + 1;
        let miner_i = (i as u32 % n_miners.max(1)) as u8 + 1;
        let mut h = dummy_header(number, parent, sealer(miner_i));
        finalize_dummy_hash(&mut h);
        parent = decode_hex_fixed::<32>(&h.hash).expect("dummy hash");
        out.push(h);
    }
    out
}

fn qty(n: u64) -> String {
    format!("0x{n:x}")
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn rpc_err(id: Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":msg}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_bsc_config::PROVIDER_PROOF_LOOKBACK;
    use helios_bsc_consensus::{
        min_votes_for_finality, newest_safe, verify_seal_coinbase, Snapshot, SnapshotError,
        VoteError,
    };
    use helios_bsc_execution::verify_eth_get_proof;
    use helios_bsc_types::min_distinct_sealers;

    fn req(method: &str, params: Value) -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
    }

    fn proof_from(mock: &MockRpc) -> EthAccountProof {
        let resp = mock.handle(req(
            "eth_getProof",
            json!([WBNB_ADDRESS, json!([]), "latest"]),
        ));
        serde_json::from_value(resp["result"].clone()).expect("proof result")
    }

    #[test]
    fn honest_fixture_seals_verify() {
        let mock = MockRpc::new(Scenario::HonestFixtures);
        assert_eq!(mock.headers().len(), 5);
        for h in mock.headers() {
            verify_seal_coinbase(h).expect("honest seal");
        }
        let proof = proof_from(&mock);
        let acc = verify_eth_get_proof(&mock.fixture_state_root(), &mock.wbnb_address(), &proof)
            .expect("honest getProof");
        assert_eq!(acc.nonce, 1);
        let n = mock.tip_number().unwrap();
        let resp = mock.handle(req("eth_blockNumber", json!([])));
        assert_eq!(resp["result"], qty(n));
        let by_num = mock.handle(req("eth_getBlockByNumber", json!(["latest", false])));
        assert_eq!(
            by_num["result"]["hash"],
            mock.headers().last().unwrap().hash
        );
        let hash = &mock.headers()[0].hash;
        let by_hash = mock.handle(req("eth_getBlockByHash", json!([hash, false])));
        assert_eq!(by_hash["result"]["number"], mock.headers()[0].number);
    }

    #[test]
    fn fixture_checkpoint_sealing_set_is_unique() {
        let cp = MockRpc::new(Scenario::HonestFixtures).checkpoint().unwrap();
        cp.validate_basic().expect("unique 20-byte set");
        assert_eq!(cp.sealing_set.len(), 21);
        let mut seen = std::collections::HashSet::new();
        for a in &cp.sealing_set {
            assert!(seen.insert(decode_hex_fixed::<20>(a).unwrap()));
        }
    }

    #[test]
    fn mutated_seal_rejected() {
        let mock = MockRpc::new(Scenario::MutatedSeal);
        for h in mock.headers() {
            assert!(verify_seal_coinbase(h).is_err());
        }
    }

    #[test]
    fn coinbase_mismatch_rejected() {
        let mock = MockRpc::new(Scenario::CoinbaseMismatch);
        for h in mock.headers() {
            assert!(verify_seal_coinbase(h).is_err());
        }
    }

    #[test]
    fn broken_parent_rejected() {
        let mock = MockRpc::new(Scenario::BrokenParent);
        let headers = mock.headers();
        assert_ne!(
            headers[1].parent_hash.to_lowercase(),
            headers[0].hash.to_lowercase()
        );
        let mut snap = Snapshot::from_checkpoint(&mock.checkpoint().unwrap()).unwrap();
        let miner = decode_hex_fixed::<20>(&headers[1].miner).unwrap();
        let err = snap.apply_verified(&headers[1], miner).unwrap_err();
        assert!(matches!(err, SnapshotError::ParentHashMismatch));
    }

    #[test]
    fn lying_balance_proof_rejected() {
        let mock = MockRpc::new(Scenario::LyingBalance);
        let proof = proof_from(&mock);
        assert_eq!(proof.balance, "0x1");
        assert!(
            verify_eth_get_proof(&mock.fixture_state_root(), &mock.wbnb_address(), &proof).is_err()
        );
    }

    #[test]
    fn wrong_state_root_rejected() {
        let mock = MockRpc::new(Scenario::WrongStateRoot);
        let proof = proof_from(&mock);
        assert_eq!(mock.verification_state_root(), WRONG_STATE_ROOT);
        assert!(verify_eth_get_proof(&WRONG_STATE_ROOT, &mock.wbnb_address(), &proof).is_err());
        verify_eth_get_proof(&mock.fixture_state_root(), &mock.wbnb_address(), &proof)
            .expect("honest proof still verifies against fixture stateRoot");
    }

    #[test]
    fn wrong_address_proof_rejected() {
        let mock = MockRpc::new(Scenario::WrongAddress);
        let proof = proof_from(&mock);
        assert!(
            verify_eth_get_proof(&mock.fixture_state_root(), &mock.wbnb_address(), &proof).is_err()
        );
        assert!(verify_eth_get_proof(&mock.fixture_state_root(), &WRONG_ADDRESS, &proof).is_err());
    }

    #[test]
    fn fourteen_sealers_not_safe() {
        let mock = MockRpc::new(Scenario::FourteenSealers);
        let chain = mock.verified_chain().unwrap();
        let miners: std::collections::BTreeSet<_> = chain.iter().map(|b| b.miner).collect();
        assert_eq!(miners.len(), 14);
        assert!(newest_safe(&chain, n_seal()).is_none());
        assert!(newest_safe(&distinct_sealer_chain(14), n_seal()).is_none());
        assert_eq!(min_distinct_sealers(n_seal()), 15);
    }

    #[test]
    fn truncated_history_no_safe() {
        let mock = MockRpc::new(Scenario::TruncatedHistory);
        let chain = mock.verified_chain().unwrap();
        let miners: std::collections::BTreeSet<_> = chain.iter().map(|b| b.miner).collect();
        assert!(miners.len() < 15);
        assert!(newest_safe(&chain, n_seal()).is_none());
        assert!(newest_safe(&cycling_sealer_chain(8, 4), n_seal()).is_none());
    }

    // ---- Fast finality (BEP-126): forged attestations ----

    const FORGED_FINALITY: [Scenario; 4] = [
        Scenario::ForgedAttestationSignature,
        Scenario::ForgedAttestationTarget,
        Scenario::StrippedAttestation,
        Scenario::DowngradedQuorum,
    ];

    /// Apply `headers[1..]` to a snapshot rooted at [`MockRpc::finality_checkpoint`],
    /// returning the snapshot as it stood and the first error, if any.
    ///
    /// Seals are not re-verified: every forged scenario rewrites `extraData`, which breaks
    /// the seal by construction, so `apply_header` would reject on the seal before ever
    /// reaching `check_attestation` and the test would prove the wrong thing.
    fn drive(mock: &MockRpc) -> (Snapshot, Option<SnapshotError>) {
        let cp = mock.finality_checkpoint().expect("finality checkpoint");
        cp.validate_basic().expect("checkpoint with vote keys");
        let mut snap = Snapshot::from_checkpoint(&cp).expect("snapshot");
        assert!(
            snap.fast_finality_available(),
            "vote keys missing — every attestation check would be skipped"
        );
        for h in &mock.headers()[1..] {
            let miner = decode_hex_fixed::<20>(&h.miner).expect("miner");
            if let Err(e) = snap.apply_verified(h, miner) {
                return (snap, Some(e));
            }
        }
        (snap, None)
    }

    /// Positive control. Without it a bug that rejected every header would make all four
    /// forgery tests below pass.
    #[test]
    fn honest_attestations_finalize_two_blocks_behind_the_tip() {
        let mock = MockRpc::new(Scenario::HonestFixtures);
        let (snap, err) = drive(&mock);
        assert!(err.is_none(), "honest fixtures must apply: {err:?}");

        let tip = mock.tip_number().unwrap();
        assert_eq!(snap.number, tip);
        // `GetFinalizedHeader` is the newest attestation's source, one justified block
        // behind its target — the flat lag-2 measured on live mainnet.
        assert_eq!(snap.justified().map(|(n, _)| n), Some(tip - 1));
        let (number, hash) = snap.finalized().expect("finalized head");
        assert_eq!(number, tip - 2);
        assert_eq!(
            hash,
            decode_hex_fixed::<32>(&mock.headers()[2].hash).unwrap(),
            "the finalized head must be a block we actually walked"
        );
    }

    /// A real BLS signature over another block's `VoteData`: structurally perfect, so it
    /// can only fail at `FastAggregateVerify`.
    #[test]
    fn replayed_attestation_signature_rejected() {
        let mock = MockRpc::new(Scenario::ForgedAttestationSignature);
        let (_, err) = drive(&mock);
        assert!(
            matches!(
                err,
                Some(SnapshotError::Vote(VoteError::SignatureVerifyFailed))
            ),
            "{err:?}"
        );
    }

    /// Target-is-parent is checked before the signature, so this is the linkage rule
    /// failing, not the crypto.
    #[test]
    fn forged_attestation_target_rejected() {
        let mock = MockRpc::new(Scenario::ForgedAttestationTarget);
        let (_, err) = drive(&mock);
        assert!(
            matches!(err, Some(SnapshotError::AttestationTargetHash)),
            "{err:?}"
        );
    }

    /// `ceil(2*21/3)` = 14, not the confirmation-depth `floor(2*21/3)+1` = 15.
    #[test]
    fn downgraded_quorum_rejected() {
        let mock = MockRpc::new(Scenario::DowngradedQuorum);
        let (_, err) = drive(&mock);
        assert!(
            matches!(
                err,
                Some(SnapshotError::Vote(VoteError::NotEnoughVotes {
                    got: 13,
                    need: 14
                }))
            ),
            "{err:?}"
        );
        assert_eq!(min_votes_for_finality(21), 14);
        assert_eq!(DOWNGRADED_VOTES, 13);
    }

    /// Absent is normal, wrong is fatal. Stripping the attestation must **not** reject the
    /// header — the client just keeps the finalized head it already had, which is the only
    /// thing that stops an upstream from downgrading finality by omission being confused
    /// with an attack.
    #[test]
    fn stripped_attestation_is_accepted_and_freezes_finality() {
        let mock = MockRpc::new(Scenario::StrippedAttestation);
        for i in 0..mock.headers().len() {
            let present = !mock.attestation_rlp(i).unwrap().is_empty();
            assert_eq!(present, i < STRIP_ATTESTATION_FROM, "header {i}");
        }

        let (snap, err) = drive(&mock);
        assert!(err.is_none(), "an absent attestation is legal: {err:?}");

        let tip = mock.tip_number().unwrap();
        assert_eq!(snap.number, tip, "every header was still accepted");
        // Finality stalls where headers[2] left it: its attestation targets tip-3 and
        // sources tip-4. The two stripped headers move neither.
        assert_eq!(snap.justified().map(|(n, _)| n), Some(tip - 3));
        assert_eq!(snap.finalized().map(|(n, _)| n), Some(tip - 4));
    }

    /// Each forgery must live entirely inside the attestation region: if it spilled into
    /// the vanity, the validator records or the seal, the rejection above could be blamed
    /// on the wrong rule.
    #[test]
    fn forgery_is_confined_to_the_attestation_region() {
        let honest = MockRpc::new(Scenario::HonestFixtures);
        for scenario in FORGED_FINALITY {
            let forged = MockRpc::new(scenario);
            let mut differs = 0;
            for (i, (a, b)) in honest.headers().iter().zip(forged.headers()).enumerate() {
                assert_eq!(a.hash, b.hash, "{scenario:?} #{i} hash");
                assert_eq!(a.parent_hash, b.parent_hash, "{scenario:?} #{i} parentHash");
                assert_eq!(a.miner, b.miner, "{scenario:?} #{i} miner");
                let ea = decode_hex(&a.extra_data).unwrap();
                let eb = decode_hex(&b.extra_data).unwrap();
                let (ha, hb) = (ea.len() - EXTRA_SEAL, eb.len() - EXTRA_SEAL);
                assert_eq!(
                    ea[..ha - honest.attestation_rlp(i).unwrap().len()],
                    eb[..hb - forged.attestation_rlp(i).unwrap().len()],
                    "{scenario:?} #{i} vanity + validator records"
                );
                assert_eq!(ea[ha..], eb[hb..], "{scenario:?} #{i} seal");
                if honest.attestation_rlp(i).unwrap() != forged.attestation_rlp(i).unwrap() {
                    differs += 1;
                }
            }
            assert!(differs > 0, "{scenario:?} changed nothing");
        }
    }

    #[test]
    fn finality_checkpoint_carries_the_real_epoch_set() {
        let cp = MockRpc::new(Scenario::HonestFixtures)
            .finality_checkpoint()
            .unwrap();
        cp.validate_basic().expect("21 addresses + 21 vote keys");
        assert_eq!(cp.sealing_set.len(), 21);
        let keys = cp.vote_keys.as_ref().expect("vote keys");
        assert_eq!(keys.len(), 21);
        for k in keys {
            assert_eq!(decode_hex(k).unwrap().len(), 48);
        }
        // Every fixture miner must be in the set, or the walk would fail as unauthorized
        // long before any attestation was looked at.
        for h in MockRpc::new(Scenario::HonestFixtures).headers() {
            assert!(
                cp.sealing_set
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(&h.miner)),
                "{} not in the epoch set",
                h.miner
            );
        }
    }

    #[test]
    fn in_turn_15_sealers_is_safe() {
        assert_eq!(PROVIDER_PROOF_LOOKBACK, 112);
        assert_eq!(min_distinct_sealers(21), 15);
        let chain = distinct_sealer_chain(15);
        let miners: std::collections::BTreeSet<_> = chain.iter().skip(1).map(|b| b.miner).collect();
        assert_eq!(miners.len(), 15);
        let safe = newest_safe(&chain, n_seal()).expect("15 distinct subsequent sealers is Safe");
        assert_eq!(safe.required_sealers, 15);
        assert!(safe.distinct_sealers >= 15);
        assert_eq!(safe.number, chain[0].number);
    }
}
