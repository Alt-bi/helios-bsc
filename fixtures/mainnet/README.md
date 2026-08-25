# Mainnet fixtures

Captured 2026-08-18 from `https://bsc-mainnet.public.blastapi.io`.

| File | What |
|------|------|
| `header_116662000.json` | Epoch **below** the one that governs the fixtures. Bootstrap needs two boundaries: the activation height of an epoch is set by the *previous* epoch's validator count and turn length, so `header_116663000` alone cannot say whether it is already active. |
| `header_116663000.json` | Epoch that **governs** the blocks below (activates at +87 = 116663087). Supplies the *real* 21-address sealing set, so tests can keep `enforce_inturn` on instead of padding a fake set. |
| `header_116663998.json` … `header_116664002.json` | Headers across epoch **116664000** (`number % 1000 == 0`) |
| `proof_wbnb_tip.json` | `eth_getProof(WBNB)` **at tip** — MPT unit-test vector only. **Not** a Safe-lag Demo Slice proof. |
| `proof_wbnb_slot0.json` | WBNB account + **storage slot 0** ("Wrapped BNB") at a tip block. `eth_getStorageAt` CI vector. |
| `wbnb_code.hex` | WBNB runtime bytecode. keccak256 matches `codeHash` in `proof_wbnb_tip.json`. `eth_getCode` CI vector. |
| `proof_absent.json` | Exclusion proof for a never-used address (typo USDC). Verifies as empty account, not path-mismatch. |

## Epoch 116664000 extraData (parsed)

- `n` (validator count) = **21**
- `turnLength` byte after validator records = **8** (not the source-comment value 16)
- `extraData` length = 1710 bytes (vanity + n + 21×68 + turnLength + vote attestation + seal)
- `difficulty` = `0x2` (in-turn)
- `miner` = `0x9bb56c2b4dbe5a06d79911c9899b6f817696acfc`

## Authenticity

These fixtures are the ground truth for every consensus test, so a hand-edited or
truncated one would make tests pass while proving nothing. Re-check them against the
chain (headers field-by-field, proof `stateRoot`/`blockHash`, WBNB bytecode):

```bash
python scripts/verify_fixtures.py --rpc https://bsc-dataseed.bnbchain.org
```

Last verified **2026-08-21**: all 6 headers then present (`header_116662000.json` added 2026-08-24 via `capture_headers.py`; `n=21`, `turnLength=8`, activation `116662087`), 3 proofs and `wbnb_code.hex` match live
BSC mainnet (via `bsc-dataseed.bnbchain.org`; header data only, no `eth_getProof`).

Send a **`User-Agent`** if you probe by hand: BlastAPI / publicnode / meowrpc answer
**403** to a bare `Python-urllib` or `curl` default. Every `scripts/*.py` already sets
one, as does the client (`helios-bsc`), so this only bites ad-hoc one-liners.

Refresh:

```bash
python scripts/capture_headers.py --rpc URL --from-block 116663998 --count 5 --out fixtures/mainnet/
```
