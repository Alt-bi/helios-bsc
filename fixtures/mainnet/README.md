# Mainnet fixtures

Captured 2026-08-18 from `https://bsc-mainnet.public.blastapi.io`.

| File | What |
|------|------|
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

Refresh:

```bash
python scripts/capture_headers.py --rpc URL --from-block 116663998 --count 5 --out fixtures/mainnet/
```
