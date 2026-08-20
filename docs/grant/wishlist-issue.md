# Wishlist issue (paste into bnb-chain/community-contributions)

**Title:**

```
Wishlist: Parlia light client / trust-minimized local JSON-RPC for wallets (Helios-like for BSC)
```

**Body:**

```markdown
## Summary

BNB Chain wallets and dapps mostly rely on centralized JSON-RPC providers. A compromised or buggy RPC can lie about balances and state. Full/fast BSC nodes need multi-TB storage, so end users cannot practically self-verify.

Ethereum has [Helios](https://github.com/a16z/helios). BSC uses **Parlia** (no ETH sync committees), so Helios does not port cleanly.

## Proposal

An open-source **Parlia light client** that:
- verifies header seals + epoch validator transitions + confirmation-depth Safe head
- verifies `eth_getProof` (MPT) against Safe `stateRoot`
- exposes a **local fail-closed JSON-RPC** for wallet-like reads (`eth_getBalance`, etc.) with ~0 durable chain storage

## Existing work

We are building **helios-bsc**: https://github.com/Alt-bi/helios-bsc  
(MIT OR Apache-2.0, Demo Slice in progress.)

Related but different: [parlia-elc](https://github.com/datachainlab/parlia-elc) (IBC/LCP), not a wallet-local RPC.

## Ask

Please consider this for the Grant Wishlist / Builder Grant as **Developer Tools & Infrastructure** / wallet security public good.
```
