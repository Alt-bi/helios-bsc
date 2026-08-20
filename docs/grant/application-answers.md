# Copy-paste answers — BNB Chain Builder Grant form

Form: https://forms.monday.com/forms/0469580c0e412266a888526a38b114a0?r=euc1  

Fill placeholders: `YOUR_*`. Field names on Monday may vary slightly — map by meaning.

---

### Project name
```
helios-bsc
```

### Project category / area
```
Developer Tools and Infrastructure
```

### One-line description
```
Trust-minimized Parlia light client for BNB Smart Chain with local verified JSON-RPC (Helios-like for BSC).
```

### Full description
```
helios-bsc is an open-source Rust light client for BNB Smart Chain (Parlia). It maintains a minimal verified view of recent headers (ECDSA seals, epoch validator set transitions, confirmation-depth Safe head) and serves a local fail-closed JSON-RPC that verifies account/storage proofs (eth_getProof / MPT) against the Safe stateRoot. Wallet mode maps "latest" to Safe. This gives users Helios-like trust minimization on BSC without running a multi-TB full node. Upstream RPCs remain a data plane only—responses that break seal or Merkle rules are rejected.

Status: Demo Slice implemented (seals, Safe, MPT, local RPC, checkpoints, adversarial tests). We are applying for a modest Builder Grant to publish/harden the release and close the Safe-lag eth_getProof provider gap (paid/archive path or self-hosted untrusted full/fast node runbook).
```

### Why BNB Chain / impact
```
Most BSC users blindly trust RPC providers. A verified local light client improves wallet and bot security across the ecosystem as a public good—similar to what Helios did for Ethereum—while staying practical (~0 chain disk). It strengthens developer tooling and user safety without competing with node operators.
```

### Open source?
```
Yes — dual license MIT OR Apache-2.0
```

### GitHub URL
```
https://github.com/Alt-bi/helios-bsc
```

### Website / docs
```
https://github.com/Alt-bi/helios-bsc (README + docs/)
```

### Demo link
```
YOUR_DEMO_VIDEO_URL (or "See README Quick start: cargo run -p helios-bsc -- info / probe-safe / run")
```

### Grant amount requested (USD)
```
8000
```

### How funds will be used
```
Milestone 1 ($4000): public GitHub release v0.1, documentation, CI, demo recording.
Milestone 2 ($4000): reproducible Safe-lag eth_getProof path (paid provider or Alt F runbook), soak report vs independent oracle, short wallet integration guide.
See milestones in docs/grant/milestones.md.
```

### Timeline
```
M1: 4–6 weeks after agreement. M2: additional 6–8 weeks.
```

### Team
```
Solo developer. Name: YOUR_NAME. Contact: YOUR_EMAIL / Telegram YOUR_TG.
```

### Differentiator / competitors
```
Not a16z Helios (Ethereum/L2 only). Not datachainlab/parlia-elc (IBC/LCP bridge light client). Not a full BSC node. Focus: wallet-grade local verified eth_* RPC for Parlia.
```

### Risks / limitations (honesty helps)
```
Verified state reads require an upstream that can serve eth_getProof at Safe lag (~108–120 blocks). Many free RPCs prune earlier; we fail closed. Milestone 2 specifically addresses a reproducible proof path.
```

### Other / notes
```
Wishlist issue: (link if opened). Design doc in repo docs/design.md.
```
