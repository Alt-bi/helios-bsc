# Security

Report vulnerabilities **privately** via GitHub Security Advisories on this repository. Do not file a public issue for seal verification, MPT walking, bind/CORS, or local-RPC exploits.

Threat model: [`docs/threat-model.md`](docs/threat-model.md).

## Operator assumptions

- Upstream JSON-RPC is **untrusted**. Integrity is Parlia seals + MPT proofs against a Safe `stateRoot`. `--backup` is transport failover only, not a trust oracle.
- Default listen address is **loopback** (`127.0.0.1:8545`). Non-loopback is opt-in (`--allow-non-loopback`) and has no in-process auth.
- No CORS `*`. Loopback binds require a loopback `Host` header (DNS rebinding).
- Do not commit `.env` or API keys.
