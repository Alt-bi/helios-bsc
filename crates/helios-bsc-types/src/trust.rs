use serde::{Deserialize, Serialize};

/// Trust label for RPC responses / meta methods.
///
/// Standard eth_* clients (MetaMask) do not see this on the wire; fail-closed
/// methods return hard errors instead of silent unverified data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// Cryptographically verified against consensus-safe stateRoot.
    Verified,
    /// Broadcast / gossip path — no local state verification.
    Unverified,
    /// Method not implemented; must error.
    Unsupported,
}
