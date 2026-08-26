//! Library surface for the `helios-bsc` binary (tests + CLI).

pub mod bind;
pub mod diff;
pub mod health;
pub mod rpc_server;
pub mod soak_state;
pub mod sync;
pub mod upstream;

pub use rpc_server::Node;
pub use upstream::{open_data_plane, Failover, RpcUpstream, Upstream};

#[cfg(test)]
mod adversarial;
