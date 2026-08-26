//! Listen-address policy: loopback by default (no in-process RPC auth).

use anyhow::{bail, Result};

/// Host of `ip:port` or `[v6]:port`.
pub fn listen_host(listen: &str) -> &str {
    let s = listen.trim();
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(s);
    }
    s.rsplit_once(':').map(|(h, _)| h).unwrap_or(s)
}

pub fn listen_is_loopback(listen: &str) -> bool {
    let h = listen_host(listen).trim_matches(|c| c == '[' || c == ']');
    let h = h.trim();
    h.eq_ignore_ascii_case("127.0.0.1")
        || h.eq_ignore_ascii_case("localhost")
        || h == "::1"
        || h.eq_ignore_ascii_case("ip6-localhost")
}

/// HTTP `Host` on a loopback bind. Accepts `127/8` so DNS-rebinding to
/// `127.0.0.2` cannot skip a `127.0.0.1`-only allow-list.
pub fn http_host_is_loopback(host: &str) -> bool {
    if listen_is_loopback(host) {
        return true;
    }
    let h = listen_host(host.trim()).trim_matches(|c| c == '[' || c == ']');
    let h = h.trim();
    let mut parts = h.split('.');
    if parts.next() != Some("127") {
        return false;
    }
    let rest: Vec<&str> = parts.collect();
    rest.len() == 3 && rest.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Loopback RPC: require a loopback `Host` (DNS rebinding). LAN binds skip this.
pub fn rpc_http_host_reject(host: Option<&str>, loopback_only: bool) -> Option<u16> {
    if !loopback_only {
        return None;
    }
    match host {
        Some(h) if http_host_is_loopback(h) => None,
        _ => Some(403),
    }
}

/// What an operator sees when the process is reachable off the machine.
///
/// This used to be one line, which is the wrong size for what it says. In a container it
/// is worse than that: the published image's `CMD` already carries
/// `--allow-non-loopback`, because Docker NAT is not loopback and the process cannot be
/// reached through a published port without binding `0.0.0.0`. So for anyone running the
/// image, the flag is not a decision they made — it is pre-satisfied, and the only thing
/// between them and an open port is the `127.0.0.1:` prefix in their own `-p` argument.
///
/// The text is a function, not an inline literal, so the unit test below pins the phrases
/// that `release.yml` greps for. If someone rewords this, the test fails here rather than
/// the CI check silently passing on a warning that no longer says anything.
pub fn non_loopback_warning(listen: &str) -> String {
    format!(
        "\n\
         !!! helios-bsc is listening on {listen}, which is not loopback.\n\
         !!!\n\
         !!! There is no authentication in this process. Anyone who can reach this port\n\
         !!! can read through it, broadcast raw transactions, and spend your upstream RPC\n\
         !!! quota. The loopback Host check that blocks DNS rebinding is also inactive in\n\
         !!! this mode, because it only applies to loopback binds.\n\
         !!!\n\
         !!! Put a firewall and a reverse proxy in front of it, terminating TLS and\n\
         !!! authenticating. Under Docker, publish as -p 127.0.0.1:8545:8545 and never\n\
         !!! as -p 8545:8545.\n"
    )
}

/// Non-loopback binds need `--allow-non-loopback` (no RPC auth in this binary).
pub fn assert_listen_policy(listen: &str, allow_non_loopback: bool) -> Result<()> {
    if listen_is_loopback(listen) {
        return Ok(());
    }
    if allow_non_loopback {
        eprintln!("{}", non_loopback_warning(listen));
        return Ok(());
    }
    bail!("refusing non-loopback bind {listen}; pass --allow-non-loopback (no built-in auth)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts() {
        assert!(listen_is_loopback("127.0.0.1:8545"));
        assert!(listen_is_loopback("localhost:8545"));
        assert!(listen_is_loopback("LOCALHOST:9"));
        assert!(listen_is_loopback("[::1]:8545"));
        assert!(!listen_is_loopback("0.0.0.0:8545"));
        assert!(!listen_is_loopback("192.168.1.10:8545"));
        assert!(!listen_is_loopback("[::]:8545"));
        assert!(!listen_is_loopback("example.local:8545"));
    }

    #[test]
    fn compose_publishes_host_loopback_only() {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compose.yaml");
        let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        assert!(
            s.contains("127.0.0.1:8545:8545"),
            "compose must pin host bind to loopback"
        );
        assert!(
            !s.contains("- \"8545:8545\""),
            "bare 8545:8545 would expose every interface"
        );
    }

    #[test]
    fn policy_requires_flag() {
        assert!(assert_listen_policy("127.0.0.1:8545", false).is_ok());
        assert!(assert_listen_policy("0.0.0.0:8545", false).is_err());
        assert!(assert_listen_policy("0.0.0.0:8545", true).is_ok());
    }

    /// `release.yml` greps the running image's output for these phrases, to prove the
    /// warning still reaches an operator who published the port to the world. A CI grep
    /// against text nobody pins is a check that quietly stops checking, so the phrases
    /// live here and this test is what breaks first if they are reworded.
    #[test]
    fn the_non_loopback_warning_says_what_is_at_risk() {
        let w = non_loopback_warning("0.0.0.0:8545");

        // The address, so it is obvious which bind is meant.
        assert!(w.contains("0.0.0.0:8545"), "{w}");
        // Grepped by CI. Keep these two in step with the workflow.
        assert!(w.contains("no authentication in this process"), "{w}");
        assert!(w.contains("-p 127.0.0.1:8545:8545"), "{w}");
        // The concrete consequences, not just an adjective.
        assert!(w.contains("broadcast raw transactions"), "{w}");
        assert!(w.contains("DNS rebinding"), "{w}");
        // Loud enough to survive a log stream: several lines, each marked.
        assert!(
            w.lines().filter(|l| l.starts_with("!!!")).count() >= 8,
            "warning should be a block, not a line: {w}"
        );
    }

    /// A loopback bind is the safe default and must stay quiet — a warning printed on the
    /// ordinary path is a warning people learn to scroll past.
    #[test]
    fn loopback_binds_produce_no_warning() {
        for listen in ["127.0.0.1:8545", "localhost:8545", "[::1]:8545"] {
            assert!(listen_is_loopback(listen), "{listen}");
            assert!(assert_listen_policy(listen, false).is_ok(), "{listen}");
        }
    }

    #[test]
    fn http_host_loopback_rebinding() {
        assert!(http_host_is_loopback("127.0.0.1:8545"));
        assert!(http_host_is_loopback("localhost"));
        assert!(http_host_is_loopback("[::1]:8545"));
        assert!(http_host_is_loopback("127.0.0.2:8545"));
        assert!(!http_host_is_loopback("evil.example:8545"));
        assert!(!http_host_is_loopback("0.0.0.0:8545"));
        assert_eq!(rpc_http_host_reject(Some("127.0.0.1:8545"), true), None);
        assert_eq!(rpc_http_host_reject(Some("evil.example"), true), Some(403));
        assert_eq!(rpc_http_host_reject(None, true), Some(403));
        assert_eq!(rpc_http_host_reject(Some("evil.example"), false), None);
        assert_eq!(
            rpc_http_host_reject(Some("localhost.evil.com"), true),
            Some(403)
        );
        assert_eq!(
            rpc_http_host_reject(Some("127.0.0.1.nip.io"), true),
            Some(403)
        );
        assert_eq!(rpc_http_host_reject(Some(""), true), Some(403));
    }
}
