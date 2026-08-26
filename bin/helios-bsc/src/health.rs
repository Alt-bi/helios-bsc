//! `helios-bsc health` — tells "the process is up" apart from "the process is working".
//!
//! A container that refuses to start is loud: `restart: unless-stopped` cycles it and
//! `docker compose ps` says `Restarting`. The failure this exists for is the quiet one —
//! the process is up, the port answers, `/metrics` reads atomics and looks green, and the
//! head has not moved for an hour because the upstream went away or the sync thread is
//! stuck. Nothing in the container reports that today.
//!
//! What it asks is `helios_bsc_syncStatus`, which is the one call that cannot be answered
//! from stale state: it refreshes (coalesced to one block interval, so a probe every 30 s
//! costs at most one upstream `eth_blockNumber`) and fails closed with `-32003` when the
//! client cannot verify a head at all.
//!
//! **This reports; it does not restart.** Docker does not restart an unhealthy container
//! on its own, and that is the behaviour we want: a client whose checkpoint went stale
//! must not be restarted into the crash loop `docs/runbooks/long-soak.md` describes. The
//! probe makes the state visible and leaves the decision to a human.

use serde_json::Value;

/// Wall-clock chain lag, in seconds, past which the head counts as not moving.
///
/// Not the SLO bound. `docs/slo.md` puts the in-turn upper bound at 120 blocks (~54 s)
/// and says outright that a longer stretch is a valid out-of-turn run rather than a
/// failure — so gating on the SLO would paint a working client red for doing the right
/// thing, and a probe that is red during normal operation is a probe people switch off.
///
/// A stalled head, by contrast, does not hover: at 450 ms blocks the lag grows by 8000
/// blocks an hour and never comes back. Five minutes is far above any legitimate
/// out-of-turn stretch and still catches a stall while somebody could still act on it.
pub const DEFAULT_MAX_LAG_SECONDS: u64 = 300;

/// What the probe was asked to enforce. `None` means "do not check this one".
#[derive(Debug, Clone, Copy)]
pub struct HealthLimits {
    pub max_lag_seconds: Option<u64>,
    pub max_lag_blocks: Option<u64>,
}

impl Default for HealthLimits {
    fn default() -> Self {
        Self {
            max_lag_seconds: Some(DEFAULT_MAX_LAG_SECONDS),
            max_lag_blocks: None,
        }
    }
}

/// The verdict, with the reason attached either way. A probe that says only "unhealthy"
/// sends the reader to the logs; this way `docker inspect` already carries the finding.
#[derive(Debug, PartialEq, Eq)]
pub enum Health {
    Ok(String),
    Unhealthy(String),
}

impl Health {
    pub fn is_ok(&self) -> bool {
        matches!(self, Health::Ok(_))
    }

    pub fn message(&self) -> &str {
        match self {
            Health::Ok(m) | Health::Unhealthy(m) => m,
        }
    }
}

fn u64_field(status: &Value, key: &str) -> Option<u64> {
    status.get(key)?.as_u64()
}

/// Judge a `helios_bsc_syncStatus` result object.
///
/// Split from the network call so the decision is unit-testable without a server: the
/// part that can be wrong is which numbers mean unhealthy, not how to POST.
pub fn judge(status: &Value, limits: &HealthLimits) -> Health {
    if !status.is_object() {
        return Health::Unhealthy("syncStatus did not return an object".to_string());
    }
    // A head is the minimum. Without it there is nothing to be late about, and a client
    // that reports no Safe head is one no read can be served from.
    let Some(safe) = u64_field(status, "safe") else {
        return Health::Unhealthy("syncStatus carries no safe head".to_string());
    };
    if safe == 0 {
        return Health::Unhealthy("safe head is 0 — nothing verified yet".to_string());
    }
    let lag_blocks = u64_field(status, "safeLagBlocks");
    let lag_seconds = u64_field(status, "safeLagSeconds");

    // Missing lag fields are treated as a failure rather than a pass. A probe that cannot
    // read the number it exists to check has not checked it, and reporting healthy on the
    // strength of a field that was not there is the same defect as a soak reporting
    // `compared=0` as success.
    if limits.max_lag_seconds.is_some() && lag_seconds.is_none() {
        return Health::Unhealthy("syncStatus carries no safeLagSeconds to check".to_string());
    }
    if limits.max_lag_blocks.is_some() && lag_blocks.is_none() {
        return Health::Unhealthy("syncStatus carries no safeLagBlocks to check".to_string());
    }

    if let (Some(max), Some(actual)) = (limits.max_lag_seconds, lag_seconds) {
        if actual > max {
            return Health::Unhealthy(format!(
                "safe head is {actual}s behind the tip (limit {max}s) — the head is not moving"
            ));
        }
    }
    if let (Some(max), Some(actual)) = (limits.max_lag_blocks, lag_blocks) {
        if actual > max {
            return Health::Unhealthy(format!(
                "safe head is {actual} blocks behind the tip (limit {max})"
            ));
        }
    }

    let finality = status
        .get("safeSource")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let secs = lag_seconds.unwrap_or(0);
    Health::Ok(format!("safe={safe} lag={secs}s source={finality}"))
}

/// Turn a JSON-RPC envelope into either the `result` object or a stated reason.
///
/// `-32003 not_synced` is the client's own fail-closed answer when it cannot verify a
/// head — during bootstrap, or after the upstream went away. It is a legitimate answer to
/// the question and an unhealthy one, which is why the container's HEALTHCHECK carries a
/// `--start-period`: bootstrap must not be read as a stall.
pub fn result_of(envelope: &Value) -> Result<&Value, String> {
    if let Some(err) = envelope.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("no message");
        return Err(format!("syncStatus returned error {code}: {msg}"));
    }
    envelope
        .get("result")
        .ok_or_else(|| "syncStatus reply had neither result nor error".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn healthy_status(lag_seconds: u64) -> Value {
        json!({
            "safe": 118_000_000u64,
            "safeLagBlocks": lag_seconds * 1000 / 450,
            "safeLagSeconds": lag_seconds,
            "safeSource": "fast-finality",
        })
    }

    #[test]
    fn a_moving_head_is_healthy() {
        let v = judge(&healthy_status(50), &HealthLimits::default());
        assert!(v.is_ok(), "{}", v.message());
        assert!(v.message().contains("fast-finality"));
    }

    #[test]
    fn the_slo_bound_is_not_the_health_bound() {
        // docs/slo.md: lag above the in-turn upper bound (120 blocks / ~54s) is a valid
        // out-of-turn stretch, not a failure. A probe that reddens here would be red
        // during normal operation, and a probe that is normally red gets switched off.
        let just_over_slo = healthy_status(60);
        assert!(judge(&just_over_slo, &HealthLimits::default()).is_ok());
    }

    #[test]
    fn a_stalled_head_is_unhealthy() {
        let v = judge(&healthy_status(301), &HealthLimits::default());
        assert!(!v.is_ok());
        assert!(v.message().contains("not moving"), "{}", v.message());
    }

    #[test]
    fn an_explicit_block_limit_is_enforced_too() {
        let limits = HealthLimits {
            max_lag_seconds: None,
            max_lag_blocks: Some(200),
        };
        // 50s at 450ms is ~111 blocks: inside 200.
        assert!(judge(&healthy_status(50), &limits).is_ok());
        // 120s is ~266 blocks: outside.
        let v = judge(&healthy_status(120), &limits);
        assert!(!v.is_ok());
        assert!(v.message().contains("blocks behind"), "{}", v.message());
    }

    #[test]
    fn no_head_is_unhealthy() {
        assert!(!judge(&json!({"safeLagSeconds": 1}), &HealthLimits::default()).is_ok());
        assert!(!judge(
            &json!({"safe": 0, "safeLagSeconds": 1}),
            &HealthLimits::default()
        )
        .is_ok());
    }

    #[test]
    fn a_missing_lag_field_is_unhealthy_not_healthy() {
        // The whole point of the probe is the lag. If the field it checks is absent, it
        // has checked nothing -- and "checked nothing" must never read as "found nothing".
        let v = judge(&json!({"safe": 118_000_000u64}), &HealthLimits::default());
        assert!(!v.is_ok());
        assert!(v.message().contains("no safeLagSeconds"), "{}", v.message());

        let limits = HealthLimits {
            max_lag_seconds: None,
            max_lag_blocks: Some(200),
        };
        let v = judge(&json!({"safe": 118_000_000u64}), &limits);
        assert!(!v.is_ok());
        assert!(v.message().contains("no safeLagBlocks"), "{}", v.message());
    }

    #[test]
    fn a_non_object_status_is_unhealthy() {
        assert!(!judge(&json!("fine"), &HealthLimits::default()).is_ok());
        assert!(!judge(&json!(null), &HealthLimits::default()).is_ok());
    }

    #[test]
    fn not_synced_is_reported_as_the_reason() {
        let env = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32003, "message": "not_synced: upstream"}});
        let err = result_of(&env).unwrap_err();
        assert!(err.contains("-32003"), "{err}");
        assert!(err.contains("not_synced"), "{err}");
    }

    #[test]
    fn a_reply_with_neither_result_nor_error_is_refused() {
        assert!(result_of(&json!({"jsonrpc": "2.0", "id": 1})).is_err());
    }

    #[test]
    fn a_result_envelope_is_unwrapped() {
        let env = json!({"jsonrpc": "2.0", "id": 1, "result": {"safe": 7}});
        assert_eq!(result_of(&env).unwrap().get("safe").unwrap(), 7);
    }
}
