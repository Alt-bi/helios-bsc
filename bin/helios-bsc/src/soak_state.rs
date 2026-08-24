//! Crash-resumable soak accounting.
//!
//! The GA gate is a *duration* gate, and a soak host that dies at hour 14 used to reset
//! it to zero. This keeps the tally on disk so a restart continues it.
//!
//! What it deliberately does **not** do is pretend the result is continuous. A resumed
//! soak has gaps; [`SoakState::largest_gap_secs`] measures the worst one and the summary
//! prints it, so "24h" always comes with the shape of the 24h attached.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Bumped whenever a stored field changes meaning. An older shape is refused rather
/// than migrated: a tally that silently mixes two accounting rules proves nothing.
pub const STATE_VERSION: u32 = 1;

/// What a run is soaking. A resume that changes any of it is refused — continuing one
/// experiment's clock with another experiment's numbers is not a longer soak.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SoakFingerprint {
    pub upstream: String,
    pub oracle: String,
    pub fast_finality: bool,
    /// Lowercased, in list order. Stored in full rather than as a count, so a mismatch
    /// says which address moved.
    pub addresses: Vec<String>,
}

impl SoakFingerprint {
    /// First difference, phrased for an operator, or `None` when the two agree.
    pub fn differs_from(&self, other: &Self) -> Option<String> {
        if self.upstream != other.upstream {
            return Some(format!("upstream {} != {}", other.upstream, self.upstream));
        }
        if self.oracle != other.oracle {
            return Some(format!("oracle {} != {}", other.oracle, self.oracle));
        }
        if self.fast_finality != other.fast_finality {
            return Some(format!(
                "finality {} != {}",
                head_name(other.fast_finality),
                head_name(self.fast_finality)
            ));
        }
        if self.addresses != other.addresses {
            return Some(format!(
                "address list ({} stored, {} now)",
                other.addresses.len(),
                self.addresses.len()
            ));
        }
        None
    }
}

fn head_name(fast: bool) -> &'static str {
    if fast {
        "fast"
    } else {
        "confirmation-depth"
    }
}

/// One uninterrupted stretch of soaking.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SoakSession {
    pub started_unix: u64,
    pub ended_unix: u64,
}

impl SoakSession {
    pub fn secs(&self) -> u64 {
        self.ended_unix.saturating_sub(self.started_unix)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SoakState {
    pub version: u32,
    pub fingerprint: SoakFingerprint,
    pub compared: u32,
    pub matched: u32,
    pub mismatched: u32,
    pub skipped: u32,
    /// Comparisons that ran at the BLS-finalized head. Carried across sessions for the
    /// same reason the gate checks it at all: asking for fast finality and reaching it
    /// are different facts.
    pub compared_at_fast: u32,
    /// Comparisons that reached each best-effort sub-check. Carried across sessions so a
    /// long soak can say what it actually exercised, not just how many times it ran.
    #[serde(default)]
    pub checked_balance: u32,
    #[serde(default)]
    pub checked_nonce: u32,
    #[serde(default)]
    pub checked_slot0: u32,
    #[serde(default)]
    pub checked_call: u32,
    #[serde(default)]
    pub checked_finality: u32,
    /// Addresses matched at least once, lowercased.
    pub unique: Vec<String>,
    /// Sessions in start order. The soaked total is their sum, never
    /// `now - sessions[0].started_unix`.
    pub sessions: Vec<SoakSession>,
}

impl SoakState {
    pub fn new(fingerprint: SoakFingerprint) -> Self {
        Self {
            version: STATE_VERSION,
            fingerprint,
            ..Self::default()
        }
    }

    /// Seconds actually spent soaking, summed over sessions.
    ///
    /// Not the span from the first session's start: a crash-resumed soak has gaps, and
    /// counting them as soak time is exactly the overstatement this file exists to avoid.
    pub fn soaked_secs(&self) -> u64 {
        self.sessions.iter().map(SoakSession::secs).sum()
    }

    /// Longest interruption between sessions, or `None` for a single unbroken run.
    pub fn largest_gap_secs(&self) -> Option<u64> {
        self.sessions
            .windows(2)
            .map(|w| w[1].started_unix.saturating_sub(w[0].ended_unix))
            .max()
    }

    /// How much longer this soak must run to reach `target`.
    pub fn remaining_secs(&self, target: u64) -> u64 {
        target.saturating_sub(self.soaked_secs())
    }

    pub fn done_set(&self) -> HashSet<String> {
        self.unique.iter().cloned().collect()
    }

    /// Start a new session. Sessions are appended open (`ended == started`) and closed
    /// by [`SoakState::touch_session`], so a crash leaves the tally as of the last save
    /// rather than losing the session entirely.
    pub fn open_session(&mut self, now_unix: u64) {
        self.sessions.push(SoakSession {
            started_unix: now_unix,
            ended_unix: now_unix,
        });
    }

    /// Extend the open session to `now_unix`. Called on every save, so an unclean exit
    /// costs at most the time since the last round.
    pub fn touch_session(&mut self, now_unix: u64) {
        if let Some(last) = self.sessions.last_mut() {
            last.ended_unix = last.ended_unix.max(now_unix);
        }
    }

    /// Load a compatible state, or `Ok(None)` when there is nothing to resume.
    ///
    /// A version or fingerprint mismatch is an **error**, not a fresh start: silently
    /// discarding an operator's 14 hours because a flag moved is the failure this whole
    /// module exists to prevent.
    pub fn load(path: &Path, want: &SoakFingerprint) -> Result<Option<Self>> {
        let raw = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        let state: Self = serde_json::from_slice(&raw)
            .with_context(|| format!("parse soak state {}", path.display()))?;
        if state.version != STATE_VERSION {
            bail!(
                "soak state {} is version {}, this build writes {STATE_VERSION} — start a new state file or keep the old binary",
                path.display(),
                state.version
            );
        }
        if let Some(diff) = want.differs_from(&state.fingerprint) {
            bail!(
                "soak state {} was recorded for a different run ({diff}) — resuming would merge two experiments",
                path.display()
            );
        }
        Ok(Some(state))
    }

    /// Persist through the same temp-then-`sync_all`-then-rename path the checkpoint
    /// uses. A soak state torn in half by a crash is worse than none: it would resume
    /// with a tally nobody can defend.
    pub fn save(&self, path: &Path) -> Result<()> {
        crate::sync::atomic_write(path, &self.to_json()?)
            .with_context(|| format!("write soak state {}", path.display()))
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut v = serde_json::to_vec_pretty(self).context("encode soak state")?;
        v.push(b'\n');
        Ok(v)
    }
}

/// `13h 55m` / `48s` — durations an operator reads next to a 24h target.
pub fn human_secs(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp() -> SoakFingerprint {
        SoakFingerprint {
            upstream: "up.example".into(),
            oracle: "oracle.example".into(),
            fast_finality: true,
            addresses: vec!["0xaa".into(), "0xbb".into()],
        }
    }

    /// The whole point of the file: a crash at hour 14 costs the time since the last
    /// save, not the 14 hours.
    #[test]
    fn sessions_sum_rather_than_span() {
        let mut s = SoakState::new(fp());
        s.open_session(1_000);
        s.touch_session(1_000 + 50_000); // ~13.9h, then the host dies
        s.open_session(1_000 + 90_000); // resumed 11h later
        s.touch_session(1_000 + 90_000 + 40_000);

        assert_eq!(s.soaked_secs(), 90_000, "soak time is the sum of sessions");
        assert_eq!(
            s.largest_gap_secs(),
            Some(40_000),
            "the gap is reported, not folded into the total"
        );
        assert_eq!(s.remaining_secs(86_400), 0, "90000s clears a 24h target");
        assert_eq!(s.remaining_secs(100_000), 10_000);
    }

    #[test]
    fn a_single_run_has_no_gap() {
        let mut s = SoakState::new(fp());
        s.open_session(10);
        s.touch_session(20);
        assert_eq!(s.largest_gap_secs(), None);
        assert_eq!(s.soaked_secs(), 10);
    }

    /// `touch_session` must never move an end backwards: a host whose clock steps back
    /// would otherwise shorten a session that really happened.
    #[test]
    fn touch_never_shortens_a_session() {
        let mut s = SoakState::new(fp());
        s.open_session(1_000);
        s.touch_session(5_000);
        s.touch_session(2_000);
        assert_eq!(s.soaked_secs(), 4_000);
    }

    #[test]
    fn a_missing_state_file_is_a_fresh_start() {
        let path = std::env::temp_dir().join(format!("helios_soak_absent_{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_eq!(SoakState::load(&path, &fp()).unwrap(), None);
    }

    /// Refusing beats both alternatives: silently starting over throws away the hours,
    /// silently resuming merges two different experiments into one number.
    #[test]
    fn a_state_from_another_run_is_refused_not_discarded() {
        let dir = std::env::temp_dir().join(format!("helios_soak_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");

        let mut stored = SoakState::new(fp());
        stored.compared = 4129;
        std::fs::write(&path, stored.to_json().unwrap()).unwrap();

        // Same run: resumes with its tally intact.
        let back = SoakState::load(&path, &fp()).unwrap().expect("resumable");
        assert_eq!(back.compared, 4129);

        for (mutate, needle) in [
            (
                Box::new(|f: &mut SoakFingerprint| f.oracle = "other.example".into())
                    as Box<dyn Fn(&mut SoakFingerprint)>,
                "oracle",
            ),
            (
                Box::new(|f: &mut SoakFingerprint| f.fast_finality = false),
                "finality",
            ),
            (
                Box::new(|f: &mut SoakFingerprint| f.addresses.push("0xcc".into())),
                "address list",
            ),
        ] {
            let mut other = fp();
            mutate(&mut other);
            let err = SoakState::load(&path, &other).unwrap_err().to_string();
            assert!(err.contains(needle), "{needle} not named in: {err}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_from_an_older_build_is_refused() {
        let dir = std::env::temp_dir().join(format!("helios_soak_v_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");

        let mut stored = SoakState::new(fp());
        stored.version = STATE_VERSION + 1;
        std::fs::write(&path, stored.to_json().unwrap()).unwrap();

        let err = SoakState::load(&path, &fp()).unwrap_err().to_string();
        assert!(err.contains("version"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn durations_read_as_hours_next_to_a_24h_target() {
        assert_eq!(human_secs(50_100), "13h 55m");
        assert_eq!(human_secs(86_400), "24h 00m");
        assert_eq!(human_secs(125), "2m 05s");
        assert_eq!(human_secs(48), "48s");
    }
}
