//! `canary` — warrant canaries: signed, dated, expiring statements.
//!
//! A canary is a dead-man switch in document form. The operator signs a
//! statement ("as of this date we have received no warrant") with a `keyring`
//! identity and republishes it on a schedule. Each renewal bumps a monotonic
//! sequence number. Readers verify the signature, check the expiry, and check
//! that the sequence never goes backwards; a canary that expires without
//! renewal — or that regresses — is the signal.
//!
//! Wire format is a single copy-pasteable text document:
//! ```text
//! BPCANARY1
//! key: BPKEY1 <name> <ed25519 hex> <x25519 hex>
//! issued: <unix> <rfc3339>
//! expires: <unix> <rfc3339>
//! sequence: <n>
//! -----BEGIN STATEMENT-----
//! <free text>
//! -----END STATEMENT-----
//! BPSIG1 <ed25519 signature hex>
//! ```
//! The signature covers the header fields (unix timestamps, not the derived
//! human dates) and the exact statement text.

use keyring::{format_signature, parse_signature, KeyPair, PublicIdentity};
use thiserror::Error;

const DOC_TAG: &str = "BPCANARY1";
const BEGIN: &str = "-----BEGIN STATEMENT-----";
const END: &str = "-----END STATEMENT-----";

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Key(#[from] keyring::Error),
    #[error("malformed canary: {0}")]
    BadFormat(&'static str),
    #[error("signature does not verify")]
    BadSignature,
    #[error("renewal check failed: {0}")]
    Renewal(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A parsed (or freshly issued) canary document.
#[derive(Clone, Debug)]
pub struct Canary {
    pub identity: PublicIdentity,
    pub issued: u64,
    pub expires: u64,
    pub sequence: u64,
    pub statement: String,
    pub signature: [u8; 64],
}

/// Liveness of a canary at a given time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Signature good, not yet expired; seconds remaining.
    Valid { remaining: u64 },
    /// Signature good but past its expiry; seconds overdue. The dead-man
    /// signal: absence of a fresh canary is the message.
    Expired { overdue: u64 },
}

impl Canary {
    /// Sign a new canary: `statement` from `kp`, valid for `valid_secs` from
    /// `now`, carrying `sequence`.
    pub fn issue(
        kp: &KeyPair,
        statement: &str,
        now: u64,
        valid_secs: u64,
        sequence: u64,
    ) -> Result<Self> {
        let statement = normalize(statement);
        if statement.is_empty() {
            return Err(Error::BadFormat("empty statement"));
        }
        let identity = kp.public();
        let expires = now.saturating_add(valid_secs);
        let msg = signing_bytes(&identity, now, expires, sequence, &statement);
        Ok(Canary {
            identity,
            issued: now,
            expires,
            sequence,
            statement,
            signature: kp.sign(&msg),
        })
    }

    /// Re-issue this canary from `kp`: same statement, fresh validity window,
    /// sequence incremented. `kp` must be the same identity key.
    pub fn renew(&self, kp: &KeyPair, now: u64, valid_secs: u64) -> Result<Self> {
        if kp.public().ed != self.identity.ed {
            return Err(Error::Renewal("different signing key"));
        }
        Canary::issue(kp, &self.statement, now, valid_secs, self.sequence + 1)
    }

    /// Verify the embedded signature. On success, callers still need
    /// [`status`](Self::status) (expiry) and, across renewals,
    /// [`check_succession`](Self::check_succession).
    pub fn verify(&self) -> Result<()> {
        let msg = signing_bytes(
            &self.identity,
            self.issued,
            self.expires,
            self.sequence,
            &self.statement,
        );
        if self.identity.verify(&msg, &self.signature) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    /// Liveness at time `now`. Meaningful only after [`verify`](Self::verify).
    pub fn status(&self, now: u64) -> Status {
        if now <= self.expires {
            Status::Valid {
                remaining: self.expires - now,
            }
        } else {
            Status::Expired {
                overdue: now - self.expires,
            }
        }
    }

    /// Check that `self` is a legitimate successor to `prev`: same signing
    /// key, strictly higher sequence, not issued earlier. Detects rollback
    /// (an adversary replaying an old canary).
    pub fn check_succession(&self, prev: &Canary) -> Result<()> {
        if self.identity.ed != prev.identity.ed {
            return Err(Error::Renewal("signing key changed"));
        }
        if self.sequence <= prev.sequence {
            return Err(Error::Renewal("sequence did not increase (rollback?)"));
        }
        if self.issued < prev.issued {
            return Err(Error::Renewal("issued earlier than previous canary"));
        }
        Ok(())
    }

    /// Render the full signed document.
    pub fn render(&self) -> String {
        format!(
            "{DOC_TAG}\nkey: {}\nissued: {} {}\nexpires: {} {}\nsequence: {}\n{BEGIN}\n{}\n{END}\n{}\n",
            self.identity.to_line(),
            self.issued,
            format_ts(self.issued),
            self.expires,
            format_ts(self.expires),
            self.sequence,
            self.statement,
            format_signature(&self.signature),
        )
    }

    /// Parse a canary document. Checks structure only; call
    /// [`verify`](Self::verify) for the signature.
    pub fn parse(text: &str) -> Result<Self> {
        let lines: Vec<&str> = text.lines().collect();
        let start = lines
            .iter()
            .position(|l| l.trim() == DOC_TAG)
            .ok_or(Error::BadFormat("missing BPCANARY1 header"))?;

        let mut identity = None;
        let mut issued = None;
        let mut expires = None;
        let mut sequence = None;
        let mut i = start + 1;
        while i < lines.len() {
            let line = lines[i].trim();
            if line == BEGIN {
                break;
            }
            if let Some(v) = line.strip_prefix("key:") {
                identity = Some(PublicIdentity::parse(v)?);
            } else if let Some(v) = line.strip_prefix("issued:") {
                issued = Some(parse_unix(v)?);
            } else if let Some(v) = line.strip_prefix("expires:") {
                expires = Some(parse_unix(v)?);
            } else if let Some(v) = line.strip_prefix("sequence:") {
                sequence = Some(
                    v.trim()
                        .parse::<u64>()
                        .map_err(|_| Error::BadFormat("sequence"))?,
                );
            }
            i += 1;
        }
        if i >= lines.len() {
            return Err(Error::BadFormat("missing statement block"));
        }
        let body_start = i + 1;
        let body_end = lines[body_start..]
            .iter()
            .position(|l| l.trim() == END)
            .map(|p| body_start + p)
            .ok_or(Error::BadFormat("unterminated statement block"))?;
        let statement = normalize(&lines[body_start..body_end].join("\n"));
        let signature = parse_signature(&lines[body_end + 1..].join("\n"))?;

        Ok(Canary {
            identity: identity.ok_or(Error::BadFormat("missing key"))?,
            issued: issued.ok_or(Error::BadFormat("missing issued"))?,
            expires: expires.ok_or(Error::BadFormat("missing expires"))?,
            sequence: sequence.ok_or(Error::BadFormat("missing sequence"))?,
            statement,
            signature,
        })
    }
}

/// The exact bytes the signature covers. Unix timestamps only — the human
/// dates in the rendering are derived, unsigned decoration.
fn signing_bytes(
    id: &PublicIdentity,
    issued: u64,
    expires: u64,
    sequence: u64,
    statement: &str,
) -> Vec<u8> {
    format!(
        "{DOC_TAG}\n{}\nissued: {issued}\nexpires: {expires}\nsequence: {sequence}\n{statement}",
        id.to_line()
    )
    .into_bytes()
}

/// Trim outer blank space, normalize line endings, trim trailing whitespace
/// per line — so a document survives copy-paste byte-exactly.
fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n")
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim_matches('\n')
        .to_string()
}

fn parse_unix(v: &str) -> Result<u64> {
    v.split_whitespace()
        .next()
        .and_then(|t| t.parse::<u64>().ok())
        .ok_or(Error::BadFormat("timestamp"))
}

/// Unix seconds now.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Render unix seconds as RFC 3339 UTC (`2026-07-03T12:00:00Z`).
/// Days-to-civil conversion per Howard Hinnant's algorithm.
pub fn format_ts(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let rem = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe as i64 + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

/// Human "N days H hours" for status displays.
pub fn format_duration(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> KeyPair {
        KeyPair::generate("ops").unwrap()
    }

    const NOW: u64 = 1_751_500_000;
    const MONTH: u64 = 30 * 86_400;

    #[test]
    fn issue_render_parse_verify_roundtrip() {
        let kp = kp();
        let c = Canary::issue(
            &kp,
            "No warrants received.\nAll systems ours.",
            NOW,
            MONTH,
            1,
        )
        .unwrap();
        let doc = c.render();
        let parsed = Canary::parse(&doc).unwrap();
        parsed.verify().unwrap();
        assert_eq!(parsed.statement, c.statement);
        assert_eq!(parsed.sequence, 1);
        assert_eq!(parsed.issued, NOW);
        assert_eq!(parsed.expires, NOW + MONTH);
        // Round-trips byte-identically.
        assert_eq!(parsed.render(), doc);
    }

    #[test]
    fn tampered_fields_fail_verification() {
        let kp = kp();
        let c = Canary::issue(&kp, "all clear", NOW, MONTH, 1).unwrap();
        for mutate in [
            |c: &mut Canary| c.statement = "all clear!".into(),
            |c: &mut Canary| c.expires += 86_400, // stretch the window
            |c: &mut Canary| c.sequence += 1,
            |c: &mut Canary| c.issued -= 1,
        ] {
            let mut bad = c.clone();
            mutate(&mut bad);
            assert!(matches!(bad.verify(), Err(Error::BadSignature)));
        }
        c.verify().unwrap();
    }

    #[test]
    fn status_tracks_expiry() {
        let c = Canary::issue(&kp(), "ok", NOW, MONTH, 1).unwrap();
        assert_eq!(c.status(NOW), Status::Valid { remaining: MONTH });
        assert_eq!(c.status(NOW + MONTH + 60), Status::Expired { overdue: 60 });
    }

    #[test]
    fn renew_bumps_sequence_and_window() {
        let kp = kp();
        let c1 = Canary::issue(&kp, "ok", NOW, MONTH, 1).unwrap();
        let c2 = c1.renew(&kp, NOW + MONTH - 86_400, MONTH).unwrap();
        c2.verify().unwrap();
        assert_eq!(c2.sequence, 2);
        assert_eq!(c2.statement, c1.statement);
        c2.check_succession(&c1).unwrap();

        // Wrong key can't renew.
        let mallory = KeyPair::generate("mallory").unwrap();
        assert!(c1.renew(&mallory, NOW, MONTH).is_err());
    }

    #[test]
    fn succession_detects_rollback_and_key_swap() {
        let kp = kp();
        let c1 = Canary::issue(&kp, "ok", NOW, MONTH, 5).unwrap();
        let replay = Canary::issue(&kp, "ok", NOW + 10, MONTH, 5).unwrap();
        assert!(replay.check_succession(&c1).is_err()); // same seq

        let older = Canary::issue(&kp, "ok", NOW - 100, MONTH, 6).unwrap();
        assert!(older.check_succession(&c1).is_err()); // issued earlier

        let other = KeyPair::generate("other").unwrap();
        let swapped = Canary::issue(&other, "ok", NOW + 10, MONTH, 6).unwrap();
        assert!(swapped.check_succession(&c1).is_err()); // key changed
    }

    #[test]
    fn parse_tolerates_surrounding_noise() {
        let c = Canary::issue(&kp(), "still here", NOW, MONTH, 3).unwrap();
        let noisy = format!("Our canary page:\n\n{}\n(updated monthly)\n", c.render());
        let parsed = Canary::parse(&noisy).unwrap();
        parsed.verify().unwrap();
        assert_eq!(parsed.statement, "still here");
    }

    #[test]
    fn malformed_documents_rejected() {
        assert!(Canary::parse("").is_err());
        assert!(Canary::parse("BPCANARY1\nsequence: 1").is_err());
        let c = Canary::issue(&kp(), "x", NOW, MONTH, 1).unwrap();
        let truncated = c.render().lines().take(6).collect::<Vec<_>>().join("\n");
        assert!(Canary::parse(&truncated).is_err());
    }

    #[test]
    fn empty_statement_rejected() {
        assert!(Canary::issue(&kp(), "  \n ", NOW, MONTH, 1).is_err());
    }

    #[test]
    fn timestamp_formatting_known_values() {
        assert_eq!(format_ts(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_ts(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(format_ts(951_782_400), "2000-02-29T00:00:00Z"); // leap day
        assert_eq!(format_duration(0), "0m");
        assert_eq!(format_duration(3 * 86_400 + 7_200), "3d 2h");
        assert_eq!(format_duration(5_400), "1h 30m");
    }
}
