//! The seal policy, read from git configuration.
//!
//! Everything a seal decides by policy lives here: how many TSAs must answer,
//! how long they get, what a failure means, where evidence is stored and which
//! authorities are asked. The defaults are the safe ones and are applied when a
//! key is unset; an unknown value for a key with a fixed vocabulary is an error,
//! never a silent fallback to the default, because a misspelt `on-failure=fial`
//! must not quietly become `warn`.
//!
//! [`Policy::load`] is also where the authorities are assembled: one
//! [`HttpBackend`] per configured TSA and the pinned [`AnchorStore`] for their
//! anchor bundles. Both are built here rather than by the caller so that a
//! missing anchor is caught when the policy is read, not at the first seal.
//! Load, then hand [`Policy::backends`] and [`Policy::anchors`] to
//! [`crate::seal::seal`].
//!
//! Anchors load per authority, not all-or-nothing: a bundle that cannot be read
//! or parsed leaves that authority out of the store and is recorded in
//! [`Policy::anchor_failures`], which the seal turns into a `Fail` record for
//! that id. One broken anchor must not cost the authorities that are pinned
//! correctly. Only when *no* configured authority has a usable anchor does the
//! seal refuse.
//!
//! TSA keys are `time.tsa.<id>.url`, `.anchor`, `.alg`, `.policy`, `.timeout`
//! and `.insecure-http`. The id is the text between `time.tsa.` and the last
//! dot, so an id cannot contain a dot but may contain any other character git
//! accepts. An anchor or url *key* that is missing is still an error: a
//! half-configured TSA would otherwise only fail at seal time. `alg` defaults to
//! `sha256`, `timeout` to six seconds per attempt and `insecure-http` to false.
//!
//! `.insecure-http = true` records that a plain `http://` endpoint was accepted
//! on purpose. The token is verified against the pinned anchor either way, so
//! this changes no verdict; it only makes the risk visible — one warning per
//! insecure authority while the policy is loaded, which is seal time.
//!
//! Durations accept `500ms`, `10s` and bare seconds. Relative anchor paths are
//! resolved against the repository, because the config holding them is
//! repository-local; `~/` is resolved against `HOME`.
//!
//! ```
//! # use git_time_core::policy::{Gate, OnFailure, Policy, SealDuringRebase, Store};
//! let policy = Policy::default();
//! assert_eq!(policy.required, 1);
//! assert_eq!(policy.on_failure, OnFailure::Warn);
//! assert_eq!(policy.gate, Gate::PostCommit);
//! assert_eq!(policy.store, Store::Trailer);
//! assert_eq!(policy.seal_during_rebase, SealDuringRebase::All);
//! assert!(policy.enabled);
//! assert!(policy.record_failures);
//! assert_eq!(policy.max_trailer_bytes, 65_536);
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::imprint::{Alg, Digest};
use crate::repo::{Repo, RepoError, run_git};
use crate::trust::AnchorStore;
use crate::tsa::{HttpBackend, StampRequest, TsaBackend};

/// Default of `time.deadline`: the whole fan-out gets ten seconds.
const DEFAULT_DEADLINE: Duration = Duration::from_secs(10);

/// Default of `time.tsa.<id>.timeout`: one attempt gets six seconds.
const DEFAULT_TSA_TIMEOUT: Duration = Duration::from_secs(6);

/// Default of `time.max-trailer-bytes`: 64 KiB of trailer block.
const DEFAULT_MAX_TRAILER_BYTES: usize = 65_536;

/// The prefix of every TSA config key, up to the id.
const TSA_PREFIX: &str = "time.tsa.";

/// What a failed seal means to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFailure {
    /// Print the problem and carry on; the hook still exits 0.
    Warn,
    /// Print the problem and exit 3; git ignores it, wrappers do not.
    Fail,
}

/// Where the seal runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Seal after the commit exists. Evidence is added, never missing.
    PostCommit,
    /// Probe the authorities before the commit and refuse on a short quorum.
    PreCommit,
}

/// Where the evidence goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    /// The trailer block inside the commit object. The default.
    Trailer,
    /// A note on `refs/notes/rfc3161`; the trailer keeps only the imprint.
    Note,
    /// Both of the above.
    Both,
}

/// Which commits a rebase seals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealDuringRebase {
    /// Every rewritten commit.
    All,
    /// Only the tip.
    Tip,
    /// None; the commits stay unsealed until `git time seal --range`.
    Off,
}

/// One configured timestamp authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaConfig {
    /// The identifier the trailer and the failure records use.
    pub id: String,
    /// The endpoint requests are posted to.
    pub url: String,
    /// The PEM bundle pinned for this id; its first certificate is the anchor.
    pub anchor: PathBuf,
    /// The imprint algorithm and the algorithm requests ask for.
    pub alg: Alg,
    /// The TSA policy to request, when one is configured.
    pub policy: Option<String>,
    /// Whether the endpoint was accepted as plain `http://`.
    pub insecure_http: bool,
    /// Per-attempt timeout.
    pub timeout: Duration,
}

/// How a seal behaves.
///
/// The fields are public so a caller can adjust a loaded policy (a test
/// tightening `required`, a command-line flag); construct one with
/// [`Policy::default`] and [`Policy::load`], which are the only ways to fill in
/// the built authorities.
#[derive(Clone)]
pub struct Policy {
    /// Successes the seal needs to count as sealed; `0` is best effort.
    pub required: usize,
    /// Hard bound on the whole fan-out.
    pub deadline: Duration,
    /// What a failure means to the caller.
    pub on_failure: OnFailure,
    /// Where the seal runs.
    pub gate: Gate,
    /// Where the evidence goes.
    pub store: Store,
    /// Which rebase commits are sealed.
    pub seal_during_rebase: SealDuringRebase,
    /// Whether failed TSAs leave a `Fail` line.
    pub record_failures: bool,
    /// Whether sealing happens at all.
    pub enabled: bool,
    /// Whether verification calls an unsigned commit a failure. A command-line
    /// flag (`git time verify --require-signed`), not a config key.
    pub require_signed: bool,
    /// Budget for the trailer block, in bytes.
    pub max_trailer_bytes: usize,
    /// The configured authorities, in config order.
    pub tsas: Vec<TsaConfig>,
    /// One backend per authority in `tsas`, in the same order.
    backends: Vec<Arc<dyn TsaBackend>>,
    /// The anchors pinned for `tsas`; an authority whose bundle did not load is
    /// simply absent.
    anchors: AnchorStore,
    /// Why an authority's anchor is absent from `anchors`, keyed by its id.
    anchor_failures: BTreeMap<String, String>,
}

/// The defaults are the safe configuration: one TSA, ten seconds, warn, seal
/// after the commit, trailer storage, every rebase commit, record failures,
/// enabled, 64 KiB trailer.
///
/// There are no authorities until a policy is loaded, so a seal with a default
/// policy fans out to nothing and stays under a quorum of one.
impl Default for Policy {
    fn default() -> Self {
        Self {
            required: 1,
            deadline: DEFAULT_DEADLINE,
            on_failure: OnFailure::Warn,
            gate: Gate::PostCommit,
            store: Store::Trailer,
            seal_during_rebase: SealDuringRebase::All,
            record_failures: true,
            enabled: true,
            require_signed: false,
            max_trailer_bytes: DEFAULT_MAX_TRAILER_BYTES,
            tsas: Vec::new(),
            backends: Vec::new(),
            anchors: AnchorStore::default(),
            anchor_failures: BTreeMap::new(),
        }
    }
}

impl std::fmt::Debug for Policy {
    /// The backends are trait objects and not `Debug`; the count is what a
    /// reader needs from them.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("required", &self.required)
            .field("deadline", &self.deadline)
            .field("on_failure", &self.on_failure)
            .field("gate", &self.gate)
            .field("store", &self.store)
            .field("seal_during_rebase", &self.seal_during_rebase)
            .field("record_failures", &self.record_failures)
            .field("enabled", &self.enabled)
            .field("require_signed", &self.require_signed)
            .field("max_trailer_bytes", &self.max_trailer_bytes)
            .field("tsas", &self.tsas)
            .field("backends", &self.backends.len())
            .field("anchor_failures", &self.anchor_failures)
            .finish_non_exhaustive()
    }
}

impl Policy {
    /// Read the policy of `repo` from git configuration.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for a config that cannot be read, a value outside its
    /// key's vocabulary, a TSA without url or anchor, or a malformed policy OID.
    /// An anchor bundle that does not load is *not* an error: it is recorded in
    /// [`Policy::anchor_failures`] and only that authority is left unpinned.
    pub fn load(repo: &Repo) -> Result<Self, ConfigError> {
        let mut policy = Self::default();

        if let Some(value) = repo.config_non_empty("time.required")? {
            policy.required = parse(&value, "time.required", "a whole number")?;
        }
        if let Some(value) = repo.config_non_empty("time.deadline")? {
            policy.deadline = parse_duration(&value, "time.deadline")?;
        }
        if let Some(value) = repo.config_non_empty("time.on-failure")? {
            policy.on_failure = parse_enum(
                &value,
                "time.on-failure",
                "`warn` or `fail`",
                &[("warn", OnFailure::Warn), ("fail", OnFailure::Fail)],
            )?;
        }
        if let Some(value) = repo.config_non_empty("time.gate")? {
            policy.gate = parse_enum(
                &value,
                "time.gate",
                "`post-commit` or `pre-commit`",
                &[
                    ("post-commit", Gate::PostCommit),
                    ("pre-commit", Gate::PreCommit),
                ],
            )?;
        }
        if let Some(value) = repo.config_non_empty("time.store")? {
            policy.store = parse_enum(
                &value,
                "time.store",
                "`trailer`, `note` or `both`",
                &[
                    ("trailer", Store::Trailer),
                    ("note", Store::Note),
                    ("both", Store::Both),
                ],
            )?;
        }
        if let Some(value) = repo.config_non_empty("time.seal-during-rebase")? {
            policy.seal_during_rebase = parse_enum(
                &value,
                "time.seal-during-rebase",
                "`all`, `tip` or `off`",
                &[
                    ("all", SealDuringRebase::All),
                    ("tip", SealDuringRebase::Tip),
                    ("off", SealDuringRebase::Off),
                ],
            )?;
        }
        if let Some(value) = repo.config_non_empty("time.record-failures")? {
            policy.record_failures = parse_bool(&value, "time.record-failures")?;
        }
        if let Some(value) = repo.config_non_empty("time.enabled")? {
            policy.enabled = parse_bool(&value, "time.enabled")?;
        }
        if let Some(value) = repo.config_non_empty("time.max-trailer-bytes")? {
            policy.max_trailer_bytes = parse(&value, "time.max-trailer-bytes", "a whole number")?;
        }

        policy.tsas = read_tsas(repo)?;
        // Every authority that travels in the clear, for the one warning below.
        let mut insecure: Vec<&TsaConfig> = Vec::new();
        for tsa in &policy.tsas {
            policy.backends.push(Arc::new(HttpBackend {
                id: tsa.id.clone(),
                url: tsa.url.clone(),
                timeout: tsa.timeout,
            }));
            // The transport is not what makes a token evidence, but a reader
            // deserves to know the imprint travelled in the clear.
            if tsa.insecure_http {
                insecure.push(tsa);
            }
            // One bundle at a time: a missing or unparseable anchor belongs to
            // its own authority and must not take the pinned ones down with it.
            let path = resolve_anchor(repo, &tsa.anchor);
            if let Err(error) = policy.anchors.insert(&tsa.id, &path) {
                policy
                    .anchor_failures
                    .insert(tsa.id.clone(), error.to_string());
            }
        }
        // One line, not one per authority: with many authorities a per-authority
        // warning would bury the seal output. Said here, where the backends are
        // built — that is, at seal time. Five ids are named, the rest counted.
        if !insecure.is_empty() {
            const NAMED: usize = 5;
            let shown: Vec<&str> = insecure
                .iter()
                .take(NAMED)
                .map(|tsa| tsa.id.as_str())
                .collect();
            let mut list = shown.join(", ");
            if insecure.len() > shown.len() {
                list.push_str(&format!(", and {} more", insecure.len() - shown.len()));
            }
            eprintln!(
                "rfc3161: warning: {} {} plain http ({}); integrity is still verified, \
                 transport is not",
                insecure.len(),
                if insecure.len() == 1 {
                    "authority uses"
                } else {
                    "authorities use"
                },
                list
            );
        }
        Ok(policy)
    }

    /// The one backend per configured TSA, in config order.
    #[must_use]
    pub fn backends(&self) -> &[Arc<dyn TsaBackend>] {
        &self.backends
    }

    /// The anchors pinned for the configured TSAs.
    #[must_use]
    pub fn anchors(&self) -> &AnchorStore {
        &self.anchors
    }

    /// Why `id`'s anchor is not pinned, when it failed to load.
    #[must_use]
    pub fn anchor_failure(&self, id: &str) -> Option<&str> {
        self.anchor_failures.get(id).map(String::as_str)
    }

    /// The configured TSA with `id`, if any.
    #[must_use]
    pub fn tsa(&self, id: &str) -> Option<&TsaConfig> {
        self.tsas.iter().find(|tsa| tsa.id == id)
    }
}

/// The raw fields of one `time.tsa.<id>` section.
#[derive(Default)]
struct TsaFields {
    url: Option<String>,
    anchor: Option<String>,
    alg: Option<String>,
    policy: Option<String>,
    insecure_http: Option<String>,
    timeout: Option<String>,
}

/// Read every `time.tsa.<id>.<field>` key, in id order.
fn read_tsas(repo: &Repo) -> Result<Vec<TsaConfig>, ConfigError> {
    let args = ["config", "--get-regexp", "^time\\.tsa\\."];
    let run = run_git(repo.path(), &args, None)?;
    let listing = match run.code {
        // No `time.tsa.*` key at all.
        Some(1) => String::new(),
        Some(0) => String::from_utf8_lossy(&run.stdout).into_owned(),
        _ => {
            return Err(ConfigError::Repo(RepoError::Git {
                command: args.join(" "),
                stderr: run.stderr,
            }));
        }
    };

    let mut sections: Vec<(String, TsaFields)> = Vec::new();
    for line in listing.lines() {
        let Some(key) = line.split(' ').next() else {
            continue;
        };
        let Some(rest) = key.strip_prefix(TSA_PREFIX) else {
            continue;
        };
        let Some((id, field)) = rest.rsplit_once('.') else {
            continue;
        };
        let value = line
            .split_once(' ')
            .map(|(_, value)| value.trim().to_owned())
            .unwrap_or_default();

        let index = match sections.iter().position(|(seen, _)| seen == id) {
            Some(index) => index,
            None => {
                sections.push((id.to_owned(), TsaFields::default()));
                sections.len() - 1
            }
        };
        let fields = &mut sections[index].1;
        let slot = match field {
            "url" => &mut fields.url,
            "anchor" => &mut fields.anchor,
            "alg" => &mut fields.alg,
            "policy" => &mut fields.policy,
            "insecure-http" => &mut fields.insecure_http,
            "timeout" => &mut fields.timeout,
            // Unknown fields are left alone, so a newer writer's key does not
            // stop an older reader.
            _ => continue,
        };
        *slot = Some(value);
    }

    let mut tsas = Vec::with_capacity(sections.len());
    for (id, fields) in sections {
        let Some(url) = fields.url.filter(|url| !url.is_empty()) else {
            return Err(ConfigError::Missing { id, what: "url" });
        };
        let Some(anchor) = fields.anchor.filter(|anchor| !anchor.is_empty()) else {
            return Err(ConfigError::Missing { id, what: "anchor" });
        };
        let alg = match fields.alg.as_deref().filter(|alg| !alg.is_empty()) {
            None => Alg::Sha256,
            Some(name) => name.parse().map_err(|_| ConfigError::Invalid {
                key: format!("{TSA_PREFIX}{id}.alg"),
                value: name.to_owned(),
                expected: "`sha256` or `sha512`",
            })?,
        };
        let policy = fields.policy.filter(|policy| !policy.is_empty());
        if let Some(policy) = &policy {
            let key = format!("{TSA_PREFIX}{id}.policy");
            // The request builder is the one authority on what a policy may be.
            let probe = Digest {
                alg,
                bytes: vec![0; alg.digest_len()],
            };
            StampRequest::new(probe, &mut rand::rng())
                .and_then(|request| request.with_policy(Some(policy.clone())))
                .map_err(|_| ConfigError::Invalid {
                    key,
                    value: policy.clone(),
                    expected: "a dotted-decimal OID",
                })?;
        }
        let timeout = match fields.timeout.as_deref().filter(|value| !value.is_empty()) {
            None => DEFAULT_TSA_TIMEOUT,
            Some(value) => parse_duration(value, &format!("{TSA_PREFIX}{id}.timeout"))?,
        };
        let insecure_http = match fields
            .insecure_http
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            None => false,
            Some(value) => parse_bool(value, &format!("{TSA_PREFIX}{id}.insecure-http"))?,
        };
        tsas.push(TsaConfig {
            id,
            url,
            anchor: PathBuf::from(anchor),
            alg,
            policy,
            insecure_http,
            timeout,
        });
    }
    Ok(tsas)
}

/// Resolve `path` as configured: `~/` against `HOME`, a relative path against
/// the repository, an absolute path as given.
fn resolve_anchor(repo: &Repo, path: &PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
        return path.clone();
    }
    if path.is_relative() {
        return repo.path().join(path);
    }
    path.clone()
}

fn parse<T: std::str::FromStr>(
    value: &str,
    key: &str,
    expected: &'static str,
) -> Result<T, ConfigError> {
    value.parse().map_err(|_| ConfigError::Invalid {
        key: key.to_owned(),
        value: value.to_owned(),
        expected,
    })
}

fn parse_enum<T: Copy>(
    value: &str,
    key: &str,
    expected: &'static str,
    values: &[(&str, T)],
) -> Result<T, ConfigError> {
    let lowered = value.to_ascii_lowercase();
    values
        .iter()
        .find(|(name, _)| *name == lowered)
        .map(|(_, value)| *value)
        .ok_or_else(|| ConfigError::Invalid {
            key: key.to_owned(),
            value: value.to_owned(),
            expected,
        })
}

/// Parse a git boolean, the spelling `insecure-http` is written in.
///
/// Public because a surface that shows a value without loading the whole policy
/// — the authority rows — must accept exactly the spellings a load accepts; an
/// invalid value is an error here, as it is in [`Policy::load`].
pub fn parse_bool(value: &str, key: &str) -> Result<bool, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(ConfigError::Invalid {
            key: key.to_owned(),
            value: value.to_owned(),
            expected: "`true` or `false`",
        }),
    }
}

/// Parse a duration: `<n>ms`, `<n>s`, `<n>m`, or a bare number of seconds.
///
/// No fractional values: the shortest deadline is a millisecond, and a decimal
/// point would only invite `1.5s` to be read as 1 s.
fn parse_duration(value: &str, key: &str) -> Result<Duration, ConfigError> {
    let invalid = || ConfigError::Invalid {
        key: key.to_owned(),
        value: value.to_owned(),
        expected: "a duration such as `10s`, `500ms` or bare seconds",
    };
    let (digits, millis) = if let Some(digits) = value.strip_suffix("ms") {
        (digits, 1)
    } else if let Some(digits) = value.strip_suffix('s') {
        (digits, 1_000)
    } else if let Some(digits) = value.strip_suffix('m') {
        (digits, 60_000)
    } else {
        (value, 1_000)
    };
    let count: u64 = digits.parse().map_err(|_| invalid())?;
    count
        .checked_mul(millis)
        .map(Duration::from_millis)
        .ok_or_else(invalid)
}

/// Why a policy could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration could not be queried.
    #[error(transparent)]
    Repo(#[from] RepoError),
    /// A value is outside its key's vocabulary.
    #[error("`{key} = {value:?}` is invalid: expected {expected}")]
    Invalid {
        /// The offending key.
        key: String,
        /// Its value.
        value: String,
        /// What the key accepts.
        expected: &'static str,
    },
    /// A TSA section lacks a required field.
    #[error("TSA `{id}` has no `{what}`")]
    Missing {
        /// The offending TSA id.
        id: String,
        /// The absent field.
        what: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_accept_ms_s_bare_and_minutes() {
        assert_eq!(
            parse_duration("500ms", "k").ok(),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            parse_duration("10s", "k").ok(),
            Some(Duration::from_secs(10))
        );
        assert_eq!(parse_duration("2", "k").ok(), Some(Duration::from_secs(2)));
        assert_eq!(
            parse_duration("3m", "k").ok(),
            Some(Duration::from_secs(180))
        );
        assert_eq!(parse_duration("0", "k").ok(), Some(Duration::ZERO));
    }

    #[test]
    fn durations_reject_fractions_junk_and_overflow() {
        assert!(parse_duration("1.5s", "k").is_err());
        assert!(parse_duration("ten", "k").is_err());
        assert!(parse_duration("s", "k").is_err());
        assert!(parse_duration("-1s", "k").is_err());
        assert!(parse_duration("18446744073709551615m", "k").is_err());
    }

    #[test]
    fn bools_accept_the_git_spellings_and_reject_others() {
        for yes in ["true", "yes", "on", "1", "TRUE"] {
            assert_eq!(parse_bool(yes, "k").ok(), Some(true), "{yes}");
        }
        for no in ["false", "no", "off", "0"] {
            assert_eq!(parse_bool(no, "k").ok(), Some(false), "{no}");
        }
        assert!(parse_bool("maybe", "k").is_err());
    }

    #[test]
    fn enums_are_matched_without_case_and_fail_closed() {
        let values = [("warn", OnFailure::Warn), ("fail", OnFailure::Fail)];
        assert_eq!(
            parse_enum("FAIL", "k", "`warn` or `fail`", &values).ok(),
            Some(OnFailure::Fail)
        );
        assert!(parse_enum("fial", "k", "`warn` or `fail`", &values).is_err());
    }
}
