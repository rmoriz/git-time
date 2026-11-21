//! Anchor bundles: where they live, how they are fetched, and how doctor names
//! them. The listings here also carry each root's `notAfter` with an `expired`
//! or soon marker, because a rotation is only noticed where the choice is made.
//!
//! An anchor is only useful once it is pinned locally, so a preset
//! public` writes one bundle per authority and prints its SHA-256 fingerprint for
//! a reader to compare against the authority's published value. A failed fetch is
//! a warning, not an install failure: hooks are still worth wiring and `doctor`
//! will name the missing bundle.
//!
//! The fetch is replaceable. `GIT_TIME_ANCHOR_FETCH_CMD` is run through `sh -c`
//! with `GIT_TIME_ANCHOR_URL` set to the URL, and its stdout is the bundle; tests
//! use this instead of the network. Without it a GET is tried first and its body
//! is taken when it carries a PEM certificate; otherwise the URL is asked for a
//! token and the anchor is the self-signed root of a genuine reply. That covers
//! the two shapes an authority publishes in: a certificate download, and a
//! timestamp endpoint that answers a GET with prose or with 405/403 — several do
//! the latter, and taking that for a failure abandoned the working POST.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use git_time_core::imprint::{Alg, Digest};
use git_time_core::presets::Preset;
use git_time_core::repo::Repo;
use git_time_core::tsa::backend::USER_AGENT;
use git_time_core::tsa::{StampRequest, encode, parse_response};
use x509_cert::Certificate;
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
use x509_cert::ext::pkix::name::GeneralName;

use crate::cmd::Exit;

/// How long one anchor fetch may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The config directory itself, `$XDG_CONFIG_HOME` or `~/.config`, with no
/// leaf. Both state directories join it, so they cannot drift apart.
#[must_use]
pub fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"))
}

/// The directory anchor bundles are pinned in: `$XDG_CONFIG_HOME` when set,
/// `~/.config` otherwise.
#[must_use]
pub fn dir() -> PathBuf {
    config_home().join("git-time").join("anchors")
}

/// The bundle path of `id`: `configured` when the repository named one, else the
/// default `dir()/<id>.pem` that `install` writes.
///
/// A freshly fetched bundle written anywhere else would print a fingerprint of a
/// file the policy never reads, so every reader and writer resolves through this
/// one expression.
fn path_for(configured: Option<&Path>, id: &str) -> PathBuf {
    configured.map_or_else(|| dir().join(format!("{id}.pem")), Path::to_path_buf)
}

/// The bundle path for `preset`, from its own configured `anchor`.
#[must_use]
pub fn bundle_path(preset: &Preset) -> PathBuf {
    path_for(preset.anchor_path, preset.name)
}

/// The lowercase hex SHA-256 fingerprint of `bytes`.
///
/// The pins and the lock spell it as one lowercase token; the preset comparison
/// needs the certificate form ([`git_time_core::trust::fingerprint`]), so the
/// digest lives there and this only rewrites its spelling.
#[must_use]
pub fn fingerprint(bytes: &[u8]) -> String {
    git_time_core::trust::fingerprint(bytes)
        .replace(':', "")
        .to_ascii_lowercase()
}

/// The `notAfter` of `certificate` as `YYYY-MM-DD`.
///
/// The ASN.1 value renders as an RFC 3339 instant; a listing has room for the
/// day alone, and the day is what a reader holds against their calendar.
#[must_use]
pub fn not_after(certificate: &Certificate) -> String {
    certificate
        .tbs_certificate
        .validity
        .not_after
        .to_string()
        .chars()
        .take(10)
        .collect()
}

/// How many days before `notAfter` a date is called soon: a rotation is not
/// noticed in the last week, so the warning starts well ahead of it.
const EXPIRY_SOON: i64 = 90;

/// The verdict on the date `not_after` at `now`: `"expired"` once `now` is past
/// it, `"(expires soon)"` within [`EXPIRY_SOON`] days, nothing otherwise.
///
/// Being a pure function of `now` keeps the clock rewindable in a test without
/// minting an old certificate. An unparsable date has no verdict.
#[must_use]
pub fn expiry_label(not_after: &str, now: jiff::Timestamp) -> &'static str {
    let Ok(date) = not_after.parse::<jiff::civil::Date>() else {
        return "";
    };
    // Midnight UTC of the day: a root that expires at any hour of it is past
    // as soon as the day is.
    let Ok(expires) = date.at(0, 0, 0, 0).to_zoned(jiff::tz::TimeZone::UTC) else {
        return "";
    };
    let expires = expires.timestamp();
    if now > expires {
        return "expired";
    }
    if expires.as_second() - now.as_second() <= EXPIRY_SOON * 86_400 {
        return "(expires soon)";
    }
    ""
}

/// Whether the date `not_after` is already past at `now`.
#[must_use]
pub fn expired(not_after: &str, now: jiff::Timestamp) -> bool {
    expiry_label(not_after, now) == "expired"
}

/// The date for a listing, with its verdict when there is one.
///
/// The space is only there when something follows it, so a quiet line does not
/// end in a blank.
#[must_use]
pub fn expiry_text(not_after: &str, now: jiff::Timestamp) -> String {
    match expiry_label(not_after, now) {
        "" => not_after.to_owned(),
        label => format!("{not_after} {label}"),
    }
}

/// One root of a pinned bundle, as the listings show it.
#[derive(Debug, Clone)]
pub struct RootRow {
    /// The SHA-256 fingerprint of the root.
    pub fingerprint: String,
    /// Its `notAfter` as `YYYY-MM-DD`.
    pub not_after: String,
}

/// The roots of the bundle at `path`, in file order.
///
/// `None` when the bundle is missing, unparseable or holds no root, so a
/// listing says `-` instead of inventing a date.
#[must_use]
pub fn roots(path: &Path) -> Option<Vec<RootRow>> {
    let roots = crate::cmd::anchor::root_certificates(path)?;
    let mut rows = Vec::with_capacity(roots.len());
    for der in roots {
        let certificate = Certificate::from_der(&der).ok()?;
        rows.push(RootRow {
            fingerprint: fingerprint(&der),
            not_after: not_after(&certificate),
        });
    }
    Some(rows)
}

/// Fetch the bundle at `url`.
///
/// A GET is tried first: when it answers 2xx with a certificate — PEM, DER or a
/// PKCS#7 collection, which is what a CA's download path serves — that body is
/// the bundle and no token is requested. Every other outcome — a non-2xx status,
/// a body that holds no certificate (a timestamp endpoint answers a GET with
/// prose), or a transport error — falls through to [`root_from_endpoint`], and if
/// that fails too the error names both attempts.
///
/// # Errors
///
/// The reason both attempts failed: the stub command failed, neither the GET nor
/// the POST produced something, the reply carried no certificate, or the endpoint
/// answered a timestamp reply without a self-signed root.
pub async fn fetch(url: &str) -> Result<Vec<u8>, String> {
    if let Some(command) = std::env::var_os("GIT_TIME_ANCHOR_FETCH_CMD") {
        return run_stub(&command, url);
    }

    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|error| format!("cannot build the HTTP client: {error}"))?;
    let mut get_error = None;
    match client.get(url).send().await {
        Ok(response) if response.status().is_success() => {
            match response.bytes().await {
                // A certificate download: whatever the encoding, the body is the
                // whole bundle.
                Ok(body) => {
                    if let Some(bundle) = bundle_from(&body) {
                        return Ok(bundle);
                    }
                }
                Err(error) => get_error = Some(format!("reading {url} failed: {error}")),
            }
        }
        Ok(response) => get_error = Some(format!("GET {url} answered {}", response.status())),
        Err(error) => get_error = Some(format!("GET {url} failed: {error}")),
    }
    root_from_endpoint(&client, url)
        .await
        .map_err(|error| match get_error {
            Some(get_error) => format!("{get_error}; {error}"),
            None => error,
        })
}

/// Fetch the bundle of `url`, then append the certificates of `chain`.
///
/// A handful of replies stop below the root and name no `caIssuers` to walk
/// (the Portuguese state PKI embeds the signing leaf alone), so the preset names
/// the issuer publication as well. The appended certificates are only the path:
/// what is trusted is still the root the pin is checked against.
///
/// # Errors
///
/// [`fetch`]'s reason for the bundle, or the failing URL for a chain member.
pub async fn fetch_chain(url: &str, chain: &[&str]) -> Result<Vec<u8>, String> {
    let mut bundle = fetch(url).await?;
    for extra in chain {
        let more = fetch(extra)
            .await
            .map_err(|error| format!("fetching the chain member {extra}: {error}"))?;
        bundle.extend(more);
    }
    Ok(bundle)
}

/// Run the `GIT_TIME_ANCHOR_FETCH_CMD` stub for `url`.
fn run_stub(command: &std::ffi::OsStr, url: &str) -> Result<Vec<u8>, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("GIT_TIME_ANCHOR_URL", url)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("cannot run the fetch command: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if stderr.is_empty() {
            format!("the fetch command exited with {}", output.status)
        } else {
            stderr
        });
    }
    // The bytes are handed back as they are: whether they are certificates is
    // decided by parsing them where they are about to be pinned, so a prose
    // answer can be named as unparseable instead of as a failed fetch.
    Ok(output.stdout)
}

/// `bytes` as a PEM bundle, when they hold certificates at all.
///
/// A download is often DER — Belgium publishes its root that way, the Portuguese
/// state PKI its whole hierarchy — and the bundle format is PEM, so the body is
/// re-encoded rather than handed on verbatim.
fn bundle_from(bytes: &[u8]) -> Option<Vec<u8>> {
    let certificates = parse_certificates(bytes);
    if certificates.is_empty() {
        return None;
    }
    let mut pem = Vec::new();
    for certificate in certificates {
        pem.extend(pem_block(&certificate.to_der().ok()?));
    }
    Some(pem)
}

/// POST a timestamp query to `url` and return the anchor its reply names.
///
/// A reply is a token, not a bundle: the anchor is the self-signed root of the
/// chain it carries, or the root the top certificate's `caIssuers` leads to.
async fn root_from_endpoint(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let mut rng = rand::rng();
    let digest = Digest {
        alg: Alg::Sha256,
        bytes: vec![0x5a; Alg::Sha256.digest_len()],
    };
    let request = StampRequest::new(digest, &mut rng).map_err(|error| error.to_string())?;
    let body = encode(&request);
    let response = client
        .post(url)
        .header("content-type", "application/timestamp-query")
        .body(body)
        .send()
        .await
        .map_err(|error| format!("POST {url} failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("POST {url} answered {}", response.status()));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("reading the reply of {url} failed: {error}"))?;
    let token = match parse_response(&bytes) {
        Ok(git_time_core::tsa::RawResponse::Granted { token, .. }) => token,
        Ok(git_time_core::tsa::RawResponse::Rejected { status, text }) => {
            return Err(format!(
                "{url} rejected the query with status {status}: {}",
                text.unwrap_or_default()
            ));
        }
        Err(error) => return Err(format!("{url} answered no timestamp: {error}")),
    };
    root_pem(client, &token).await
}

/// The PEM of `token`'s root, then the other certificates of its chain.
async fn root_pem(client: &reqwest::Client, token: &[u8]) -> Result<Vec<u8>, String> {
    let (root, others) = resolve_root(client, token_certificates(token)?).await?;
    let mut pem = pem_block(&root.to_der().map_err(|error| error.to_string())?);
    for other in others {
        pem.extend(pem_block(
            &other.to_der().map_err(|error| error.to_string())?,
        ));
    }
    Ok(pem)
}

/// Every certificate the CMS token `token` carries.
fn token_certificates(token: &[u8]) -> Result<Vec<Certificate>, String> {
    const OID_SIGNED_DATA: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    let content =
        ContentInfo::from_der(token).map_err(|error| format!("the token is not CMS: {error}"))?;
    if content.content_type != OID_SIGNED_DATA {
        return Err("the token is not SignedData".to_owned());
    }
    let signed_data_der = content
        .content
        .to_der()
        .map_err(|error| format!("the token is not SignedData: {error}"))?;
    let signed = SignedData::from_der(&signed_data_der)
        .map_err(|error| format!("the token is not SignedData: {error}"))?;
    let Some(certificates) = signed.certificates else {
        return Err("the reply carries no certificate".to_owned());
    };

    let certificates: Vec<Certificate> = certificates
        .0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => Some(certificate.clone()),
            _ => None,
        })
        .collect();
    if certificates.is_empty() {
        return Err("the reply carries no certificate".to_owned());
    }
    Ok(certificates)
}

/// The self-signed certificate in `pool`, walking `caIssuers` to find it.
///
/// Many authorities put only leaf and intermediates in the token: their root is
/// published at the AIA URL the top certificate names, and that is where the
/// fingerprint this project pins was read from. Walking stays bounded — a few
/// hops, and only certificates that are not already in the pool count — and
/// every fetched certificate still only becomes the anchor if the preset's
/// fingerprint check accepts it (see `install_anchor`).
async fn resolve_root(
    client: &reqwest::Client,
    mut pool: Vec<Certificate>,
) -> Result<(Certificate, Vec<Certificate>), String> {
    /// How many `caIssuers` hops one reply may take.
    const MAX_HOPS: usize = 4;

    let mut errors: Vec<String> = Vec::new();
    for _ in 0..MAX_HOPS {
        if let Some(index) = pool.iter().position(|certificate| {
            certificate.tbs_certificate.subject == certificate.tbs_certificate.issuer
        }) {
            let root = pool.remove(index);
            return Ok((root, pool));
        }
        // Prefer the certificates nobody in the pool claims to have issued, but
        // take `caIssuers` from anywhere: several authorities publish the
        // pointer on the leaf alone, and it still names the way up.
        let mut ordered: Vec<&Certificate> = pool
            .iter()
            .filter(|candidate| !issued_in(&pool, candidate))
            .collect();
        ordered.extend(pool.iter().filter(|candidate| issued_in(&pool, candidate)));

        let mut urls: Vec<String> = Vec::new();
        for candidate in ordered {
            for url in ca_issuers(candidate) {
                if !urls.contains(&url) {
                    urls.push(url);
                }
            }
        }
        if urls.is_empty() {
            break;
        }

        let mut fetched = Vec::new();
        for url in urls {
            match certificates_at(client, &url).await {
                Ok(certificates) => {
                    fetched = certificates;
                    break;
                }
                Err(error) => errors.push(error),
            }
        }
        if fetched.is_empty() {
            break;
        }
        for certificate in fetched {
            let known = pool.iter().any(|other| {
                other.tbs_certificate.subject == certificate.tbs_certificate.subject
                    && other.tbs_certificate.serial_number
                        == certificate.tbs_certificate.serial_number
            });
            if !known {
                pool.push(certificate);
            }
        }
    }

    Err(if errors.is_empty() {
        "the reply carries no self-signed root and names no caIssuers to walk".to_owned()
    } else {
        format!(
            "the reply carries no self-signed root and its caIssuers could not be read: {}",
            errors.join("; ")
        )
    })
}

/// Whether any certificate in `pool` names `candidate`'s issuer as its subject.
fn issued_in(pool: &[Certificate], candidate: &Certificate) -> bool {
    pool.iter()
        .any(|other| other.tbs_certificate.subject == candidate.tbs_certificate.issuer)
}

/// The `caIssuers` URLs `certificate` publishes, in the order it lists them.
fn ca_issuers(certificate: &Certificate) -> Vec<String> {
    const OID_AIA: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
    const OID_CA_ISSUERS: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");

    certificate
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|extension| extension.extn_id == OID_AIA)
        .and_then(|extension| {
            AuthorityInfoAccessSyntax::from_der(extension.extn_value.as_bytes()).ok()
        })
        .map(|access| {
            access
                .0
                .into_iter()
                .filter(|description| description.access_method == OID_CA_ISSUERS)
                .filter_map(|description| match description.access_location {
                    GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Fetch one AIA target and parse it as a certificate collection.
async fn certificates_at(client: &reqwest::Client, url: &str) -> Result<Vec<Certificate>, String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(format!("{url} is not an http URL"));
    }
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("GET {url} failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("GET {url} answered {}", response.status()));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("reading {url} failed: {error}"))?;

    let certificates = parse_certificates(&bytes);
    if certificates.is_empty() {
        return Err(format!("{url} carried no certificate"));
    }
    Ok(certificates)
}

/// The certificates in `bytes`: a single DER certificate, a PKCS#7 collection,
/// or any number of PEM blocks.
pub(crate) fn parse_certificates(bytes: &[u8]) -> Vec<Certificate> {
    if let Ok(certificate) = Certificate::from_der(bytes) {
        return vec![certificate];
    }
    if let Ok(content) = ContentInfo::from_der(bytes)
        && let Ok(content_der) = content.content.to_der()
        && let Ok(signed) = SignedData::from_der(&content_der)
        && let Some(certificates) = signed.certificates
    {
        let found: Vec<Certificate> = certificates
            .0
            .iter()
            .filter_map(|choice| match choice {
                CertificateChoices::Certificate(certificate) => Some(certificate.clone()),
                _ => None,
            })
            .collect();
        if !found.is_empty() {
            return found;
        }
    }

    let text = String::from_utf8_lossy(bytes);
    let mut found = Vec::new();
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            inside = true;
            body.clear();
            continue;
        }
        if line == "-----END CERTIFICATE-----" {
            if inside
                && let Ok(der) = BASE64.decode(body.as_bytes())
                && let Ok(certificate) = Certificate::from_der(&der)
            {
                found.push(certificate);
            }
            inside = false;
            continue;
        }
        if inside {
            body.push_str(line);
        }
    }
    found
}

/// `der` as one PEM certificate block.
pub(crate) fn pem_block(der: &[u8]) -> Vec<u8> {
    let encoded = BASE64.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out.into_bytes()
}

/// Every TSA id configured under `time.tsa.<id>.url` or `time.tsa.<id>.anchor`,
/// in id order. An `anchor`-key-only section is still locked, so a lock written
/// before the key was dropped does not start reporting drift.
pub fn tsa_ids(repo: &Repo) -> Result<Vec<String>, Exit> {
    let mut ids = Vec::new();
    for (key, _value) in listing(repo)? {
        let Some(rest) = key.strip_prefix("time.tsa.") else {
            continue;
        };
        let Some((id, field)) = rest.rsplit_once('.') else {
            continue;
        };
        if matches!(field, "url" | "anchor") && !ids.iter().any(|seen: &String| seen == id) {
            ids.push(id.to_owned());
        }
    }
    ids.sort();
    Ok(ids)
}

/// The `key value` pairs of every `time.tsa.*` key.
///
/// `tsa::rows` reads the sections through this, so every reader works off the
/// same list and the section fields are parsed in one place.
pub(crate) fn listing(repo: &Repo) -> Result<Vec<(String, String)>, Exit> {
    let listing = match crate::cmd::git_stdout(repo, &["config", "--get-regexp", "^time\\.tsa\\."])
    {
        Ok(listing) => listing,
        // git exits 1 for "no match"; `git_stdout` reports that as usage.
        Err(exit) if exit.code() == 2 => String::new(),
        Err(exit) => return Err(exit),
    };
    Ok(listing
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(key, value)| (key.to_owned(), value.trim().to_owned()))
        .collect())
}

/// A configured anchor, as doctor reads it.
pub struct Configured {
    /// The TSA id the anchor belongs to.
    pub id: String,
    /// The path exactly as configured.
    pub configured: PathBuf,
    /// The path resolved the way `Policy::load` resolves it.
    pub path: PathBuf,
}

/// Every `time.tsa.<id>.anchor` of `repo`, in id order.
///
/// Read without `Policy::load`, which resolves the same paths but swallows a
/// bundle that does not load into `Policy::anchor_failures`; doctor has to name
/// that anchor, and `install` has to write to it.
pub fn configured(repo: &Repo) -> Result<Vec<Configured>, Exit> {
    let mut anchors = Vec::new();
    for (key, value) in listing(repo)? {
        let Some(rest) = key.strip_prefix("time.tsa.") else {
            continue;
        };
        let Some((id, field)) = rest.rsplit_once('.') else {
            continue;
        };
        if field != "anchor" || value.is_empty() {
            continue;
        }
        let configured = PathBuf::from(&value);
        anchors.push(Configured {
            id: id.to_owned(),
            path: resolve(repo, &configured),
            configured,
        });
    }
    anchors.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(anchors)
}

/// Where `id`'s bundle is written: the configured `time.tsa.<id>.anchor` path
/// when there is one, the default `dir()/<id>.pem` otherwise.
///
/// A freshly fetched bundle written anywhere else would print a fingerprint of
/// a file the policy never reads, so every writer resolves through this.
pub fn target(repo: &Repo, id: &str) -> Result<PathBuf, Exit> {
    let configured = configured(repo)?
        .into_iter()
        .find(|anchor| anchor.id == id)
        .map(|anchor| anchor.path);
    Ok(path_for(configured.as_deref(), id))
}

/// Whether the repository has any `time.tsa.*` key, whatever the id.
pub fn any_section(repo: &Repo) -> Result<bool, Exit> {
    Ok(listing(repo)?
        .iter()
        .any(|(key, _)| key.starts_with("time.tsa.")))
}

/// Whether `time.tsa.<id>` has any key at all in the local config.
///
/// The section is checked, not its `url`: a hand-edited or half-written section
/// may hold an `anchor` or `policy` without a `url`, and merging into it would
/// silently keep those stale values.
pub fn section_exists(repo: &Repo, id: &str) -> Result<bool, Exit> {
    match crate::cmd::git_stdout(
        repo,
        &[
            "config",
            "--local",
            "--get-regexp",
            &format!("^time\\.tsa\\.{id}\\."),
        ],
    ) {
        Ok(listing) => Ok(!listing.trim().is_empty()),
        // git exits 1 for "no match"; `git_stdout` reports that as usage.
        Err(exit) if exit.code() == 2 => Ok(false),
        Err(exit) => Err(exit),
    }
}

/// Resolve an anchor path like the policy does: `~/` against `HOME`, a relative
/// path against the repository, an absolute path as given.
pub fn resolve(repo: &Repo, path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    if path.is_relative() {
        return repo.path().join(path);
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use git_time_core::tsa::RawResponse;

    /// A captured granted reply: the extraction must put the self-signed root
    /// first, as the anchor bundle format requires. Offline, from a fixture.
    #[test]
    fn the_chain_root_is_extracted_first() {
        let response =
            include_bytes!("../../../git-time-core/tests/fixtures/resp_granted_freetsa.tsr");
        let RawResponse::Granted { token, .. } =
            parse_response(response).expect("a granted fixture")
        else {
            panic!("the fixture is not granted");
        };
        let pem = String::from_utf8(
            runtime()
                .block_on(root_pem(&client(), &token))
                .expect("a root"),
        )
        .expect("PEM is text");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));

        let first = pem
            .split_once("-----\n")
            .and_then(|(_, rest)| rest.split_once("\n-----END"))
            .map(|(body, _)| body.replace('\n', ""))
            .expect("a first block");
        let der = BASE64.decode(first).expect("base64");
        let certificate = x509_cert::Certificate::from_der(&der).expect("a certificate");
        assert_eq!(
            certificate.tbs_certificate.subject, certificate.tbs_certificate.issuer,
            "the first certificate is the self-signed root"
        );
    }

    /// Midnight UTC of `year-month-day`, as the display sites take their `now`.
    fn at(year: i16, month: i8, day: i8) -> jiff::Timestamp {
        jiff::civil::date(year, month, day)
            .at(0, 0, 0, 0)
            .to_zoned(jiff::tz::TimeZone::UTC)
            .expect("an instant")
            .timestamp()
    }

    #[test]
    fn a_date_before_now_is_expired() {
        assert_eq!(expiry_label("2025-12-31", at(2026, 1, 1)), "expired");
        // The expiration day itself is past at its own midnight.
        assert_eq!(expiry_label("2026-01-01", at(2026, 1, 1)), "(expires soon)");
    }

    /// The space is only the separator of a label: a quiet date is not padded.
    #[test]
    fn expiry_text_spaces_only_when_a_label_follows() {
        assert_eq!(
            expiry_text("2020-02-01", at(2026, 1, 1)),
            "2020-02-01 expired"
        );
        assert_eq!(expiry_text("2030-01-01", at(2026, 1, 1)), "2030-01-01");
    }

    #[test]
    fn eighty_nine_days_out_is_soon() {
        assert_eq!(expiry_label("2026-03-31", at(2026, 1, 1)), "(expires soon)");
        // Exactly the horizon still counts.
        assert_eq!(expiry_label("2026-04-01", at(2026, 1, 1)), "(expires soon)");
    }

    #[test]
    fn ninety_one_days_out_is_quiet() {
        assert_eq!(expiry_label("2026-04-02", at(2026, 1, 1)), "");
    }

    #[test]
    fn an_unparsable_date_has_no_verdict() {
        assert_eq!(expiry_label("", at(2026, 1, 1)), "");
        assert_eq!(expiry_label("soon", at(2026, 1, 1)), "");
        // A malformed `to_string` of an ASN.1 time is short, and still quiet.
        assert_eq!(not_after_of("20260101000000Z"), "");
    }

    /// `expiry_label` over a full instant string, to show the truncation that
    /// [`not_after`] does is what makes a date parse.
    fn not_after_of(text: &str) -> &'static str {
        expiry_label(&text.chars().take(10).collect::<String>(), at(2026, 1, 1))
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .build()
            .expect("client")
    }

    /// Run `openssl` with `args`, or panic.
    fn openssl(args: &[&std::ffi::OsStr]) {
        let status = std::process::Command::new("openssl")
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("openssl is available");
        assert!(status.success(), "openssl {args:?} failed");
    }

    fn os(value: &std::path::Path) -> &std::ffi::OsStr {
        value.as_os_str()
    }

    /// A self-signed P-256 CA, returned as DER.
    fn build_root(dir: &Path) -> Vec<u8> {
        let config = dir.join("ca.cnf");
        std::fs::write(
            &config,
            "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\ncommonName=Common Name\n\
             [v3_ca]\nbasicConstraints=critical,CA:TRUE\n\
             keyUsage=critical,keyCertSign,cRLSign\n",
        )
        .expect("write config");
        let key = dir.join("root.key");
        let pem = dir.join("root.pem");
        openssl(&[
            "req".as_ref(),
            "-x509".as_ref(),
            "-sha256".as_ref(),
            "-newkey".as_ref(),
            "ec".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_paramgen_curve:P-256".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_param_enc:named_curve".as_ref(),
            "-nodes".as_ref(),
            "-keyout".as_ref(),
            os(&key),
            "-out".as_ref(),
            os(&pem),
            "-days".as_ref(),
            "2".as_ref(),
            "-subj".as_ref(),
            "/CN=walk-root".as_ref(),
            "-config".as_ref(),
            os(&config),
            "-extensions".as_ref(),
            "v3_ca".as_ref(),
        ]);
        let text = std::fs::read(&pem).expect("read root");
        crate::cmd::anchor::first_certificate(&text).expect("root PEM")
    }

    /// A token signed by a leaf below an intermediate, carrying both; `aia`
    /// becomes the intermediate's `caIssuers` URL. The root is not in the token.
    fn build_token(dir: &Path, aia: Option<&str>) -> Vec<u8> {
        let root_key = dir.join("root.key");
        let root_pem = dir.join("root.pem");
        let int_key = dir.join("int.key");
        let int_csr = dir.join("int.csr");
        let int_pem = dir.join("int.pem");
        let int_ext = dir.join("int.ext");
        let leaf_key = dir.join("leaf.key");
        let leaf_csr = dir.join("leaf.csr");
        let leaf_pem = dir.join("leaf.pem");
        let leaf_ext = dir.join("leaf.ext");
        let tst = dir.join("tst.der");
        let token = dir.join("token.der");

        openssl(&[
            "req".as_ref(),
            "-new".as_ref(),
            "-newkey".as_ref(),
            "ec".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_paramgen_curve:P-256".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_param_enc:named_curve".as_ref(),
            "-nodes".as_ref(),
            "-keyout".as_ref(),
            os(&int_key),
            "-out".as_ref(),
            os(&int_csr),
            "-subj".as_ref(),
            "/CN=walk-intermediate".as_ref(),
        ]);
        let mut intermediate = String::from(
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
        );
        if let Some(aia) = aia {
            intermediate.push_str(&format!("authorityInfoAccess=caIssuers;URI:{aia}\n"));
        }
        std::fs::write(&int_ext, intermediate).expect("write intermediate extensions");
        let int_serial = dir.join("int.srl");
        std::fs::write(&int_serial, "01\n").expect("write serial");
        openssl(&[
            "x509".as_ref(),
            "-req".as_ref(),
            "-sha256".as_ref(),
            "-in".as_ref(),
            os(&int_csr),
            "-CA".as_ref(),
            os(&root_pem),
            "-CAkey".as_ref(),
            os(&root_key),
            "-CAserial".as_ref(),
            os(&int_serial),
            "-out".as_ref(),
            os(&int_pem),
            "-days".as_ref(),
            "2".as_ref(),
            "-extfile".as_ref(),
            os(&int_ext),
        ]);

        openssl(&[
            "req".as_ref(),
            "-new".as_ref(),
            "-newkey".as_ref(),
            "ec".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_paramgen_curve:P-256".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_param_enc:named_curve".as_ref(),
            "-nodes".as_ref(),
            "-keyout".as_ref(),
            os(&leaf_key),
            "-out".as_ref(),
            os(&leaf_csr),
            "-subj".as_ref(),
            "/CN=walk-leaf".as_ref(),
        ]);
        std::fs::write(
            &leaf_ext,
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n\
             extendedKeyUsage=critical,timeStamping\n",
        )
        .expect("write leaf extensions");
        let leaf_serial = dir.join("leaf.srl");
        std::fs::write(&leaf_serial, "02\n").expect("write serial");
        openssl(&[
            "x509".as_ref(),
            "-req".as_ref(),
            "-sha256".as_ref(),
            "-in".as_ref(),
            os(&leaf_csr),
            "-CA".as_ref(),
            os(&int_pem),
            "-CAkey".as_ref(),
            os(&int_key),
            "-CAserial".as_ref(),
            os(&leaf_serial),
            "-out".as_ref(),
            os(&leaf_pem),
            "-days".as_ref(),
            "2".as_ref(),
            "-extfile".as_ref(),
            os(&leaf_ext),
        ]);

        std::fs::write(&tst, b"imprint").expect("write TSTInfo");
        openssl(&[
            "cms".as_ref(),
            "-sign".as_ref(),
            "-binary".as_ref(),
            "-nodetach".as_ref(),
            "-in".as_ref(),
            os(&tst),
            "-signer".as_ref(),
            os(&leaf_pem),
            "-inkey".as_ref(),
            os(&leaf_key),
            "-certfile".as_ref(),
            os(&int_pem),
            "-md".as_ref(),
            "sha256".as_ref(),
            "-outform".as_ref(),
            "DER".as_ref(),
            "-out".as_ref(),
            os(&token),
        ]);
        std::fs::read(&token).expect("read token")
    }

    #[test]
    fn the_root_is_walked_from_the_top_certificates_ca_issuers() {
        unset_stub();
        let dir = tempfile::TempDir::new().expect("temp dir");
        let root = build_root(dir.path());
        // The server answers with the root, which is what a CA's AIA target
        // serves; the intermediate in the token names its URL.
        let (base, server) = serve(vec![(200, root.clone())]);
        let token = build_token(dir.path(), Some(&format!("{base}root.der")));

        let pem = runtime()
            .block_on(root_pem(&client(), &token))
            .expect("the walk finds the root");

        let first = parse_certificates(&pem).remove(0);
        assert_eq!(
            first.tbs_certificate.subject, first.tbs_certificate.issuer,
            "the bundle starts with the self-signed root"
        );
        assert!(
            parse_certificates(&pem)
                .iter()
                .any(|certificate| certificate.tbs_certificate.subject
                    != certificate.tbs_certificate.issuer),
            "the intermediate stays in the bundle"
        );
        let seen = server.join().expect("server");
        assert!(
            seen.iter().any(|head| head.contains("root.der")),
            "the caIssuers URL was requested: {seen:?}"
        );
    }

    #[test]
    fn an_aia_that_cannot_be_read_is_named() {
        unset_stub();
        let dir = tempfile::TempDir::new().expect("temp dir");
        let _root = build_root(dir.path());
        let (base, server) = serve(vec![(404, b"gone".to_vec())]);
        let token = build_token(dir.path(), Some(&format!("{base}missing.der")));

        let error = runtime()
            .block_on(root_pem(&client(), &token))
            .expect_err("no root to be found");
        assert!(error.contains("missing.der"), "{error}");
        assert!(error.contains("404"), "{error}");
        server.join().expect("server");
    }

    /// The granted fixture's bundle, as the GET branch would receive it.
    fn bundle() -> String {
        let response =
            include_bytes!("../../../git-time-core/tests/fixtures/resp_granted_freetsa.tsr");
        let RawResponse::Granted { token, .. } =
            parse_response(response).expect("a granted fixture")
        else {
            panic!("the fixture is not granted");
        };
        String::from_utf8(
            runtime()
                .block_on(root_pem(&client(), &token))
                .expect("a root"),
        )
        .expect("PEM is text")
    }

    /// A loopback server that answers the queued `(status, body)` pairs in order
    /// and hands back the request heads it saw. `Connection: close` forces one
    /// connection per request, so the pairs line up with the client's attempts.
    fn serve(answers: Vec<(u16, Vec<u8>)>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for (status, body) in answers {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut head = Vec::new();
                let mut buffer = [0u8; 512];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).expect("read");
                    if read == 0 {
                        break;
                    }
                    head.extend_from_slice(&buffer[..read]);
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                // Drain the request body so the reply does not race a reset.
                let length = text
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                let already = head.len().saturating_sub(
                    head.windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .unwrap_or(0)
                        + 4,
                );
                let mut rest = vec![0u8; length.saturating_sub(already)];
                if !rest.is_empty() {
                    stream.read_exact(&mut rest).expect("read body");
                }
                seen.push(text);
                let reply = format!(
                    "HTTP/1.1 {status} {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    if status == 200 { "OK" } else { "Nope" },
                    body.len()
                );
                stream.write_all(reply.as_bytes()).expect("write head");
                stream.write_all(&body).expect("write body");
            }
            seen
        });
        (format!("http://{address}/"), handle)
    }

    /// The fetch must not need the stub, and `GIT_TIME_ANCHOR_FETCH_CMD` is read
    /// from the process, so every test here clears it.
    fn unset_stub() {
        unsafe { std::env::remove_var("GIT_TIME_ANCHOR_FETCH_CMD") };
    }

    fn block_on(
        future: impl std::future::Future<Output = Result<Vec<u8>, String>>,
    ) -> Result<Vec<u8>, String> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    /// A 405 on the GET is what DFN and the other endpoint-only presets answer;
    /// it means "not this method", not "no anchor".
    #[test]
    fn a_get_that_is_not_a_certificate_falls_back_to_the_token() {
        unset_stub();
        let fixture =
            include_bytes!("../../../git-time-core/tests/fixtures/resp_granted_freetsa.tsr");
        let (url, server) = serve(vec![
            (405, b"Method Not Allowed".to_vec()),
            (200, fixture.to_vec()),
        ]);

        let pem = String::from_utf8(block_on(fetch(&url)).expect("the token's root"))
            .expect("PEM is text");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");

        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(requests[0].starts_with("GET "), "{}", requests[0]);
        assert!(requests[1].starts_with("POST "), "{}", requests[1]);
        assert!(
            requests[1]
                .to_ascii_lowercase()
                .contains("content-type: application/timestamp-query"),
            "{}",
            requests[1]
        );
        // An authority's front proxy may refuse a request without one.
        for request in &requests {
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains(&format!("user-agent: {USER_AGENT}").to_ascii_lowercase()),
                "{request}"
            );
        }
    }

    /// A certificate answer is the bundle itself: no token request follows.
    #[test]
    fn a_certificate_answer_is_used_without_a_token_request() {
        unset_stub();
        let pem = bundle();
        let (url, server) = serve(vec![(200, pem.clone().into_bytes())]);

        assert_eq!(
            String::from_utf8(block_on(fetch(&url)).expect("the bundle")).expect("PEM is text"),
            pem
        );
        assert_eq!(server.join().expect("server").len(), 1, "one request only");
    }

    /// A DER download is the bundle too: several CAs publish roots that way and
    /// would otherwise be talked to as timestamp endpoints.
    #[test]
    fn a_der_certificate_answer_is_used_without_a_token_request() {
        unset_stub();
        let dir = tempfile::TempDir::new().expect("temp dir");
        let der = build_root(dir.path());
        let (url, server) = serve(vec![(200, der.clone())]);

        let pem =
            String::from_utf8(block_on(fetch(&url)).expect("the bundle")).expect("PEM is text");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");
        assert_eq!(
            parse_certificates(pem.as_bytes())
                .remove(0)
                .to_der()
                .expect("re-encode"),
            der,
            "the body survives the re-encoding"
        );
        assert_eq!(server.join().expect("server").len(), 1, "one request only");
    }

    /// A chain member is appended behind the root, as the bundle order the
    /// anchor reader expects.
    #[test]
    fn a_chain_member_is_appended_behind_the_anchor() {
        unset_stub();
        let dir = tempfile::TempDir::new().expect("temp dir");
        let root = build_root(dir.path());
        let issuer = root.clone();
        let (base, server) = serve(vec![(200, root.clone()), (200, issuer)]);

        let issuer_url = format!("{base}issuer.pem");
        let pem = String::from_utf8(
            block_on(fetch_chain(&base, &[issuer_url.as_str()])).expect("the bundle"),
        )
        .expect("PEM is text");
        let certificates = parse_certificates(pem.as_bytes());
        assert_eq!(certificates.len(), 2, "{pem}");
        for certificate in &certificates {
            assert_eq!(
                certificate.to_der().expect("re-encode"),
                root,
                "the anchor first, then the chain member"
            );
        }
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(requests[1].starts_with("GET "), "{}", requests[1]);
    }

    /// When both attempts fail, the reader has to see both, or a 403 that merely
    /// means "wrong method" reads like a dead authority.
    #[test]
    fn both_failed_attempts_are_named() {
        unset_stub();
        let (url, server) = serve(vec![(403, Vec::new()), (500, Vec::new())]);

        let error = block_on(fetch(&url)).expect_err("both fail");
        assert!(error.contains("GET") && error.contains("403"), "{error}");
        assert!(error.contains("POST") && error.contains("500"), "{error}");
        server.join().expect("server");
    }
}
