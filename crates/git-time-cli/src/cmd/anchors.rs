//! Anchor bundles: where they live, how they are fetched, and how doctor names
//! them.
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
use git_time_core::repo::Repo;
use git_time_core::tsa::{StampRequest, encode, parse_response};

use crate::cmd::Exit;

/// How long one anchor fetch may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The directory anchor bundles are pinned in: `$XDG_CONFIG_HOME` when set,
/// `~/.config` otherwise.
#[must_use]
pub fn dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("git-time").join("anchors")
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

/// Fetch the bundle at `url`.
///
/// A GET is tried first: when it answers 2xx with a PEM certificate, that body is
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
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|error| format!("cannot build the HTTP client: {error}"))?;
    let mut get_error = None;
    match client.get(url).send().await {
        Ok(response) if response.status().is_success() => {
            match response.bytes().await {
                // A certificate download: a plain `.pem` is the whole bundle.
                Ok(body) if holds_certificate(&body) => return Ok(body.to_vec()),
                // Something else that says 200 is still worth a token request: the
                // endpoint may be serving its own landing page.
                Ok(_) => {}
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

fn holds_certificate(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes).contains("BEGIN CERTIFICATE")
}

/// POST a timestamp query to `url` and return the self-signed root of the chain
/// the reply carries, PEM-encoded.
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
    root_pem(&token)
}

/// The PEM of the self-signed certificate in the CMS token `token`, then the
/// other certificates of its chain.
fn root_pem(token: &[u8]) -> Result<Vec<u8>, String> {
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

    let mut root = None;
    let mut others = Vec::new();
    for choice in certificates.0.iter() {
        let CertificateChoices::Certificate(certificate) = choice else {
            continue;
        };
        if certificate.tbs_certificate.subject == certificate.tbs_certificate.issuer {
            if root.is_none() {
                root = Some(certificate.clone());
            }
        } else {
            others.push(certificate.clone());
        }
    }
    let root = root.ok_or_else(|| "the reply carries no self-signed root".to_owned())?;

    let mut pem = pem_block(&root.to_der().map_err(|error| error.to_string())?);
    for other in others {
        pem.extend(pem_block(
            &other.to_der().map_err(|error| error.to_string())?,
        ));
    }
    Ok(pem)
}

fn pem_block(der: &[u8]) -> Vec<u8> {
    let encoded = BASE64.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out.into_bytes()
}

/// Every TSA id configured under `time.tsa.<id>.url`, in id order.
pub fn tsa_ids(repo: &Repo) -> Result<Vec<String>, Exit> {
    let mut ids = Vec::new();
    for (key, _value) in listing(repo)? {
        let Some(rest) = key.strip_prefix("time.tsa.") else {
            continue;
        };
        let Some((id, field)) = rest.rsplit_once('.') else {
            continue;
        };
        if field == "url" && !ids.iter().any(|seen: &String| seen == id) {
            ids.push(id.to_owned());
        }
    }
    ids.sort();
    Ok(ids)
}

/// The `key value` pairs of every `time.tsa.*` key.
fn listing(repo: &Repo) -> Result<Vec<(String, String)>, Exit> {
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
    Ok(configured(repo)?
        .into_iter()
        .find(|anchor| anchor.id == id)
        .map_or_else(|| dir().join(format!("{id}.pem")), |anchor| anchor.path))
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
        let pem = String::from_utf8(root_pem(&token).expect("a root")).expect("PEM is text");
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

    /// The granted fixture's bundle, as the GET branch would receive it.
    fn bundle() -> String {
        let response =
            include_bytes!("../../../git-time-core/tests/fixtures/resp_granted_freetsa.tsr");
        let RawResponse::Granted { token, .. } =
            parse_response(response).expect("a granted fixture")
        else {
            panic!("the fixture is not granted");
        };
        String::from_utf8(root_pem(&token).expect("a root")).expect("PEM is text")
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
