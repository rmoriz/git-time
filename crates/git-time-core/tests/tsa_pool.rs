//! Parallel TSA fan-out: deadline, quorum, retries and failure records.
//!
//! Every source here is a real HTTP backend against a stub server on
//! `127.0.0.1:0`, so the tests exercise the transport, not a mock. The stubs
//! answer from a script: a step may repeat, a script that runs out keeps
//! repeating its last step, and only the retry tests script a different second
//! answer.
//!
//! The point of the pool is that it never fails as a whole: whatever comes
//! back, successes and failures are both returned, in source order, and a
//! source that outlives the deadline becomes a `timeout` record instead of
//! holding the seal.

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{
    HeaderMap, HeaderValue, StatusCode, header::CONTENT_LENGTH, header::CONTENT_TYPE,
};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use futures::stream;
use git_time_core::imprint::{Alg, Digest, digest};
use git_time_core::tsa::backend::MAX_RESPONSE_BYTES;
use git_time_core::tsa::{
    HttpBackend, PoolPolicy, RawResponse, StampRequest, TsaBackend, encode, parse_response,
    pool::run,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The granted FreeTSA response; only its token matters to the pool.
const GRANTED: &[u8] = include_bytes!("fixtures/resp_granted_freetsa.tsr");
/// The FreeTSA rejection for an unserved policy.
const REJECTED: &[u8] = include_bytes!("fixtures/resp_rejected_freetsa.tsr");

const CONTENT_TYPE_QUERY: &str = "application/timestamp-query";

/// How a scripted answer carries its body.
#[derive(Clone)]
enum Answer {
    /// A body of known length; axum announces it.
    Bytes(Vec<u8>),
    /// `count` chunks of `len` bytes, streamed with no declared length.
    Streamed { count: usize, len: usize },
    /// An announced length whose body never arrives, so only a client that
    /// looks at `Content-Length` can answer without waiting.
    Announced(usize),
}

/// One scripted answer: status, body, and how long the stub waits first.
#[derive(Clone)]
struct Step {
    status: StatusCode,
    answer: Answer,
    delay: Duration,
}

impl Step {
    /// A granted answer carrying `body`.
    fn ok(body: &'static [u8]) -> Self {
        Self {
            status: StatusCode::OK,
            answer: Answer::Bytes(body.to_vec()),
            delay: Duration::ZERO,
        }
    }

    /// An error answer with a short diagnostic body.
    fn status(status: u16, body: &'static [u8]) -> Self {
        Self {
            status: StatusCode::from_u16(status).expect("test status"),
            answer: Answer::Bytes(body.to_vec()),
            delay: Duration::ZERO,
        }
    }

    /// A `200` that streams `count * len` body bytes without a length header.
    fn streamed(count: usize, len: usize) -> Self {
        Self {
            status: StatusCode::OK,
            answer: Answer::Streamed { count, len },
            delay: Duration::ZERO,
        }
    }

    /// A `200` announcing `length` body bytes that never arrive.
    fn announced(length: usize) -> Self {
        Self {
            status: StatusCode::OK,
            answer: Answer::Announced(length),
            delay: Duration::ZERO,
        }
    }

    /// The same step, served only after `delay`.
    fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

#[derive(Clone)]
struct StubState {
    script: Arc<Vec<Step>>,
    hits: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// A stub TSA; `url` is its request endpoint, `hits` counts what it saw.
struct Stub {
    url: String,
    hits: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Stub {
    async fn spawn(script: Vec<Step>) -> Self {
        let hits = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let state = StubState {
            script: Arc::new(script),
            hits: Arc::clone(&hits),
            bodies: Arc::clone(&bodies),
        };
        let app = Router::new().route("/tsr", post(handle)).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub");
        let addr = listener.local_addr().expect("stub address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: format!("http://{addr}/tsr"),
            hits,
            bodies,
        }
    }

    fn backend(&self, id: &str) -> Arc<dyn TsaBackend> {
        self.backend_with_timeout(id, Duration::from_secs(5))
    }

    fn backend_with_timeout(&self, id: &str, timeout: Duration) -> Arc<dyn TsaBackend> {
        Arc::new(HttpBackend {
            id: id.to_owned(),
            url: self.url.clone(),
            timeout,
        })
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// Every request body the stub received, in arrival order.
    fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().expect("bodies lock").clone()
    }
}

/// Serve one script step, refusing a request that is not a timestamp query.
async fn handle(State(state): State<StubState>, headers: HeaderMap, body: Bytes) -> Response {
    let index = state.hits.fetch_add(1, Ordering::SeqCst);
    state
        .bodies
        .lock()
        .expect("bodies lock")
        .push(body.to_vec());

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if content_type != Some(CONTENT_TYPE_QUERY) {
        return (StatusCode::BAD_REQUEST, b"bad content-type".to_vec()).into_response();
    }
    if body.first() != Some(&0x30) {
        return (StatusCode::BAD_REQUEST, b"not a DER sequence".to_vec()).into_response();
    }

    // A script that runs out keeps answering its last step, so a source that
    // is hit more often than scripted fails the same way every time.
    let last = state.script.len().saturating_sub(1);
    let step = state.script[index.min(last)].clone();
    if !step.delay.is_zero() {
        tokio::time::sleep(step.delay).await;
    }

    let mut response = match step.answer {
        Answer::Bytes(body) => Body::from(body).into_response(),
        Answer::Streamed { count, len } => Body::from_stream(stream::iter(
            (0..count).map(move |_| Ok::<Bytes, std::io::Error>(Bytes::from(vec![b'x'; len]))),
        ))
        .into_response(),
        Answer::Announced(length) => {
            let mut response =
                Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>())
                    .into_response();
            response
                .headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from(length));
            response
        }
    };
    *response.status_mut() = step.status;
    response
}

fn imprint() -> Digest {
    Digest {
        alg: Alg::Sha256,
        bytes: digest(Alg::Sha256, b"git-time pool fixture\n"),
    }
}

fn request() -> StampRequest {
    StampRequest::new(imprint(), &mut rand::rng()).expect("valid request")
}

/// The token inside the granted fixture, read back with the real parser.
fn granted_token() -> Vec<u8> {
    match parse_response(GRANTED).expect("granted fixture parses") {
        RawResponse::Granted { token, .. } => token,
        other => panic!("granted fixture parsed as {other:?}"),
    }
}

fn sources(stubs: &[&Stub], ids: &[&str]) -> Vec<Arc<dyn TsaBackend>> {
    assert_eq!(
        stubs.len(),
        ids.len(),
        "every stub needs exactly one id, or a zip would hide the mismatch"
    );
    stubs
        .iter()
        .zip(ids)
        .map(|(stub, id)| stub.backend(id))
        .collect()
}

fn policy(required: usize, deadline: Duration) -> PoolPolicy {
    PoolPolicy { required, deadline }
}

#[tokio::test]
async fn deadline_cuts_off_a_slow_source_and_keeps_the_fast_ones() {
    let good = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let bad = Stub::spawn(vec![Step::status(503, b"unavailable")]).await;
    let slow = Stub::spawn(vec![Step::ok(GRANTED).after(Duration::from_secs(5))]).await;

    let stubs = [&good, &bad, &slow];
    let backends = sources(&stubs, &["good", "bad", "slow"]);
    let started = Instant::now();
    let outcome = run(&backends, &request(), &policy(1, Duration::from_secs(1))).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(1200),
        "deadline did not bound the run: {elapsed:?}"
    );
    assert_eq!(outcome.tokens.len(), 1);
    assert_eq!(outcome.tokens[0].id, "good");
    assert_eq!(outcome.tokens[0].token, granted_token());
    assert_eq!(
        outcome.failures,
        [
            ("bad".to_owned(), "http 503: unavailable".to_owned()),
            ("slow".to_owned(), "timeout".to_owned()),
        ]
    );
    assert_eq!(bad.hits(), 2, "a 503 gets exactly one retry");
    assert_eq!(slow.hits(), 1);
}

/// Many authorities, the quorum long since met, one straggler: the run must end
/// at the deadline, not when the straggler does. That is what keeps
/// `install --preset all` usable.
#[tokio::test]
async fn a_met_quorum_does_not_wait_for_a_straggler() {
    let fast = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let slow = Stub::spawn(vec![Step::ok(GRANTED).after(Duration::from_secs(5))]).await;

    // Twenty sources, one of them slow; the fast stub answers nineteen.
    let mut ids: Vec<String> = (0..19).map(|index| format!("fast{index}")).collect();
    ids.push("slow".to_owned());
    let mut backends: Vec<Arc<dyn TsaBackend>> = (0..19)
        .map(|index| fast.backend(&format!("fast{index}")))
        .collect();
    backends.push(slow.backend("slow"));

    let started = Instant::now();
    let outcome = run(&backends, &request(), &policy(2, Duration::from_secs(1))).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(1200),
        "the deadline bounded the run, not the straggler: {elapsed:?}"
    );
    assert!(outcome.tokens.len() >= 2, "the quorum is in hand");
    assert!(
        outcome
            .failures
            .iter()
            .any(|(id, reason)| id == "slow" && reason == "timeout"),
        "the straggler is named: {:?}",
        outcome.failures
    );
    // Every source is still accounted for, whichever way it went.
    assert_eq!(outcome.tokens.len() + outcome.failures.len(), 20);
}

#[tokio::test]
async fn sources_are_reported_in_source_order_with_distinct_nonces() {
    // Later sources answer first, so completion order is the reverse of
    // source order and only an index-keyed collect can pass.
    let first = Stub::spawn(vec![Step::ok(GRANTED).after(Duration::from_millis(80))]).await;
    let second = Stub::spawn(vec![Step::ok(GRANTED).after(Duration::from_millis(40))]).await;
    let third = Stub::spawn(vec![Step::ok(GRANTED)]).await;

    let stubs = [&first, &second, &third];
    let backends = sources(&stubs, &["a", "b", "c"]);
    let request = request()
        .with_policy(Some("1.2.3.4.1".to_owned()))
        .expect("valid policy");
    let outcome = run(&backends, &request, &policy(3, Duration::from_secs(2))).await;

    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    let ids: Vec<&str> = outcome
        .tokens
        .iter()
        .map(|stamped| stamped.id.as_str())
        .collect();
    assert_eq!(ids, ["a", "b", "c"]);
    assert_eq!(outcome.tokens.len(), 3);
    assert!(outcome.tokens.iter().all(|s| s.token == granted_token()));

    let nonces: Vec<&[u8]> = outcome
        .tokens
        .iter()
        .map(|stamped| stamped.request.nonce.as_slice())
        .collect();
    assert!(nonces.iter().all(|nonce| nonce.len() == 8));
    assert_ne!(nonces[0], nonces[1]);
    assert_ne!(nonces[1], nonces[2]);
    assert_ne!(nonces[0], nonces[2]);

    // Every per-source request keeps the caller's imprint and policy.
    for stamped in &outcome.tokens {
        assert_eq!(stamped.request.imprint, request.imprint);
        assert_eq!(stamped.request.policy, request.policy);
    }

    assert!(outcome.met(&policy(3, Duration::from_secs(2))));
}

#[tokio::test]
async fn quorum_is_only_met_by_enough_tokens() {
    let good = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let good_too = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let bad = Stub::spawn(vec![Step::status(503, b"unavailable")]).await;

    let one = [&good, &bad];
    let short = run(
        &sources(&one, &["good", "bad"]),
        &request(),
        &policy(2, Duration::from_secs(2)),
    )
    .await;
    assert_eq!(short.tokens.len(), 1);
    assert_eq!(short.failures.len(), 1);
    assert!(!short.met(&policy(2, Duration::from_secs(2))));

    let two = [&good, &good_too];
    let enough = run(
        &sources(&two, &["good", "good-too"]),
        &request(),
        &policy(2, Duration::from_secs(2)),
    )
    .await;
    assert_eq!(enough.tokens.len(), 2);
    assert!(enough.failures.is_empty());
    assert!(enough.met(&policy(2, Duration::from_secs(2))));
}

#[tokio::test]
async fn a_rejection_is_a_failure_with_its_reason() {
    let rejected = Stub::spawn(vec![Step::ok(REJECTED)]).await;

    let stubs = [&rejected];
    let outcome = run(
        &sources(&stubs, &["freetsa"]),
        &request(),
        &policy(1, Duration::from_secs(2)),
    )
    .await;

    assert!(outcome.tokens.is_empty());
    assert_eq!(outcome.failures.len(), 1);
    let (id, reason) = &outcome.failures[0];
    assert_eq!(id, "freetsa");
    assert!(reason.contains("reject"), "{reason}");
    assert!(
        reason.to_lowercase().contains("policy is not supported"),
        "{reason}"
    );
    assert_eq!(rejected.hits(), 1, "a rejection is not retried");
}

#[tokio::test]
async fn a_malformed_body_fails_without_a_retry() {
    let broken = Stub::spawn(vec![Step::ok(b"\x30\x03\x02\x01")]).await;

    let stubs = [&broken];
    let outcome = run(
        &sources(&stubs, &["broken"]),
        &request(),
        &policy(1, Duration::from_secs(2)),
    )
    .await;

    assert!(outcome.tokens.is_empty());
    assert_eq!(outcome.failures.len(), 1);
    assert!(
        outcome.failures[0].1.contains("malformed"),
        "{:?}",
        outcome.failures
    );
    assert_eq!(broken.hits(), 1, "a malformed body is not retried");
}

#[tokio::test]
async fn a_503_is_retried_once_and_then_succeeds() {
    // The retry budget is exactly one: a second 503 is final. The stub's
    // second answer is the one that succeeds.
    let flaky = Stub::spawn(vec![Step::status(503, b"unavailable"), Step::ok(GRANTED)]).await;

    let stubs = [&flaky];
    let outcome = run(
        &sources(&stubs, &["flaky"]),
        &request(),
        &policy(1, Duration::from_secs(2)),
    )
    .await;

    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    assert_eq!(outcome.tokens.len(), 1);
    assert_eq!(outcome.tokens[0].token, granted_token());
    assert_eq!(flaky.hits(), 2, "the failed attempt is retried once");
}

#[tokio::test]
async fn a_second_503_is_final() {
    let stuck = Stub::spawn(vec![Step::status(503, b"unavailable")]).await;

    let stubs = [&stuck];
    let outcome = run(
        &sources(&stubs, &["stuck"]),
        &request(),
        &policy(1, Duration::from_secs(2)),
    )
    .await;

    assert!(outcome.tokens.is_empty());
    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(stuck.hits(), 2, "one retry, then the failure is kept");
}

#[tokio::test]
async fn a_rate_limit_is_retried_once() {
    let limited = Stub::spawn(vec![Step::status(429, b"slow down"), Step::ok(GRANTED)]).await;

    let stubs = [&limited];
    let outcome = run(
        &sources(&stubs, &["limited"]),
        &request(),
        &policy(1, Duration::from_secs(2)),
    )
    .await;

    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    assert_eq!(outcome.tokens.len(), 1);
    assert_eq!(limited.hits(), 2);
}

#[tokio::test]
async fn a_plain_4xx_is_not_retried() {
    let refused = Stub::spawn(vec![Step::status(400, b"bad request")]).await;

    let stubs = [&refused];
    let outcome = run(
        &sources(&stubs, &["refused"]),
        &request(),
        &policy(1, Duration::from_secs(2)),
    )
    .await;

    assert!(outcome.tokens.is_empty());
    assert!(
        outcome.failures[0].1.contains("400"),
        "{:?}",
        outcome.failures
    );
    assert_eq!(refused.hits(), 1);
}

#[tokio::test]
async fn an_invalid_imprint_is_a_failure_per_source_and_sends_nothing() {
    // Constructed by hand: `StampRequest::new` is exactly what refuses this
    // imprint, so it cannot build the base request.
    let broken = StampRequest {
        imprint: Digest {
            alg: Alg::Sha256,
            bytes: vec![0xab; 3],
        },
        nonce: vec![1, 2, 3],
        policy: None,
        cert_req: true,
    };

    let first = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let second = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let stubs = [&first, &second];
    let outcome = run(
        &sources(&stubs, &["first", "second"]),
        &broken,
        &policy(1, Duration::from_secs(2)),
    )
    .await;

    assert!(outcome.tokens.is_empty());
    let ids: Vec<&str> = outcome.failures.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["first", "second"]);
    assert!(
        outcome
            .failures
            .iter()
            .all(|(_, reason)| reason.contains("invalid message imprint")),
        "{:?}",
        outcome.failures
    );
    assert_eq!(first.hits(), 0);
    assert_eq!(second.hits(), 0);
}

#[tokio::test]
async fn an_invalid_policy_is_refused_before_any_request() {
    // The imprint is a valid SHA-256 digest, so only the policy can refuse
    // this base request: the imprint check cannot be what stops the call-out.
    let broken = StampRequest {
        imprint: imprint(),
        nonce: vec![1, 2, 3],
        policy: Some("not-an-oid".to_owned()),
        cert_req: true,
    };

    let first = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let second = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let stubs = [&first, &second];
    let outcome = run(
        &sources(&stubs, &["first", "second"]),
        &broken,
        &policy(1, Duration::from_secs(2)),
    )
    .await;

    assert!(outcome.tokens.is_empty());
    let ids: Vec<&str> = outcome.failures.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["first", "second"]);
    assert!(
        outcome
            .failures
            .iter()
            .all(|(_, reason)| reason.contains("is not a dotted-decimal OID")),
        "{:?}",
        outcome.failures
    );
    assert_eq!(first.hits(), 0);
    assert_eq!(second.hits(), 0);
    assert!(first.bodies().is_empty());
    assert!(second.bodies().is_empty());
}

#[tokio::test]
async fn a_transport_error_is_retried_exactly_once() {
    // Every connection is accepted and hung up on with no answer, and each
    // accept is counted at the socket. A third attempt after the retry would be
    // counted too, so a settle pause before the assert rules it out.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener address");
    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&attempts);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let backends: [Arc<dyn TsaBackend>; 1] = [Arc::new(HttpBackend {
        id: "dead".to_owned(),
        url: format!("http://{addr}/tsr"),
        timeout: Duration::from_secs(2),
    })];
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        run(&backends, &request(), &policy(1, Duration::from_secs(5))),
    )
    .await
    .expect("run finished");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(outcome.tokens.is_empty());
    assert_eq!(outcome.failures.len(), 1);
    assert!(
        outcome.failures[0].1.contains("request failed"),
        "{:?}",
        outcome.failures
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "one retry on a transport error, no more"
    );
}

#[tokio::test]
async fn cert_req_false_is_absent_from_the_requests() {
    // The pool rebuilds each source's request; losing the `cert_req` copy would
    // silently send the DER default (TRUE) instead. The received bytes are
    // compared with an exact encoding, so only an absent `certReq` passes.
    let off = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let request = StampRequest {
        cert_req: false,
        ..request()
    };

    let stubs = [&off];
    let outcome = run(
        &sources(&stubs, &["off"]),
        &request,
        &policy(1, Duration::from_secs(2)),
    )
    .await;

    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);

    let bodies = off.bodies();
    assert_eq!(bodies.len(), 1);
    let mut expected = outcome.tokens[0].request.clone();
    expected.cert_req = false;

    let mut with_cert_req = expected.clone();
    with_cert_req.cert_req = true;
    assert_ne!(encode(&with_cert_req), encode(&expected));
    assert_eq!(
        bodies[0],
        encode(&expected),
        "the sent request must carry no certReq"
    );
}

#[tokio::test]
async fn an_oversize_streamed_body_fails_without_a_token() {
    // 2 MiB in chunks and no `Content-Length`: only counting the body while it
    // streams can stop this. The transport error is retried, so both attempts
    // are bounded the same way.
    let huge = Stub::spawn(vec![Step::streamed(32, 64 * 1024)]).await;

    let stubs = [&huge];
    let outcome = run(
        &sources(&stubs, &["huge"]),
        &request(),
        &policy(1, Duration::from_secs(2)),
    )
    .await;

    assert!(outcome.tokens.is_empty());
    assert_eq!(
        outcome.failures,
        [(
            "huge".to_owned(),
            format!(
                "timestamp authority request failed: response exceeded {MAX_RESPONSE_BYTES} bytes"
            ),
        )]
    );
    assert_eq!(
        huge.hits(),
        2,
        "an oversize body is retried like any transport error"
    );
}

#[tokio::test]
async fn an_announced_oversize_body_is_refused_without_reading() {
    // The declared length is over the cap and the stub never sends a body byte,
    // so only an early look at `Content-Length` can answer; a backend that
    // reads would sit there until its own timeout.
    let announced = Stub::spawn(vec![Step::announced(2 * 1024 * 1024)]).await;
    let backends = [announced.backend_with_timeout("announced", Duration::from_secs(5))];

    let started = Instant::now();
    let outcome = run(&backends, &request(), &policy(1, Duration::from_secs(10))).await;
    let elapsed = started.elapsed();

    assert!(outcome.tokens.is_empty());
    assert_eq!(
        outcome.failures,
        [(
            "announced".to_owned(),
            format!(
                "timestamp authority request failed: response exceeded {MAX_RESPONSE_BYTES} bytes"
            ),
        )]
    );
    assert_eq!(announced.hits(), 2);
    assert!(
        elapsed < Duration::from_secs(2),
        "the body was read instead of skipped: {elapsed:?}"
    );
}

#[tokio::test]
async fn an_all_fast_pool_returns_promptly() {
    // Three sources that answer at once must not serialize behind the deadline:
    // a per-source deadline applied to the whole fan-out would take the full
    // second here.
    let first = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let second = Stub::spawn(vec![Step::ok(GRANTED)]).await;
    let third = Stub::spawn(vec![Step::ok(GRANTED)]).await;

    let stubs = [&first, &second, &third];
    let started = Instant::now();
    let outcome = run(
        &sources(&stubs, &["first", "second", "third"]),
        &request(),
        &policy(3, Duration::from_secs(1)),
    )
    .await;
    let elapsed = started.elapsed();

    assert_eq!(outcome.tokens.len(), 3);
    assert!(
        elapsed < Duration::from_millis(100),
        "an all-fast fan-out took {elapsed:?}"
    );
}
