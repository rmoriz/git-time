//! Fan-out to every configured authority under one deadline.
//!
//! The pool never fails as a whole. Each source contributes either a token or a
//! `(id, reason)` record, and the caller decides what its quorum means: one dead
//! or slow authority must not cost the seal when enough others answered.
//!
//! Every source gets its own request, and therefore its own nonce. Reusing one
//! nonce across authorities would let two tokens be swapped for one another
//! without the mismatch showing.
//!
//! Results are collected by source index, never by completion order, so the
//! same inputs produce the same token and failure order however the network
//! answers.

use futures::stream::{FuturesUnordered, StreamExt as _};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{Instant, timeout, timeout_at};

use super::{StampRequest, TsaBackend};

/// What a seal needs from a fan-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolPolicy {
    /// Successes needed for the set to count as sufficient; `0` is best effort.
    pub required: usize,
    /// Hard bound on the whole fan-out.
    pub deadline: Duration,
}

/// One token, with the request that produced it.
///
/// The request is kept, not just the token, because the trailer records its
/// nonce and algorithm; without them the token could not be checked against a
/// rebuilt request later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampedToken {
    /// The authority's identifier.
    pub id: String,
    /// The raw `timeStampToken` DER, exactly as received.
    pub token: Vec<u8>,
    /// The request this authority answered.
    pub request: StampRequest,
}

/// Everything a fan-out produced, in source order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolOutcome {
    /// Tokens that came back granted and non-empty; still unverified.
    pub tokens: Vec<StampedToken>,
    /// `(id, reason)` for every source that did not answer with a token.
    pub failures: Vec<(String, String)>,
}

impl PoolOutcome {
    /// Whether enough sources succeeded for `policy`.
    #[must_use]
    pub fn met(&self, policy: &PoolPolicy) -> bool {
        self.tokens.len() >= policy.required
    }
}

/// Ask every source at once, all of them for the same request template.
///
/// Each source still draws its own nonce inside [`run_each`].
pub async fn run(
    sources: &[Arc<dyn TsaBackend>],
    request: &StampRequest,
    policy: &PoolPolicy,
) -> PoolOutcome {
    let requests = vec![request.clone(); sources.len()];
    run_each(sources, &requests, policy).await
}

/// Ask every source at once, each with its own request template.
///
/// `requests` must have one entry per source and in the same order: the seal
/// uses this to give each authority the imprint algorithm and policy configured
/// for it. The nonce is still drawn per source, so reusing a template cannot
/// reuse a nonce.
///
/// All sources are polled together, so `policy.deadline` bounds the whole call,
/// not each source in turn. A source that has not answered within it is recorded
/// as `timeout` and abandoned. A source whose request cannot even be built (an
/// invalid imprint or policy) is recorded with that error and never contacted.
///
/// The run ends as soon as it can: once the quorum is in hand and every other
/// source has answered, and once the deadline is up while the quorum is already
/// in hand, the stragglers are not worth the wait and become `timeout` records.
/// That is what keeps a wide selection near `deadline` instead of near the slowest
/// authority.
///
/// The function has no error return: the outcome is always a value. A length
/// mismatch is a programming error and pads with the first template, so the zip
/// below cannot hide a source.
pub async fn run_each(
    sources: &[Arc<dyn TsaBackend>],
    requests: &[StampRequest],
    policy: &PoolPolicy,
) -> PoolOutcome {
    debug_assert_eq!(
        requests.len(),
        sources.len(),
        "one request per source, or the padding below would run a source twice"
    );
    let (required, deadline) = (policy.required, policy.deadline);
    let deadline_at = Instant::now() + deadline;
    let mut pending = FuturesUnordered::new();
    for (index, source) in sources.iter().enumerate() {
        let template = requests.get(index).or_else(|| requests.first());
        pending.push(async move { (index, stamp_one(source, template, deadline).await) });
    }

    // Indexed, so the outcome can be reassembled in source order however the
    // network answers.
    let mut results: Vec<Option<Stamped>> = sources.iter().map(|_| None).collect();
    let mut successes = 0_usize;

    loop {
        let item = match timeout_at(deadline_at, pending.next()).await {
            Ok(item) => item,
            // Past the deadline. Enough tokens already: the stragglers are not
            // worth the latency and become timeouts below. Not enough: keep
            // waiting — every source has its own deadline and resolves on its
            // own, so this cannot hang.
            Err(_) if successes >= required => break,
            Err(_) => pending.next().await,
        };
        let Some((index, result)) = item else { break };
        if result.is_ok() {
            successes += 1;
        }
        results[index] = Some(result);
        // Everything answered, so there is nothing left to wait for.
        if results.iter().all(Option::is_some) {
            break;
        }
    }

    debug_assert_eq!(
        sources.len(),
        results.len(),
        "one result per source, or the zip below would hide a mismatch"
    );

    let mut outcome = PoolOutcome {
        tokens: Vec::with_capacity(sources.len()),
        failures: Vec::new(),
    };
    for (source, result) in sources.iter().zip(results) {
        match result {
            Some(Ok((token, request))) => outcome.tokens.push(StampedToken {
                id: source.id().to_owned(),
                token,
                request,
            }),
            Some(Err(reason)) => outcome.failures.push((source.id().to_owned(), reason)),
            // Left pending when the quorum was already met at the deadline.
            None => outcome
                .failures
                .push((source.id().to_owned(), "timeout".to_owned())),
        }
    }
    outcome
}

/// What one source produced: its token and the request behind it, or a reason.
type Stamped = Result<(Vec<u8>, StampRequest), String>;

/// One source: build its request, bound the call, map everything to a reason.
async fn stamp_one(
    source: &Arc<dyn TsaBackend>,
    request: Option<&StampRequest>,
    deadline: Duration,
) -> Result<(Vec<u8>, StampRequest), String> {
    let request = request.ok_or_else(|| "no request template".to_owned())?;
    let request = StampRequest::new(request.imprint.clone(), &mut rand::rng())
        .and_then(|built| built.with_policy(request.policy.clone()))
        .map(|mut built| {
            built.cert_req = request.cert_req;
            built
        })
        .map_err(|error| error.reason())?;

    match timeout(deadline, source.stamp(&request)).await {
        Ok(Ok(token)) if !token.is_empty() => Ok((token, request)),
        Ok(Ok(_)) => Err("granted response carried no token".to_owned()),
        Ok(Err(error)) => Err(error.reason()),
        Err(_) => Err("timeout".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{PoolOutcome, PoolPolicy};
    use std::time::Duration;

    fn policy(required: usize) -> PoolPolicy {
        PoolPolicy {
            required,
            deadline: Duration::from_secs(1),
        }
    }

    #[test]
    fn nothing_is_required_when_the_quorum_is_zero() {
        let outcome = PoolOutcome::default();
        assert!(outcome.met(&policy(0)));
        assert!(!outcome.met(&policy(1)));
    }
}
