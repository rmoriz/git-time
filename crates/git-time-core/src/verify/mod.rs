//! Verification of sealed commits and of the tokens inside them.
//!
//! [`token`] is the leaf judgement: it decides whether one RFC 3161 token is
//! evidence. [`commit`](crate::verify::commit()) builds on it and turns a whole
//! commit into a [`Verdict`].

pub mod commit;
pub mod token;

pub use commit::{
    CommitEvidence, DROPPED_FILE, SignatureStatus, TsaEvidence, Verdict, VerifyError, commit,
    named_tsas,
};
pub use token::{Invalid, TokenVerdict, signer_certificate, token};
