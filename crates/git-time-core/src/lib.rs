//! Core types and plumbing for RFC 3161 commit sealing.

// The workspace denies `unsafe`; the library forbids it outright so no module
// here can even `allow` its way back. Nothing in this crate needs it.
#![forbid(unsafe_code)]

pub mod imprint;
pub mod object;
pub mod policy;
pub mod presets;
pub mod repo;
pub mod seal;
pub mod sigcheck;
pub mod store;
pub mod trust;
pub mod tsa;
pub mod verify;
