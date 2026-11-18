//! The built-in public authority presets.
//!
//! One static table, read by `install --preset public` and by
//! `git time tsa preset add <name>`; both write exactly the same keys from it,
//! so the two surfaces cannot drift apart.
//!
//! A preset carries where the authority is reached (`url`), where its anchor
//! bundle is fetched from (`anchor_url`), the imprint algorithm requests ask
//! for and the policy they request. The anchor URL differs from the endpoint for
//! FreeTSA, whose CA is a plain PEM download. `rfc3161.ai.moda` is a load
//! balancer over many CAs: it is asked for a token and the self-signed root of
//! the reply is the anchor, which is why the same URL serves both fields.

/// One public authority a preset configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preset {
    /// The config id and the anchor file stem.
    pub name: &'static str,
    /// The timestamp endpoint.
    pub url: &'static str,
    /// Where the anchor bundle is fetched from.
    pub anchor_url: &'static str,
    /// The imprint algorithm and the algorithm requests ask for.
    pub alg: &'static str,
    /// The TSA policy requests ask for, when the authority has a published one.
    pub policy: Option<&'static str>,
}

/// The built-in presets, in the order they are written.
pub const PRESETS: [Preset; 2] = [
    Preset {
        name: "freetsa",
        url: "https://freetsa.org/tsr",
        anchor_url: "https://freetsa.org/files/cacert.pem",
        alg: "sha256",
        policy: Some("1.2.3.4.1"),
    },
    Preset {
        name: "ai-moda",
        url: "https://rfc3161.ai.moda",
        // A plain GET answers prose; the fetch asks for a token and takes the
        // root of the chain it replies with.
        anchor_url: "https://rfc3161.ai.moda",
        alg: "sha256",
        policy: None,
    },
];

/// The preset called `name`.
#[must_use]
pub fn find(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|preset| preset.name == name)
}

/// The names of every preset, in table order.
pub fn names() -> impl Iterator<Item = &'static str> {
    PRESETS.iter().map(|preset| preset.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preset_is_findable_and_named_once() {
        for preset in &PRESETS {
            assert_eq!(find(preset.name), Some(preset));
            assert_eq!(
                names().filter(|name| *name == preset.name).count(),
                1,
                "{} is named once",
                preset.name
            );
            assert!(preset.url.starts_with("https://"));
            assert!(preset.anchor_url.starts_with("https://"));
            assert_eq!(preset.alg, "sha256");
        }
        assert_eq!(find("nope"), None);
    }
}
