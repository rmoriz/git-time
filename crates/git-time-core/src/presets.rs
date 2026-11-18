//! The built-in public authority presets.
//!
//! One static table, read by `install --preset public` and by
//! `git time tsa preset add <name>`; both write exactly the same keys from it,
//! so the two surfaces cannot drift apart.
//!
//! A preset carries where the authority is reached (`url`), where its anchor
//! bundle is fetched from (`anchor_url`), the imprint algorithm requests ask
//! for, the policy they request, and — where the root is known — the
//! fingerprint that root must have.
//!
//! The order is deliberate: the two originals, then the three with a published
//! root, then the rest, which are trust on first use. FreeTSA publishes a plain PEM;
//! for every other preset the anchor URL *is* the endpoint, because no
//! certificate download is served there. The fetch asks the endpoint for a token
//! and takes the self-signed root of the chain it replies with — the same
//! mechanism `rfc3161.ai.moda` needs as a load balancer over several CAs. None
//! of those certificate URLs could be measured from here, so none are invented.
//!
//! # Why an expected fingerprint
//!
//! An anchor that is simply accepted as fetched is trust on first use: whatever
//! the network hands back on the first `install` becomes the root every later
//! verification trusts. That is fine until the first fetch is the wrong one.
//! A fingerprint makes the first pin *verifiable* — the bundle is accepted only
//! when its first certificate hashes to the value published for that authority,
//! and a mismatch leaves the previous pin alone and says both values.
//!
//! Where no fingerprint is known the fetch is TOFU, so the writer prints the
//! fetched root fingerprint prominently: that line is the only thing that makes
//! the first pin reviewable. `ai-moda` is TOFU for a second reason too — it is a
//! load balancer in front of several CAs, so there is no single expected root.
//!
//! # Why some presets are plain http
//!
//! The token is signed by the authority and verified against the pinned root, so
//! the integrity of the evidence does not depend on the transport. Plain http
//! only exposes the *imprint* (a digest of a commit git will publish anyway) and
//! lets an attacker attack availability. Where the authority offers no TLS
//! endpoint at all, http is the honest choice; `insecure_http` marks exactly
//! those presets so the writer records the acceptance and the seal warns about
//! it.

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
    /// The SHA-256 fingerprint the root must have, uppercase and colon
    /// separated, when the root is known in advance. `None` is trust on first
    /// use.
    pub fingerprint: Option<&'static str>,
    /// Whether the endpoint is plain `http://` and is accepted as such.
    pub insecure_http: bool,
}

/// The built-in presets, in the order they are written: the two originals, the
/// three with a published root, then the seven that are trust on first use.
pub const PRESETS: [Preset; 23] = [
    Preset {
        name: "freetsa",
        url: "https://freetsa.org/tsr",
        anchor_url: "https://freetsa.org/files/cacert.pem",
        alg: "sha256",
        policy: Some("1.2.3.4.1"),
        fingerprint: Some(
            "A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC",
        ),
        insecure_http: false,
    },
    Preset {
        name: "ai-moda",
        url: "https://rfc3161.ai.moda",
        // A plain GET answers prose; the fetch asks for a token and takes the
        // root of the chain it replies with.
        anchor_url: "https://rfc3161.ai.moda",
        alg: "sha256",
        policy: None,
        // A load balancer over several CAs: no single root to pin beforehand,
        // so the fetched one is printed for review (trust on first use).
        fingerprint: None,
        insecure_http: false,
    },
    Preset {
        name: "sectigo",
        url: "https://timestamp.sectigo.com/qualified",
        // A plain GET is not served; the fetch asks for a token and takes the
        // root of the chain it replies with.
        anchor_url: "https://timestamp.sectigo.com/qualified",
        alg: "sha256",
        policy: None,
        fingerprint: Some(
            "F8:71:F8:97:6B:40:68:D7:00:D5:F2:81:08:4B:4A:29:EA:F4:B8:F3:57:43:33:0B:A0:62:FA:B4:6F:58:C2:ED",
        ),
        insecure_http: false,
    },
    Preset {
        name: "certum",
        url: "http://time.certum.pl",
        anchor_url: "http://time.certum.pl",
        alg: "sha256",
        policy: None,
        fingerprint: Some(
            "5C:58:46:8D:55:F5:8E:49:7E:74:39:82:D2:B5:00:10:B6:D1:65:37:4A:CF:83:A7:D4:A3:2D:B7:68:C4:40:8E",
        ),
        insecure_http: true,
    },
    Preset {
        name: "izenpe",
        url: "http://tsa.izenpe.com",
        anchor_url: "http://tsa.izenpe.com",
        alg: "sha256",
        policy: None,
        fingerprint: Some(
            "8E:5B:8B:AE:DC:4D:58:BE:0E:30:1C:CC:B6:ED:17:3C:08:D7:C7:7C:E4:35:09:73:38:9F:F1:AF:A1:1D:7A:65",
        ),
        insecure_http: true,
    },
    // From here on: trust on first use. No root fingerprint was supplied, so
    // the fetched one is printed and has to be compared by a reader.
    Preset {
        name: "acs-microsoft",
        url: "http://timestamp.acs.microsoft.com",
        anchor_url: "http://timestamp.acs.microsoft.com",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "globalsign-r6",
        url: "http://timestamp.globalsign.com/tsa/r6advanced1",
        anchor_url: "http://timestamp.globalsign.com/tsa/r6advanced1",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "aped",
        url: "https://timestamp.aped.gov.gr/qtss",
        anchor_url: "https://timestamp.aped.gov.gr/qtss",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: false,
    },
    Preset {
        name: "cartaodecidadao",
        url: "http://ts.cartaodecidadao.pt/tsa/server",
        anchor_url: "http://ts.cartaodecidadao.pt/tsa/server",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "swisssign",
        url: "http://tsa.swisssign.net",
        anchor_url: "http://tsa.swisssign.net",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "apple",
        url: "http://timestamp.apple.com/ts01",
        anchor_url: "http://timestamp.apple.com/ts01",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "dfn",
        url: "http://zeitstempel.dfn.de",
        anchor_url: "http://zeitstempel.dfn.de",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    // The owner's live-TSA list, minus the endpoints already above. Its
    // `certum-legacy` entry is skipped: it names exactly the `certum` endpoint,
    // and a second row for one endpoint would be two ids for one authority.
    Preset {
        name: "globalsign-advanced",
        url: "http://rfc3161timestamp.globalsign.com/advanced",
        anchor_url: "http://rfc3161timestamp.globalsign.com/advanced",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "comodoca",
        url: "http://timestamp.comodoca.com",
        anchor_url: "http://timestamp.comodoca.com",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "digicert",
        url: "http://timestamp.digicert.com",
        anchor_url: "http://timestamp.digicert.com",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "identrust",
        url: "http://timestamp.identrust.com",
        anchor_url: "http://timestamp.identrust.com",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "quovadis-eu",
        url: "http://ts.quovadisglobal.com/eu",
        anchor_url: "http://ts.quovadisglobal.com/eu",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "ssl-com",
        url: "http://ts.ssl.com",
        anchor_url: "http://ts.ssl.com",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "belgium",
        url: "http://tsa.belgium.be/connect",
        anchor_url: "http://tsa.belgium.be/connect",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        // The same authority also answers on `http://tsa.cesnet.cz:3161/tsa`;
        // the TLS port is the one worth carrying.
        name: "cesnet",
        url: "https://tsa.cesnet.cz:3162/tsa",
        anchor_url: "https://tsa.cesnet.cz:3162/tsa",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: false,
    },
    Preset {
        // The query string is part of the endpoint: it selects the worker and
        // is stored and posted verbatim.
        name: "cra-ge",
        url: "http://tsa.cra.ge/signserver/tsa?workerName=qtsa",
        anchor_url: "http://tsa.cra.ge/signserver/tsa?workerName=qtsa",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "lex-persona",
        url: "http://tsa.lex-persona.com/tsa",
        anchor_url: "http://tsa.lex-persona.com/tsa",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
    },
    Preset {
        name: "accv",
        url: "http://tss.accv.es:8318/tsa",
        anchor_url: "http://tss.accv.es:8318/tsa",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
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
            // Only an accepted plain-http preset may carry an `http://` URL, and
            // both of its URLs then have to.
            if preset.insecure_http {
                assert!(preset.url.starts_with("http://"), "{}", preset.name);
                assert!(preset.anchor_url.starts_with("http://"), "{}", preset.name);
            } else {
                assert!(preset.url.starts_with("https://"), "{}", preset.name);
                assert!(preset.anchor_url.starts_with("https://"), "{}", preset.name);
            }
            assert_eq!(preset.alg, "sha256");
        }
        assert_eq!(find("nope"), None);
    }

    /// One endpoint must not appear twice: two ids for one authority would both
    /// be written by `install --preset public` and both pinned.
    #[test]
    fn no_endpoint_and_no_id_repeats() {
        for (index, preset) in PRESETS.iter().enumerate() {
            for other in &PRESETS[index + 1..] {
                assert_ne!(preset.name, other.name, "{} is named twice", preset.name);
                assert_ne!(
                    preset.url, other.url,
                    "{} and {} share an endpoint",
                    preset.name, other.name
                );
            }
        }
    }

    #[test]
    fn every_known_root_is_pinned_by_fingerprint() {
        let pinned: Vec<&str> = PRESETS
            .iter()
            .filter(|preset| preset.fingerprint.is_some())
            .map(|preset| preset.name)
            .collect();
        // The three with a published root, and not one of the TOFU presets.
        assert_eq!(pinned, ["freetsa", "sectigo", "certum", "izenpe"]);
        for name in &pinned {
            let fingerprint = find(name).and_then(|preset| preset.fingerprint);
            let fingerprint = fingerprint.expect("a pinned root");
            let parts: Vec<&str> = fingerprint.split(':').collect();
            assert_eq!(parts.len(), 32, "{name}: a SHA-256 has 32 octets");
            for part in parts {
                assert_eq!(part.len(), 2, "{name}: two uppercase hex digits");
                assert!(
                    part.bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase()),
                    "{name}: `{part}` is uppercase hex"
                );
            }
        }
    }

    #[test]
    fn the_tofu_presets_come_last_and_the_originals_first() {
        // The two originals stay first (a reorder is a user-visible change to
        // what `install` writes), the three published roots follow, and only
        // then the TOFU additions — with the one exception of `ai-moda`, which
        // is an original and TOFU.
        assert_eq!(
            names().take(5).collect::<Vec<_>>(),
            ["freetsa", "ai-moda", "sectigo", "certum", "izenpe"]
        );
        assert!(
            PRESETS[5..]
                .iter()
                .all(|preset| preset.fingerprint.is_none()),
            "a pinned root after a TOFU preset"
        );
    }

    #[test]
    fn exactly_the_http_endpoints_are_marked_insecure() {
        let insecure: Vec<&str> = PRESETS
            .iter()
            .filter(|preset| preset.insecure_http)
            .map(|preset| preset.name)
            .collect();
        assert_eq!(
            insecure,
            [
                "certum",
                "izenpe",
                "acs-microsoft",
                "globalsign-r6",
                "cartaodecidadao",
                "swisssign",
                "apple",
                "dfn",
                "globalsign-advanced",
                "comodoca",
                "digicert",
                "identrust",
                "quovadis-eu",
                "ssl-com",
                "belgium",
                "cra-ge",
                "lex-persona",
                "accv",
            ]
        );
    }
}
