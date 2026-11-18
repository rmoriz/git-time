//! The built-in public authority presets.
//!
//! One static table, read by `install`, `tsa select` and by
//! `git time tsa preset add <name>`; both write exactly the same keys from it,
//! so the two surfaces cannot drift apart.
//!
//! A preset carries where the authority is reached (`url`), where its anchor
//! bundle is fetched from (`anchor_url`), the imprint algorithm requests ask
//! for, the policy they request, and — where the root is known — the
//! fingerprint that root must have.
//!
//! The order is deliberate: the curated default first, then the rest of the
//! measured roots, then the ones that are trust on first use. FreeTSA publishes
//! a plain PEM; for every other preset the anchor URL *is* the endpoint, because
//! no certificate download is served there. The fetch asks the endpoint for a
//! token and takes the self-signed root of the chain it replies with. None of
//! those certificate URLs could be measured from here, so none are invented.
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
//! the first pin reviewable.
//!
//! # Which two are the default
//!
//! `freetsa` and `digicert`. DigiCert carries a measured fingerprint and is the
//! most available of the remaining set; Sectigo is not the second default
//! because its endpoint refuses the TLS handshake on some stacks. Two, not one,
//! so `required = 1` still has a second authority to fall back on, and no more
//! than two because every configured authority costs a request on every commit
//! and every plain-http one costs a warning line. The rest is opt-in.
//!
//! `ai-moda` was dropped from the table: it appears on no live-TSA list we were
//! given, and as a load balancer over several CAs it is the one authority that
//! can never have a correct pinned fingerprint — it answered with a DigiCert
//! root the day it was measured.
//!
//! # Where the fingerprints come from
//!
//! **Measured** — every value below was obtained by querying the endpoint and
//! walking the chain: the certificates of the reply, and the AIA `caIssuers`
//! pointer where the root was not embedded. They are SHA-1 fingerprints, the
//! form those authorities publish. Two values are SHA-256 instead: FreeTSA's
//! (published that way) and izenpe's (supplied below). Both lengths are
//! compared, chosen by the length of the expectation — see [`matching_digest`]
//! in the CLI.
//!
//! **Supplied but unverified** — `izenpe`. Retrieving its root failed (its AIA
//! URL answers something that is not a certificate), so the value is the
//! repository owner's — in SHA-256 — and has never been compared against a live
//! chain.
//!
//! Two earlier values were wrong for their endpoint and were replaced by the
//! measured ones: `sectigo` had the fingerprint of a different Sectigo root than
//! the one this endpoint chains to (`Sectigo Qualified Time Stamping Root R45`),
//! and `certum` had `5C:58:46:8D:…` where the endpoint chains to
//! `07:E0:32:E0:…` (`Certum Trusted Network CA`).
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
    /// The fingerprint the root must have, uppercase and colon separated,
    /// when the root is known in advance: 20 octets when the authority
    /// publishes SHA-1, 32 for FreeTSA's SHA-256. `None` is trust on first use.
    pub fingerprint: Option<&'static str>,
    /// Whether the endpoint is plain `http://` and is accepted as such.
    pub insecure_http: bool,
    /// Whether the curated default writes it.
    ///
    /// [`curated`] is a prefix of the table. A default that queries every
    /// endpoint and warns about every plain-http transport on every commit is not
    /// a default, it is a denial of service against the user's own latency
    /// budget; the rest is opt-in through the selector or `tsa preset add`.
    pub curated: bool,
}

/// The built-in presets, in the order they are written: the two originals, the
/// three with a published root, then the seven that are trust on first use.
pub const PRESETS: [Preset; 22] = [
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
        curated: true,
    },
    Preset {
        name: "digicert",
        url: "http://timestamp.digicert.com",
        anchor_url: "http://timestamp.digicert.com",
        alg: "sha256",
        policy: None,
        fingerprint: Some("05:63:B8:63:0D:62:D7:5A:BB:C8:AB:1E:4B:DF:B5:A8:99:B2:4D:43"),
        insecure_http: true,
        curated: true,
    },
    Preset {
        name: "sectigo",
        url: "https://timestamp.sectigo.com/qualified",
        // A plain GET is not served; the fetch asks for a token and takes the
        // root of the chain it replies with.
        anchor_url: "https://timestamp.sectigo.com/qualified",
        alg: "sha256",
        policy: None,
        fingerprint: Some("CB:73:94:4C:04:2E:53:BF:C4:57:9D:2F:71:2F:3E:EA:99:FE:43:07"),
        insecure_http: false,
        curated: false,
    },
    Preset {
        name: "certum",
        url: "http://time.certum.pl",
        anchor_url: "http://time.certum.pl",
        alg: "sha256",
        policy: None,
        fingerprint: Some("07:E0:32:E0:20:B7:2C:3F:19:2F:06:28:A2:59:3A:19:A7:0F:06:9E"),
        insecure_http: true,
        curated: false,
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
        curated: false,
    },
    // Three endpoints keep no fingerprint: for comodoca, cartaodecidadao and
    // swisssign no root could be measured here. Their fetched fingerprint is
    // printed and has to be compared by a reader.
    Preset {
        name: "acs-microsoft",
        url: "http://timestamp.acs.microsoft.com",
        anchor_url: "http://timestamp.acs.microsoft.com",
        alg: "sha256",
        policy: None,
        fingerprint: Some("F4:00:42:E2:E5:F7:E8:EF:81:89:FE:D1:55:19:AE:CE:42:C3:BF:A2"),
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "globalsign-r6",
        url: "http://timestamp.globalsign.com/tsa/r6advanced1",
        anchor_url: "http://timestamp.globalsign.com/tsa/r6advanced1",
        alg: "sha256",
        policy: None,
        fingerprint: Some("13:9B:1C:71:2F:D1:7C:3C:A5:DA:6E:57:01:AF:BA:01:58:F9:D4:5D"),
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "aped",
        url: "https://timestamp.aped.gov.gr/qtss",
        anchor_url: "https://timestamp.aped.gov.gr/qtss",
        alg: "sha256",
        policy: None,
        fingerprint: Some("44:4D:AE:31:5D:00:21:9C:6A:15:2F:0C:C0:2A:AE:32:3B:F9:C6:AC"),
        insecure_http: false,
        curated: false,
    },
    Preset {
        name: "cartaodecidadao",
        url: "http://ts.cartaodecidadao.pt/tsa/server",
        anchor_url: "http://ts.cartaodecidadao.pt/tsa/server",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "swisssign",
        url: "http://tsa.swisssign.net",
        anchor_url: "http://tsa.swisssign.net",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "apple",
        url: "http://timestamp.apple.com/ts01",
        anchor_url: "http://timestamp.apple.com/ts01",
        alg: "sha256",
        policy: None,
        fingerprint: Some("61:1E:5B:66:2C:59:3A:08:FF:58:D1:4A:E2:24:52:D1:98:DF:6C:60"),
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "dfn",
        url: "http://zeitstempel.dfn.de",
        anchor_url: "http://zeitstempel.dfn.de",
        alg: "sha256",
        policy: None,
        fingerprint: Some("58:81:54:65:3F:9F:C8:5A:37:F5:79:BC:FA:CD:2B:1D:D9:10:84:EE"),
        insecure_http: true,
        curated: false,
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
        fingerprint: Some("13:9B:1C:71:2F:D1:7C:3C:A5:DA:6E:57:01:AF:BA:01:58:F9:D4:5D"),
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "comodoca",
        url: "http://timestamp.comodoca.com",
        anchor_url: "http://timestamp.comodoca.com",
        alg: "sha256",
        policy: None,
        fingerprint: None,
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "identrust",
        url: "http://timestamp.identrust.com",
        anchor_url: "http://timestamp.identrust.com",
        alg: "sha256",
        policy: None,
        fingerprint: Some("BA:29:41:60:77:98:3F:F4:F3:EF:F2:31:05:3B:2E:EA:6D:4D:45:FD"),
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "quovadis-eu",
        url: "http://ts.quovadisglobal.com/eu",
        anchor_url: "http://ts.quovadisglobal.com/eu",
        alg: "sha256",
        policy: None,
        fingerprint: Some("1B:8E:EA:57:96:29:1A:C9:39:EA:B8:0A:81:1A:73:73:C0:93:79:67"),
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "ssl-com",
        url: "http://ts.ssl.com",
        anchor_url: "http://ts.ssl.com",
        alg: "sha256",
        policy: None,
        fingerprint: Some("B7:AB:33:08:D1:EA:44:77:BA:14:80:12:5A:6F:BD:A9:36:49:0C:BB"),
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "belgium",
        url: "http://tsa.belgium.be/connect",
        anchor_url: "http://tsa.belgium.be/connect",
        alg: "sha256",
        policy: None,
        fingerprint: Some("98:98:9F:EE:C1:6A:D7:74:61:54:15:E9:3A:96:3E:A3:EE:F5:FE:4F"),
        insecure_http: true,
        curated: false,
    },
    Preset {
        // The same authority also answers on `http://tsa.cesnet.cz:3161/tsa`;
        // the TLS port is the one worth carrying.
        name: "cesnet",
        url: "https://tsa.cesnet.cz:3162/tsa",
        anchor_url: "https://tsa.cesnet.cz:3162/tsa",
        alg: "sha256",
        policy: None,
        fingerprint: Some("E7:84:74:90:F7:11:43:FC:CE:F6:F6:5A:30:DA:1F:23:9E:0F:D7:BA"),
        insecure_http: false,
        curated: false,
    },
    Preset {
        // The query string is part of the endpoint: it selects the worker and
        // is stored and posted verbatim.
        name: "cra-ge",
        url: "http://tsa.cra.ge/signserver/tsa?workerName=qtsa",
        anchor_url: "http://tsa.cra.ge/signserver/tsa?workerName=qtsa",
        alg: "sha256",
        policy: None,
        fingerprint: Some("9E:79:CD:4E:A8:C2:79:08:11:D6:DA:43:ED:23:90:A6:CE:FF:35:3C"),
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "lex-persona",
        url: "http://tsa.lex-persona.com/tsa",
        anchor_url: "http://tsa.lex-persona.com/tsa",
        alg: "sha256",
        policy: None,
        fingerprint: Some("88:21:9A:14:A6:A1:FF:5B:62:25:17:F7:00:1E:C3:02:C3:11:01:D7"),
        insecure_http: true,
        curated: false,
    },
    Preset {
        name: "accv",
        url: "http://tss.accv.es:8318/tsa",
        anchor_url: "http://tss.accv.es:8318/tsa",
        alg: "sha256",
        policy: None,
        fingerprint: Some("93:05:7A:88:15:C6:4F:CE:88:2F:FA:91:16:52:28:78:BC:53:64:17"),
        insecure_http: true,
        curated: false,
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

/// The presets the selector ticks on a fresh repository: the curated default.
///
/// They are a prefix of [`PRESETS`], so the order `install` writes is always the
/// table order.
pub fn curated() -> impl Iterator<Item = &'static Preset> {
    PRESETS.iter().filter(|preset| preset.curated)
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
    /// be written by a fresh selection and both pinned.
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

    /// Every pinned root is spelled the way it is compared: uppercase hex
    /// octets separated by colons, 20 of them for a SHA-1 and 32 for FreeTSA's
    /// SHA-256. A value in the wrong spelling would never match.
    #[test]
    fn every_pinned_root_has_a_well_formed_fingerprint() {
        for preset in &PRESETS {
            let Some(fingerprint) = preset.fingerprint else {
                continue;
            };
            let parts: Vec<&str> = fingerprint.split(':').collect();
            // SHA-1 everywhere but the two SHA-256 values: FreeTSA's measured
            // one and izenpe's supplied one.
            let expected = if matches!(preset.name, "freetsa" | "izenpe") {
                32
            } else {
                20
            };
            assert_eq!(parts.len(), expected, "{}: {expected} octets", preset.name);
            for part in parts {
                assert_eq!(part.len(), 2, "{}: two uppercase hex digits", preset.name);
                assert!(
                    part.bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase()),
                    "{}: `{part}` is uppercase hex",
                    preset.name
                );
            }
        }
    }

    /// Exactly three endpoints keep no fingerprint, and they are the ones whose
    /// root could not be measured.
    #[test]
    fn only_the_unmeasurable_endpoints_are_tofu() {
        let tofu: Vec<&str> = PRESETS
            .iter()
            .filter(|preset| preset.fingerprint.is_none())
            .map(|preset| preset.name)
            .collect();
        assert_eq!(tofu, ["cartaodecidadao", "swisssign", "comodoca"]);

        let pinned: Vec<&str> = PRESETS
            .iter()
            .filter(|preset| preset.fingerprint.is_some())
            .map(|preset| preset.name)
            .collect();
        assert_eq!(pinned.len(), PRESETS.len() - tofu.len());
    }

    /// The default scope stays small and pinned: a preset that fires a request
    /// on every commit is opt-in, and the curated ones are a prefix so `install`
    /// writes them in table order.
    #[test]
    fn the_curated_default_is_two_pinned_roots_and_a_prefix() {
        let curated: Vec<&str> = curated().map(|preset| preset.name).collect();
        assert_eq!(curated, ["freetsa", "digicert"]);
        assert_eq!(
            PRESETS[..curated.len()]
                .iter()
                .map(|preset| preset.name)
                .collect::<Vec<_>>(),
            curated,
            "the curated presets come first"
        );
    }

    /// The curated default stays first: a reorder is a user-visible change to
    /// what `install` writes, and to the indices `tsa select` shows.
    #[test]
    fn the_curated_pair_stays_first() {
        assert_eq!(
            names().take(5).collect::<Vec<_>>(),
            ["freetsa", "digicert", "sectigo", "certum", "izenpe"]
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
                "digicert",
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
