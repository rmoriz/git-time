//! The built-in public authority presets.
//!
//! One static table, read by `install`, `tsa select` and by
//! `git time tsa preset add <name>`; both write exactly the same keys from it,
//! so the two surfaces cannot drift apart.
//!
//! A preset carries where the authority is reached (`url`), where its anchor
//! bundle is fetched from (`anchor_url`), the imprint algorithm requests ask
//! for, the policy they request, and — where the root is known — every
//! fingerprint a published root of that authority carries.
//!
//! The order is deliberate: the curated default first, then the rest of the
//! measured roots. No built-in preset is left to trust on first use. FreeTSA
//! and DFN publish a plain PEM; for every other preset the anchor URL *is* the
//! endpoint, because no certificate download is served there. The fetch asks the
//! endpoint for a token and takes the self-signed root of the chain it replies
//! with (and walks the top certificate's AIA `caIssuers` where the root is not
//! embedded).
//! No certificate URL is invented: where one is listed it was fetched and its
//! fingerprint checked against the measured pin — that is the Portuguese state
//! PKI's publication of `ECRaizEstado 002` for `cartaodecidadao`, whose own reply
//! stops at the signing leaf. A download is read in PEM, DER or PKCS#7.
//!
//! # Why expected fingerprints
//!
//! An anchor that is simply accepted as fetched is trust on first use: whatever
//! the network hands back on the first `install` becomes the root every later
//! verification trusts. That is fine until the first fetch is the wrong one.
//! A fingerprint makes the first pin *verifiable* — the bundle is accepted only
//! when its first certificate hashes to a value published for that authority,
//! and a mismatch leaves the previous pin alone and says both values.
//!
//! Where no fingerprint is known the fetch is TOFU, so the writer prints the
//! fetched root fingerprint prominently: that line is the only thing that makes
//! the first pin reviewable.
//!
//! # A rotation is a list, newest last
//!
//! A root rotation leaves two legitimate values in the wild: the retired root
//! still backs every token it signed. One slot meant either dropping the
//! retired value — and refusing its tokens on the next fetch, under a spurious
//! mismatch warning — or accepting only the old one. So each preset carries a
//! list. A fetch is accepted when *any* value matches; the retired value stays
//! until the authority no longer serves it, and the value it publishes now stays
//! last so a display can name it without printing the whole list. An empty list
//! is trust on first use, and a list that matches nothing is still a refusal.
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
//! # Where the fingerprints come from
//!
//! **Measured** — every value below was obtained by querying the endpoint and
//! walking the chain: the certificates of the reply, and the AIA `caIssuers`
//! pointer where the root was not embedded. They are SHA-1 fingerprints, the
//! form those authorities publish. Two values are SHA-256 instead: FreeTSA's
//! (published that way) and izenpe's (supplied below). Each value is compared
//! in its own length, chosen from the value — see [`matching_digest`] in the
//! CLI — so a preset may carry both spellings of one root: `freetsa`'s SHA-1
//! is the older slot of the very root whose SHA-256 it publishes.
//!
//! **Supplied, then confirmed** — `izenpe`. The value is the repository owner's
//! and in SHA-256, because retrieving its root failed at the time; the AIA walk
//! now reaches the same root and the live run compares against it.
//!
//! Two earlier values were wrong for their endpoint and were replaced by the
//! measured ones: `sectigo` had the fingerprint of a different Sectigo root than
//! the one this endpoint chains to (`Sectigo Qualified Time Stamping Root R45`),
//! and `certum` had `5C:58:46:8D:…` where the endpoint chains to
//! `07:E0:32:E0:…` (`Certum Trusted Network CA`).
//!
//! # When the roots expire
//!
//! Each row also carries the `notAfter` of its newest published root. It is a
//! measurement of the same kind as the fingerprints, taken at release through
//! `tsa preset list --refresh`, and the one value here that goes stale on its
//! own — a test fails once a date passes. A row within a year of its date is
//! rotated or dropped before the tag; a root that has already expired is a
//! release that was cut too late.
//!
//! The date is display material only and the weakest there is: a pinned bundle
//! and a probe both win over it, it never decides a matching, and a listing says
//! `listed <date>` so it cannot be read as a pin. A pin keeps printing the
//! fetched certificate's own date.
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

use std::path::Path;

/// One public authority a preset configures.
///
/// Every field is `Copy`, so the type stays `Copy`: a table row can be read by
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preset {
    /// The config id and the anchor file stem.
    pub name: &'static str,
    /// The timestamp endpoint.
    pub url: &'static str,
    /// Where the anchor bundle is fetched from.
    pub anchor_url: &'static str,
    /// Certificates to append to the bundle, between the root and the signer.
    ///
    /// Empty for every authority whose reply or `caIssuers` already reaches the
    /// root. `cartaodecidadao` embeds the signing leaf alone and publishes no
    /// `caIssuers` at all, so its whole path has to be named.
    pub chain: &'static [&'static str],
    /// The imprint algorithm and the algorithm requests ask for.
    pub alg: &'static str,
    /// The TSA policy requests ask for, when the authority has a published one.
    pub policy: Option<&'static str>,
    /// Every fingerprint a published root of this authority carries, newest
    /// last, uppercase and colon separated: 20 octets when the authority
    /// publishes SHA-1, 32 when it publishes SHA-256. Empty is trust on first
    /// use.
    ///
    /// A rotation leaves two legitimate roots in the wild, so this is a list
    /// and a match against any entry is a match. The retired value stays so a
    /// fetch of it is still accepted, and the newest stays last so a display
    /// can name what the authority publishes now. Each value is compared in
    /// the digest length it is written in, so one authority may carry both a
    /// SHA-1 and a SHA-256 spelling.
    ///
    /// # Examples
    ///
    /// ```
    /// use git_time_core::presets;
    ///
    /// let freetsa = presets::find("freetsa").expect("a pinned preset");
    /// assert!(!freetsa.fingerprints.is_empty());
    ///
    /// // FreeTSA publishes both spellings of one root, so a match may be either.
    /// assert!(freetsa.fingerprints.len() > 1);
    /// ```
    ///
    /// An empty list is trust on first use. No built-in preset is in that
    /// position today: each one's root was measured.
    pub fingerprints: &'static [&'static str],
    /// The `notAfter` of the newest root [`fingerprints`] ends on, as
    /// `YYYY-MM-DD`. `None` where nothing is published.
    ///
    /// This is the one value here that goes stale on its own, so it is
    /// re-measured at every release: `tsa preset list --refresh` names what each
    /// authority serves and a row within a year of expiry is rotated or dropped
    /// before the tag. A test fails once a date passes, which is how the expiry
    /// reaches a release decision instead of a user.
    ///
    /// Display material only, and the weakest one there is: a pinned bundle and
    /// a probe both win over it, and a pin still prints the fetched
    /// certificate's own date.
    pub not_after: Option<&'static str>,
    /// Whether the endpoint is plain `http://` and is accepted as such.
    pub insecure_http: bool,
    /// Where this authority's bundle is pinned, when the repository configured a
    /// path other than the default `dir()/<name>.pem`. `None` is the default.
    pub anchor_path: Option<&'static Path>,
    /// Whether the curated default writes it.
    ///
    /// [`curated`] is a prefix of the table. A default that queries every
    /// endpoint and warns about every plain-http transport on every commit is not
    /// a default, it is a denial of service against the user's own latency
    /// budget; the rest is opt-in through the selector or `tsa preset add`.
    pub curated: bool,
}

/// The built-in presets, in the order they are written: the two originals, then
/// the rest in the order they were measured.
pub const PRESETS: [Preset; 21] = [
    Preset {
        name: "freetsa",
        url: "https://freetsa.org/tsr",
        anchor_url: "https://freetsa.org/files/cacert.pem",
        chain: &[],
        alg: "sha256",
        policy: Some("1.2.3.4.1"),
        // The same published root in both spellings: its SHA-1, and the
        // SHA-256 FreeTSA publishes now. Newest last.
        fingerprints: &[
            "0B:93:07:6C:81:39:FA:2B:83:38:5F:78:28:D7:BE:75:73:40:D2:41",
            "A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC",
        ],
        not_after: Some("2041-03-07"),
        insecure_http: false,
        anchor_path: None,
        curated: true,
    },
    Preset {
        name: "digicert",
        url: "http://timestamp.digicert.com",
        anchor_url: "http://timestamp.digicert.com",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["05:63:B8:63:0D:62:D7:5A:BB:C8:AB:1E:4B:DF:B5:A8:99:B2:4D:43"],
        not_after: Some("2031-11-10"),
        insecure_http: true,
        anchor_path: None,
        curated: true,
    },
    Preset {
        name: "sectigo",
        url: "https://timestamp.sectigo.com/qualified",
        // A plain GET is not served; the fetch asks for a token and takes the
        // root of the chain it replies with.
        anchor_url: "https://timestamp.sectigo.com/qualified",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["CB:73:94:4C:04:2E:53:BF:C4:57:9D:2F:71:2F:3E:EA:99:FE:43:07"],
        not_after: Some("2045-10-04"),
        insecure_http: false,
        anchor_path: None,
        curated: false,
    },
    Preset {
        // The live list also carries `certum-legacy`, naming exactly this
        // endpoint; an authority keeps one row, so it is not repeated here.
        name: "certum",
        url: "http://time.certum.pl",
        anchor_url: "http://time.certum.pl",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["07:E0:32:E0:20:B7:2C:3F:19:2F:06:28:A2:59:3A:19:A7:0F:06:9E"],
        not_after: Some("2029-12-31"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "izenpe",
        url: "http://tsa.izenpe.com",
        anchor_url: "http://tsa.izenpe.com",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &[
            "8E:5B:8B:AE:DC:4D:58:BE:0E:30:1C:CC:B6:ED:17:3C:08:D7:C7:7C:E4:35:09:73:38:9F:F1:AF:A1:1D:7A:65",
        ],
        not_after: Some("2045-09-23"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "acs-microsoft",
        url: "http://timestamp.acs.microsoft.com",
        anchor_url: "http://timestamp.acs.microsoft.com",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["F4:00:42:E2:E5:F7:E8:EF:81:89:FE:D1:55:19:AE:CE:42:C3:BF:A2"],
        not_after: Some("2045-04-16"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "globalsign-r6",
        url: "http://timestamp.globalsign.com/tsa/r6advanced1",
        anchor_url: "http://timestamp.globalsign.com/tsa/r6advanced1",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &[
            "13:9B:1C:71:2F:D1:7C:3C:A5:DA:6E:57:01:AF:BA:01:58:F9:D4:5D",
            "80:94:64:0E:B5:A7:A1:CA:11:9C:1F:DD:D5:9F:81:02:63:A7:FB:D1",
        ],
        not_after: Some("2034-12-10"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "aped",
        url: "https://timestamp.aped.gov.gr/qtss",
        anchor_url: "https://timestamp.aped.gov.gr/qtss",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["44:4D:AE:31:5D:00:21:9C:6A:15:2F:0C:C0:2A:AE:32:3B:F9:C6:AC"],
        not_after: Some("2039-08-05"),
        insecure_http: false,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "cartaodecidadao",
        url: "http://ts.cartaodecidadao.pt/tsa/server",
        anchor_url: "https://www.ecce.gov.pt/media/5085/ecraizestado002.crt",
        chain: &[
            "https://pki.cartaodecidadao.pt/publico/certificado/cc_ec_cidadao_assinatura/EC%20de%20Assinatura%20Digital%20Qualificada%20do%20Cartao%20de%20Cidadao%200018.cer",
            "https://pki.cartaodecidadao.pt/publico/certificado/cc_ec_cidadao/Cartao%20de%20Cidadao%20006.cer",
        ],
        alg: "sha256",
        policy: None,
        fingerprints: &["E8:9D:08:31:6C:29:D1:15:74:9A:27:ED:58:13:32:CB:0A:B4:D7:9F"],
        not_after: Some("2043-10-04"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "apple",
        url: "http://timestamp.apple.com/ts01",
        anchor_url: "http://timestamp.apple.com/ts01",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["61:1E:5B:66:2C:59:3A:08:FF:58:D1:4A:E2:24:52:D1:98:DF:6C:60"],
        not_after: Some("2035-02-09"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "dfn",
        url: "http://zeitstempel.dfn.de",
        // DFN's own CA publication (`cacert.pem` next to `cdp1`/`cdp2`), not the
        // endpoint: the pin comes from the authority's published root rather than
        // from a token fetched over the same plain-http channel.
        anchor_url: "http://cdp1.pca.dfn.de/dfn-verein-community-root-ca/pub/cacert/cacert.pem",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["58:81:54:65:3F:9F:C8:5A:37:F5:79:BC:FA:CD:2B:1D:D9:10:84:EE"],
        not_after: Some("2042-01-21"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "globalsign-advanced",
        url: "http://rfc3161timestamp.globalsign.com/advanced",
        anchor_url: "http://rfc3161timestamp.globalsign.com/advanced",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &[
            "13:9B:1C:71:2F:D1:7C:3C:A5:DA:6E:57:01:AF:BA:01:58:F9:D4:5D",
            "80:94:64:0E:B5:A7:A1:CA:11:9C:1F:DD:D5:9F:81:02:63:A7:FB:D1",
        ],
        not_after: Some("2034-12-10"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "comodoca",
        url: "http://timestamp.comodoca.com",
        anchor_url: "http://timestamp.comodoca.com",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["52:42:1A:EA:C4:24:C2:43:5E:7F:53:55:A3:04:37:A3:B1:74:58:79"],
        not_after: Some("2046-03-21"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "identrust",
        url: "http://timestamp.identrust.com",
        anchor_url: "http://timestamp.identrust.com",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["BA:29:41:60:77:98:3F:F4:F3:EF:F2:31:05:3B:2E:EA:6D:4D:45:FD"],
        not_after: Some("2034-01-16"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "quovadis-eu",
        url: "http://ts.quovadisglobal.com/eu",
        anchor_url: "http://ts.quovadisglobal.com/eu",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["1B:8E:EA:57:96:29:1A:C9:39:EA:B8:0A:81:1A:73:73:C0:93:79:67"],
        not_after: Some("2042-01-12"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "ssl-com",
        url: "http://ts.ssl.com",
        anchor_url: "http://ts.ssl.com",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["B7:AB:33:08:D1:EA:44:77:BA:14:80:12:5A:6F:BD:A9:36:49:0C:BB"],
        not_after: Some("2041-02-12"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "belgium",
        url: "http://tsa.belgium.be/connect",
        anchor_url: "http://tsa.belgium.be/connect",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["98:98:9F:EE:C1:6A:D7:74:61:54:15:E9:3A:96:3E:A3:EE:F5:FE:4F"],
        not_after: Some("2040-06-03"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        // The same authority also answers on `http://tsa.cesnet.cz:3161/tsa`;
        // the TLS port is the one worth carrying.
        name: "cesnet",
        url: "https://tsa.cesnet.cz:3162/tsa",
        anchor_url: "https://tsa.cesnet.cz:3162/tsa",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["E7:84:74:90:F7:11:43:FC:CE:F6:F6:5A:30:DA:1F:23:9E:0F:D7:BA"],
        not_after: Some("2029-02-24"),
        insecure_http: false,
        anchor_path: None,
        curated: false,
    },
    Preset {
        // The query string is part of the endpoint: it selects the worker and
        // is stored and posted verbatim.
        name: "cra-ge",
        url: "http://tsa.cra.ge/signserver/tsa?workerName=qtsa",
        anchor_url: "http://tsa.cra.ge/signserver/tsa?workerName=qtsa",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["9E:79:CD:4E:A8:C2:79:08:11:D6:DA:43:ED:23:90:A6:CE:FF:35:3C"],
        not_after: Some("2045-10-26"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "lex-persona",
        url: "http://tsa.lex-persona.com/tsa",
        anchor_url: "http://tsa.lex-persona.com/tsa",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["88:21:9A:14:A6:A1:FF:5B:62:25:17:F7:00:1E:C3:02:C3:11:01:D7"],
        not_after: Some("2031-10-26"),
        insecure_http: true,
        anchor_path: None,
        curated: false,
    },
    Preset {
        name: "accv",
        url: "http://tss.accv.es:8318/tsa",
        anchor_url: "http://tss.accv.es:8318/tsa",
        chain: &[],
        alg: "sha256",
        policy: None,
        fingerprints: &["93:05:7A:88:15:C6:4F:CE:88:2F:FA:91:16:52:28:78:BC:53:64:17"],
        not_after: Some("2030-12-31"),
        insecure_http: true,
        anchor_path: None,
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
    fn a_table_row_can_carry_the_date_its_newest_root_expires() {
        let freetsa = find("freetsa").expect("a preset");
        assert_eq!(freetsa.not_after, Some("2041-03-07"));
    }

    /// Every row carries a date, spelled the one way the listings compare it.
    #[test]
    fn every_preset_carries_a_well_formed_not_after() {
        for preset in &PRESETS {
            let not_after = preset
                .not_after
                .unwrap_or_else(|| panic!("{}", preset.name));
            assert_eq!(not_after.len(), 10, "{}", preset.name);
            assert!(
                not_after.parse::<jiff::civil::Date>().is_ok(),
                "{}: {not_after}",
                preset.name
            );
        }
    }

    /// The canary: a root that has expired is a release decision, not a user's
    /// surprise. A failure here means the row is rotated or dropped, then the
    /// date is re-measured.
    #[test]
    fn no_preset_has_already_expired() {
        let today = jiff::Timestamp::now()
            .to_zoned(jiff::tz::TimeZone::UTC)
            .date();
        for preset in &PRESETS {
            let not_after = preset
                .not_after
                .expect("a date")
                .parse::<jiff::civil::Date>()
                .expect("a date");
            assert!(not_after > today, "{}: {not_after}", preset.name);
        }
    }

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
            // Only an accepted plain-http preset may carry an `http://` URL.
            // The anchor URL is not bound to that: `insecure_http` is about the
            // endpoint the tokens come from, and a download may still be served
            // over TLS (`cartaodecidadao`).
            if preset.insecure_http {
                assert!(preset.url.starts_with("http://"), "{}", preset.name);
            } else {
                assert!(preset.url.starts_with("https://"), "{}", preset.name);
            }
            assert!(
                preset.anchor_url.starts_with("https://")
                    || preset.anchor_url.starts_with("http://"),
                "{}",
                preset.name
            );
            assert_eq!(preset.alg, "sha256");
        }
        assert_eq!(find("nope"), None);
    }

    /// Only `cartaodecidadao` names a chain, because only its reply neither
    /// embeds the path nor publishes `caIssuers`; every other preset must fetch
    /// without one.
    #[test]
    fn only_cartaodecidadao_names_a_chain() {
        for preset in &PRESETS {
            let expected = if preset.name == "cartaodecidadao" {
                2
            } else {
                0
            };
            assert_eq!(preset.chain.len(), expected, "{}", preset.name);
        }
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
    /// octets separated by colons, 20 of them for a SHA-1 and 32 for the
    /// SHA-256 values. A value in the wrong spelling would never match. An
    /// older slot of a rotated root may be either length; the newest one is
    /// the length the authority publishes it in.
    #[test]
    fn every_pinned_root_has_a_well_formed_fingerprint() {
        for preset in &PRESETS {
            let mut seen: Vec<&str> = Vec::new();
            for (index, fingerprint) in preset.fingerprints.iter().enumerate() {
                let newest = index + 1 == preset.fingerprints.len();
                let parts: Vec<&str> = fingerprint.split(':').collect();
                match (newest, matches!(preset.name, "freetsa" | "izenpe")) {
                    // SHA-256 everywhere but the one SHA-1 value and the older
                    // slot.
                    (true, true) => {
                        assert_eq!(parts.len(), 32, "{}: 32 octets", preset.name);
                    }
                    (true, false) => {
                        assert_eq!(parts.len(), 20, "{}: 20 octets", preset.name);
                    }
                    (false, _) => {
                        assert!(
                            matches!(parts.len(), 20 | 32),
                            "{}: an older value is a SHA-1 or a SHA-256",
                            preset.name
                        );
                    }
                }
                for part in parts {
                    assert_eq!(part.len(), 2, "{}: two uppercase hex digits", preset.name);
                    assert!(
                        part.bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase()),
                        "{}: `{part}` is uppercase hex",
                        preset.name
                    );
                }
                assert!(
                    !seen.contains(fingerprint),
                    "{}: {fingerprint} is listed twice",
                    preset.name
                );
                seen.push(fingerprint);
            }
        }
    }

    /// The one rotated preset keeps the retired spelling first and the value
    /// the authority publishes now last, so a display can name the newest.
    #[test]
    fn a_rotation_keeps_the_retired_value_and_the_newest_last() {
        let freetsa = find("freetsa").expect("the preset");
        assert_eq!(freetsa.fingerprints.len(), 2);
        assert_eq!(
            freetsa.fingerprints[1].split(':').count(),
            32,
            "the current SHA-256 is last"
        );
        assert_eq!(
            freetsa.fingerprints[0].split(':').count(),
            20,
            "the retired SHA-1 stays first"
        );
    }

    /// No built-in endpoint is trust on first use any more: every row was
    /// measured. The empty-list branch stays for a future one that cannot be.
    #[test]
    fn only_the_unmeasurable_endpoints_are_tofu() {
        let tofu: Vec<&str> = PRESETS
            .iter()
            .filter(|preset| preset.fingerprints.is_empty())
            .map(|preset| preset.name)
            .collect();
        assert_eq!(tofu, Vec::<&str>::new(), "every row carries a fingerprint");

        let pinned: Vec<&str> = PRESETS
            .iter()
            .filter(|preset| !preset.fingerprints.is_empty())
            .map(|preset| preset.name)
            .collect();
        assert_eq!(pinned.len(), PRESETS.len(), "nothing is left to TOFU");
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
