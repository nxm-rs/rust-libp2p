use std::{
    io,
    io::{Cursor, Read, Write},
};

use libp2p_core::multihash::Multihash;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Digest;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

// Certificates MUST use the NamedCurve encoding for elliptic curve parameters. The libp2p
// WebTransport spec requires an ECDSA (non-RSA) self-signed certificate; browsers additionally
// require P-256 for the `serverCertificateHashes` path.
static SIGNATURE_ALGORITHM: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

pub(crate) const MULTIHASH_SHA256_CODE: u64 = 0x12;

/// Clock-skew slack applied to each edge of a certificate's served validity window.
///
/// The `not_before` of a freshly minted certificate is backdated by this amount and its served
/// validity is `certValidity - 2 * CLOCK_SKEW_ALLOWANCE`, matching go-libp2p. The backdate makes a
/// dialer whose clock lags slightly still accept the certificate (instead of rejecting it as "not
/// yet valid"); see [`Config::generate`](crate::Config::generate) for the full rotation model.
pub(crate) const CLOCK_SKEW_ALLOWANCE: Duration = Duration::hours(1);

// The libp2p WebTransport spec allows up to 14 days, but browsers (Chromium) reject certificates
// whose validity window is at/above the 2-week boundary for the `serverCertificateHashes` path, so
// we stay comfortably under it. This is the *total* window (including the clock-skew backdate); the
// served validity handed to dialers is `CERT_VALID_PERIOD - 2 * CLOCK_SKEW_ALLOWANCE`.
pub(crate) const CERT_VALID_PERIOD: Duration = Duration::days(13);

pub type CertHash = Multihash<64>;

// I would like to avoid interacting with the file system as much as possible.
// My suggestion would be:
// - libp2p::webtransport::Transport::new takes a list of certificates (of type
//   libp2p::webtransport::Certificate)
// - libp2p::webtransport::Certificate::generate allows users generate a new certificate with
//   certain parameters (validity date etc)
// - libp2p::webtransport::Certificate::{parse,to_bytes} allow users to serialize and deserialize
//   certificates
/// A self-signed WebTransport server certificate together with its private key and validity
/// window.
///
/// The private key is held as PKCS#8 DER bytes in a [`Zeroizing`] buffer so the key material is
/// wiped from memory when the certificate is dropped. The transport drops expired certificates
/// promptly during rotation, so key material is not retained beyond its useful life.
#[derive(PartialEq, Eq)]
pub struct Certificate {
    der: CertificateDer<'static>,
    /// PKCS#8-encoded private key bytes. Held in a zeroizing buffer so the secret is wiped on
    /// drop; reconstruct a borrowed [`PrivateKeyDer`] via [`Self::get_private_key_der`].
    private_key_pkcs8: Zeroizing<Vec<u8>>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

// Manual `Debug` that never prints the private key material.
impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("der", &self.der)
            .field("private_key_pkcs8", &"<redacted>")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish()
    }
}

#[derive(Debug)]
pub enum Error {
    GenError(rcgen::Error),
    IoError(io::Error),
}

impl From<rcgen::Error> for Error {
    fn from(value: rcgen::Error) -> Self {
        Self::GenError(value)
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::IoError(value)
    }
}

impl Clone for Certificate {
    fn clone(&self) -> Self {
        Self {
            der: self.der.clone(),
            private_key_pkcs8: self.private_key_pkcs8.clone(),
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }
}

impl Certificate {
    /// Generates a fresh, short-lived self-signed certificate for a WebTransport endpoint.
    ///
    /// Per the [libp2p WebTransport spec][spec] this is a **plain** ECDSA P-256 self-signed
    /// certificate valid for at most 14 days — it deliberately does **not** carry the libp2p
    /// identity (that is authenticated over Noise). Its SHA-256 hash ([`Self::cert_hash`]) is
    /// advertised in the listen multiaddr and pinned by dialers (including browsers via
    /// `serverCertificateHashes`).
    ///
    /// See also [`Config::generate`](crate::Config::generate), which builds the standard
    /// current+next certificate set with the clock-skew-adjusted, backdated windows used for
    /// rotation, rather than a single bare certificate.
    ///
    /// [spec]: https://github.com/libp2p/specs/blob/master/webtransport/README.md
    pub fn generate(not_before: OffsetDateTime) -> Result<Self, Error> {
        Self::generate_with_validity(not_before, CERT_VALID_PERIOD)
    }

    /// Generates a self-signed certificate valid from `not_before` for the given `validity_period`.
    ///
    /// This is the generation seam used by [`generate`](Self::generate) and by
    /// [`Config::generate`](crate::Config::generate). It is exposed primarily so tests can mint
    /// certificates with sub-second validity windows to exercise certificate rotation in bounded
    /// time; production callers should prefer [`Config::generate`](crate::Config::generate).
    ///
    /// The validity window must stay strictly under 14 days for browser (Chromium) interop on the
    /// `serverCertificateHashes` path; this is the caller's responsibility.
    pub fn generate_with_validity(
        not_before: OffsetDateTime,
        validity_period: Duration,
    ) -> Result<Self, Error> {
        let not_after = not_before
            .checked_add(validity_period)
            .expect("Addition does not overflow");

        let key_pair = rcgen::KeyPair::generate_for(SIGNATURE_ALGORITHM)?;
        // Browsers (Chromium) require a Subject Alternative Name even on a hash-pinned
        // certificate. The names are not used for verification (the certificate is pinned by its
        // SHA-256 hash and the peer is authenticated over Noise), but at least one must be present.
        let mut params = rcgen::CertificateParams::new(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params.self_signed(&key_pair)?;

        let der = cert.der().clone();
        let private_key_pkcs8 = Zeroizing::new(key_pair.serialize_der());

        Ok(Self {
            der,
            private_key_pkcs8,
            not_before,
            not_after,
        })
    }

    /// The instant at which this certificate becomes valid.
    ///
    /// Freshly generated certificates backdate this by a one-hour clock-skew allowance (via
    /// [`Config::generate`](crate::Config::generate)) so dialers with a slightly lagging clock do
    /// not reject the certificate as "not yet valid".
    pub fn not_before(&self) -> OffsetDateTime {
        self.not_before
    }

    /// The instant at which this certificate expires. The transport rotates to a successor before
    /// this is reached and never serves a certificate whose `not_after` is in the past.
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    pub fn get_certificate_der(&self) -> CertificateDer<'static> {
        self.der.clone()
    }

    pub fn get_private_key_der(&self) -> PrivateKeyDer<'_> {
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.private_key_pkcs8.as_slice()))
    }

    pub fn cert_hash(&self) -> CertHash {
        Multihash::wrap(
            MULTIHASH_SHA256_CODE,
            sha2::Sha256::digest(self.der.as_ref()).as_ref(),
        )
        .expect("fingerprint's len to be 32 bytes")
    }

    /// Serializes the certificate, its private key, and validity window to bytes.
    ///
    /// **Sensitive:** the returned buffer contains the raw private key material in the clear. The
    /// caller is responsible for protecting and zeroizing it (the buffer is a plain `Vec<u8>` and
    /// is *not* zeroized on drop).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        Self::write_data(&mut bytes, self.der.as_ref()).expect("Write cert data");
        Self::write_data(&mut bytes, self.private_key_pkcs8.as_slice())
            .expect("Write private_key data");

        let nb_buff = self.not_before.unix_timestamp().to_be_bytes();
        std::io::Write::write(&mut bytes, &nb_buff).expect("Write not_before");

        let na_buff = self.not_after.unix_timestamp().to_be_bytes();
        std::io::Write::write(&mut bytes, &na_buff).expect("Write not_after");

        bytes
    }

    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(data);
        let cert_data = Self::read_data(&mut cursor)?;
        let private_key_data = Self::read_data(&mut cursor)?;
        let nb = Self::read_i64(&mut cursor).unwrap();
        let na = Self::read_i64(&mut cursor).unwrap();

        let cert = CertificateDer::from(cert_data);
        let not_before = OffsetDateTime::from_unix_timestamp(nb).unwrap();
        let not_after = OffsetDateTime::from_unix_timestamp(na).unwrap();

        Ok(Self {
            der: cert,
            private_key_pkcs8: Zeroizing::new(private_key_data),
            not_before,
            not_after,
        })
    }

    fn write_data<W: Write>(w: &mut W, data: &[u8]) -> Result<(), io::Error> {
        let size = data.len() as u64;
        let size_buf = size.to_be_bytes();

        w.write_all(&size_buf)?;
        w.write_all(data)?;

        Ok(())
    }

    fn read_data<R: Read>(r: &mut R) -> Result<Vec<u8>, io::Error> {
        let size = Self::read_i64(r)? as usize;
        let mut res = vec![0u8; size];

        r.read_exact(res.as_mut_slice())?;

        Ok(res)
    }

    fn read_i64<R: Read>(r: &mut R) -> Result<i64, io::Error> {
        let mut buffer = [0u8; 8];
        r.read_exact(&mut buffer)?;

        Ok(i64::from_be_bytes(buffer))
    }
}

#[cfg(test)]
mod tests {
    use time::{Duration, macros::datetime};

    use super::{CERT_VALID_PERIOD, Certificate};

    #[test]
    fn test_certificate_parsing() {
        let not_before = datetime!(2025-08-08 0:00 UTC);
        let cert = Certificate::generate(not_before).unwrap();

        let binary_data = cert.to_bytes();
        let actual = Certificate::parse(binary_data.as_slice()).unwrap();

        assert_eq!(actual, cert);
    }

    // C1: accessors return the stored not_before / not_after.
    #[test]
    fn accessors_return_stored_window() {
        let not_before = datetime!(2025-08-08 0:00 UTC);
        let cert = Certificate::generate(not_before).unwrap();

        assert_eq!(cert.not_before(), not_before);
        assert_eq!(cert.not_after(), not_before + CERT_VALID_PERIOD);
    }

    // C2: served window stays strictly under the 14-day browser ceiling.
    #[test]
    fn validity_window_under_14_days() {
        assert!(CERT_VALID_PERIOD < Duration::days(14));

        let not_before = datetime!(2025-08-08 0:00 UTC);
        let cert = Certificate::generate(not_before).unwrap();
        assert!(cert.not_after() - cert.not_before() < Duration::days(14));
    }

    // C4: to_bytes / parse preserves accessor values.
    #[test]
    fn roundtrip_preserves_accessors() {
        let not_before = datetime!(2025-08-08 0:00 UTC);
        let cert = Certificate::generate(not_before).unwrap();
        let parsed = Certificate::parse(&cert.to_bytes()).unwrap();

        assert_eq!(parsed.not_before(), cert.not_before());
        assert_eq!(parsed.not_after(), cert.not_after());
    }

    // C5: distinct certificates hash differently.
    #[test]
    fn distinct_certs_hash_differently() {
        let not_before = datetime!(2025-08-08 0:00 UTC);
        let a = Certificate::generate(not_before).unwrap();
        let b = Certificate::generate(not_before).unwrap();

        assert_ne!(a.cert_hash(), b.cert_hash());
    }

    // C6: a sub-second validity window mints a still-valid hash via the generation seam.
    #[test]
    fn short_validity_seam_mints_hash() {
        let not_before = datetime!(2025-08-08 0:00 UTC);
        let cert = Certificate::generate_with_validity(not_before, Duration::seconds(2)).unwrap();

        assert_eq!(cert.not_after() - cert.not_before(), Duration::seconds(2));
        // Hash is well-formed (32-byte SHA-256 multihash).
        assert_eq!(cert.cert_hash().digest().len(), 32);
    }
}
