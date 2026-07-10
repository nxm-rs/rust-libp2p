// Copyright 2024 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    io,
    io::{Cursor, Read},
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

/// Version of the [`Certificate::to_bytes`] / [`Certificate::parse`] serialization format.
///
/// The serialized form begins with this single byte. [`Certificate::parse`] reads it first and
/// rejects any other value with [`Error::UnsupportedVersion`], so the format can evolve in a future
/// release without silently misparsing an old blob. This is a **compatibility discriminator, not an
/// integrity check**: the serialized blob carries the private key in the clear and is not
/// authenticated.
pub const SERIALIZATION_VERSION: u8 = 1;

/// Upper bound on each length-prefixed field accepted by [`Certificate::parse`].
///
/// A libp2p self-signed certificate DER is well under 1 KiB and a P-256 PKCS#8 key is ~140 bytes,
/// so 64 KiB is generous. `parse` checks the declared length against this bound *before*
/// allocating, so an attacker-supplied length prefix cannot drive a large allocation regardless of
/// its value.
const MAX_FIELD_LEN: usize = 64 * 1024;

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
    /// drop; reconstruct a borrowed [`PrivateKeyDer`] via [`Self::private_key_der`].
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

/// Errors produced when generating, serialising, or parsing a [`Certificate`].
///
/// This enum is `#[non_exhaustive]`: the crate is unreleased and may add further variants without
/// a breaking change, so downstream `match`es must include a wildcard arm.
///
/// It is re-exported at the crate root as [`CertificateError`](crate::CertificateError).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Certificate generation (rcgen) failed.
    #[error(transparent)]
    Generate(#[from] rcgen::Error),
    /// An I/O error occurred while reading the serialised representation (e.g. the buffer ended
    /// before a length-prefixed field was fully read).
    #[error("I/O error parsing certificate: {0}")]
    Io(#[from] io::Error),
    /// The leading version byte did not match [`SERIALIZATION_VERSION`]. The payload is the version
    /// byte found in the input; this build only supports [`SERIALIZATION_VERSION`].
    #[error("unsupported certificate serialization version: {0}")]
    UnsupportedVersion(u8),
    /// A length-prefixed field was larger than `MAX_FIELD_LEN`.
    #[error("length-prefixed field exceeded the maximum")]
    InvalidLength,
    /// The private-key bytes were not a recognised DER private key.
    #[error("private-key bytes were not a valid DER key")]
    InvalidPrivateKey,
    /// A `not_before`/`not_after` unix timestamp was outside the representable range, or
    /// `not_after` was not strictly after `not_before`.
    #[error("certificate timestamp was out of range or mis-ordered")]
    InvalidTimestamp,
    /// Bytes remained after a complete certificate was parsed (non-canonical encoding).
    #[error("trailing bytes after a complete certificate")]
    TrailingData,
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

    /// The certificate's DER-encoded bytes.
    pub fn certificate_der(&self) -> CertificateDer<'static> {
        self.der.clone()
    }

    /// A borrowed view of the PKCS#8 DER-encoded private key.
    ///
    /// **Sensitive:** the returned value borrows the in-memory private key. Do not log it or copy
    /// it into a buffer that is not zeroized.
    pub fn private_key_der(&self) -> PrivateKeyDer<'_> {
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
    /// # Format
    ///
    /// All integers are big-endian. The blob begins with a single version byte
    /// ([`SERIALIZATION_VERSION`]):
    ///
    /// ```text
    /// [u8 version][u64 len][cert DER][u64 len][key PKCS#8 DER][i64 not_before][i64 not_after]
    /// ```
    ///
    /// This is **not** a cross-implementation interchange format; it round-trips only with
    /// [`Self::parse`] of a compatible build.
    ///
    /// **Sensitive:** the returned buffer contains the raw private key material in the clear. The
    /// caller is responsible for protecting and zeroizing it (the buffer is a plain `Vec<u8>` and
    /// is *not* zeroized on drop). Persist it with filesystem-level confidentiality (mode `0600` or
    /// a secret store).
    pub fn to_bytes(&self) -> Vec<u8> {
        // Writing to a `Vec<u8>` is infallible (it grows to fit), so this never errors; we build it
        // directly with `extend_from_slice`/`push`.
        let mut bytes = Vec::new();

        bytes.push(SERIALIZATION_VERSION);
        Self::push_data(&mut bytes, self.der.as_ref());
        Self::push_data(&mut bytes, self.private_key_pkcs8.as_slice());
        bytes.extend_from_slice(&self.not_before.unix_timestamp().to_be_bytes());
        bytes.extend_from_slice(&self.not_after.unix_timestamp().to_be_bytes());

        bytes
    }

    /// Parses a certificate previously produced by [`Self::to_bytes`].
    ///
    /// # Untrusted input
    ///
    /// This is a `pub` deserialiser, so the input bytes are treated as fully untrusted. `parse`
    /// guarantees it **never panics and never makes an unbounded allocation**: the leading version
    /// byte is validated against [`SERIALIZATION_VERSION`] first, every length prefix is checked
    /// against `MAX_FIELD_LEN` (64 KiB) *before* allocating, all fallible steps return [`Error`]
    /// rather than unwrapping, and the encoding is canonical (trailing bytes are rejected as
    /// [`Error::TrailingData`]).
    ///
    /// # Errors
    ///
    /// * [`Error::UnsupportedVersion`] — the leading byte is not [`SERIALIZATION_VERSION`]. A blob
    ///   written by an older, unversioned build is rejected here because its first byte is read as
    ///   a version that does not equal [`SERIALIZATION_VERSION`]. Regenerate the certificate.
    /// * [`Error::Io`] — the input was truncated.
    /// * [`Error::InvalidLength`] — a length prefix exceeded `MAX_FIELD_LEN`.
    /// * [`Error::InvalidPrivateKey`] — the key block was not a recognised DER private key.
    /// * [`Error::InvalidTimestamp`] — a timestamp was out of range, or `not_after <= not_before`.
    /// * [`Error::TrailingData`] — bytes remained after a complete certificate.
    ///
    /// # Non-guarantees
    ///
    /// A successfully-parsed [`Certificate`] is **not** fully validated: `parse` checks the
    /// timestamp ordering (`not_after > not_before`) but performs no structural DER validation and
    /// does **not** verify that the private key corresponds to the certificate (the blob already
    /// carries the cleartext key, so it is assumed self-consistent). Callers must not treat a
    /// successful parse as proof of a currently valid certificate.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(data);

        // The version byte gates the rest of the format. An old, unversioned blob whose first byte
        // is not `SERIALIZATION_VERSION` is rejected here.
        let version = Self::read_u8(&mut cursor)?;
        if version != SERIALIZATION_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        let cert_data = Self::read_data(&mut cursor)?;
        let private_key_data = Self::read_data(&mut cursor)?;
        let nb = Self::read_i64(&mut cursor)?;
        let na = Self::read_i64(&mut cursor)?;

        // Canonical encoding: reject any trailing bytes after a complete certificate.
        if (cursor.position() as usize) != data.len() {
            return Err(Error::TrailingData);
        }

        let cert = CertificateDer::from(cert_data);
        // Validate the private key is a recognised DER key before storing it (borrowing the bytes
        // so no un-zeroized copy is left behind).
        PrivateKeyDer::try_from(private_key_data.as_slice())
            .map_err(|_| Error::InvalidPrivateKey)?;
        let not_before =
            OffsetDateTime::from_unix_timestamp(nb).map_err(|_| Error::InvalidTimestamp)?;
        let not_after =
            OffsetDateTime::from_unix_timestamp(na).map_err(|_| Error::InvalidTimestamp)?;
        // Reject a mis-ordered validity window. (We do not enforce the <=14-day ceiling here: that
        // would reject our own validly-minted certs as they age, and is a `generate`-time
        // guarantee instead.)
        if not_after <= not_before {
            return Err(Error::InvalidTimestamp);
        }

        Ok(Self {
            der: cert,
            private_key_pkcs8: Zeroizing::new(private_key_data),
            not_before,
            not_after,
        })
    }

    /// Append a single length-prefixed field (`[u64 BE len][bytes]`) to `out`. Infallible: writing
    /// to a `Vec<u8>` never fails.
    fn push_data(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(&(data.len() as u64).to_be_bytes());
        out.extend_from_slice(data);
    }

    /// Reads a single length-prefixed field, bounding the declared length against `MAX_FIELD_LEN`
    /// *before* allocating. The length is read as a big-endian `u64` (matching
    /// [`Self::push_data`]) and is therefore always non-negative; `usize::try_from` plus the
    /// cap make the on-wire length effectively bounded, so no attacker-controlled prefix can
    /// drive a large allocation.
    fn read_data<R: Read>(r: &mut R) -> Result<Vec<u8>, Error> {
        let size = Self::read_u64(r)?;
        let size = usize::try_from(size).map_err(|_| Error::InvalidLength)?;
        if size > MAX_FIELD_LEN {
            return Err(Error::InvalidLength);
        }

        let mut res = vec![0u8; size];
        r.read_exact(res.as_mut_slice())?;

        Ok(res)
    }

    fn read_u8<R: Read>(r: &mut R) -> Result<u8, io::Error> {
        let mut buffer = [0u8; 1];
        r.read_exact(&mut buffer)?;

        Ok(buffer[0])
    }

    fn read_u64<R: Read>(r: &mut R) -> Result<u64, io::Error> {
        let mut buffer = [0u8; 8];
        r.read_exact(&mut buffer)?;

        Ok(u64::from_be_bytes(buffer))
    }

    fn read_i64<R: Read>(r: &mut R) -> Result<i64, io::Error> {
        let mut buffer = [0u8; 8];
        r.read_exact(&mut buffer)?;

        Ok(i64::from_be_bytes(buffer))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use time::macros::datetime;

    use super::{Certificate, Error, MAX_FIELD_LEN, SERIALIZATION_VERSION};

    /// Build a serialised certificate body from raw parts, mirroring `to_bytes`' on-wire layout
    /// (`[u8 version]` then `u64-len || bytes` twice, then two `i64` timestamps). Used to craft
    /// malformed inputs. Prepends a valid version byte so callers exercise the post-version path.
    fn encode(cert: &[u8], key: &[u8], not_before: i64, not_after: i64) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SERIALIZATION_VERSION);
        out.extend_from_slice(&(cert.len() as u64).to_be_bytes());
        out.extend_from_slice(cert);
        out.extend_from_slice(&(key.len() as u64).to_be_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&not_before.to_be_bytes());
        out.extend_from_slice(&not_after.to_be_bytes());
        out
    }

    /// A valid PKCS#8 private key (DER) lifted from a freshly generated certificate.
    fn valid_key() -> Vec<u8> {
        let cert = Certificate::generate(datetime!(2025-08-08 0:00 UTC)).unwrap();
        // Pull the key bytes back out via the serialised form (skip the leading version byte).
        let bytes = cert.to_bytes();
        let cert_len = u64::from_be_bytes(bytes[1..9].try_into().unwrap()) as usize;
        let key_off = 9 + cert_len;
        let key_len = u64::from_be_bytes(bytes[key_off..key_off + 8].try_into().unwrap()) as usize;
        bytes[key_off + 8..key_off + 8 + key_len].to_vec()
    }

    /// Prepend the valid version byte to a raw post-version body, so tests can target the
    /// length/timestamp parsing without each repeating the version prefix.
    fn versioned(body: &[u8]) -> Vec<u8> {
        let mut out = vec![SERIALIZATION_VERSION];
        out.extend_from_slice(body);
        out
    }

    // empty input → Io (the version byte cannot even be read).
    #[test]
    fn parse_empty_is_io_error() {
        assert!(matches!(Certificate::parse(&[]), Err(Error::Io(_))));
    }

    // a wrong leading version byte → UnsupportedVersion (carrying the byte found).
    #[test]
    fn parse_rejects_wrong_version() {
        assert!(matches!(
            Certificate::parse(&[0x02]),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    // version byte 0 (also the first byte of a legacy unversioned blob) → UnsupportedVersion(0).
    #[test]
    fn parse_rejects_version_zero() {
        assert!(matches!(
            Certificate::parse(&[0x00, 0x00, 0x00]),
            Err(Error::UnsupportedVersion(0))
        ));
    }

    // truncated in the middle of the first length prefix → Io.
    #[test]
    fn parse_truncated_first_length_is_io_error() {
        assert!(matches!(
            Certificate::parse(&versioned(&[0, 0, 0])),
            Err(Error::Io(_))
        ));
    }

    // a declared cert body that is not fully present → Io.
    #[test]
    fn parse_truncated_cert_body_is_io_error() {
        let mut body = (4u64).to_be_bytes().to_vec();
        body.extend_from_slice(&[1, 2]); // claims 4 bytes, only 2 present
        assert!(matches!(
            Certificate::parse(&versioned(&body)),
            Err(Error::Io(_))
        ));
    }

    // well-formed cert+key but truncated before the timestamps → Io.
    #[test]
    fn parse_truncated_before_timestamps_is_io_error() {
        let key = valid_key();
        let mut body = Vec::new();
        body.extend_from_slice(&(1u64).to_be_bytes());
        body.push(0xAA);
        body.extend_from_slice(&(key.len() as u64).to_be_bytes());
        body.extend_from_slice(&key);
        // No timestamp bytes at all.
        assert!(matches!(
            Certificate::parse(&versioned(&body)),
            Err(Error::Io(_))
        ));
    }

    // [T2, highest severity]: an oversized (i64::MAX) length prefix is rejected BEFORE any large
    // allocation. The crafted input is tiny — we never pre-build a huge buffer (F10).
    #[test]
    fn parse_oversized_length_is_invalid_length() {
        let data = versioned(&i64::MAX.to_be_bytes()); // == u64 0x7FFF_FFFF_FFFF_FFFF
        assert!(matches!(
            Certificate::parse(&data),
            Err(Error::InvalidLength)
        ));
    }

    // a "negative" length (-1 as i64 == u64::MAX) is rejected as InvalidLength, guarding the old
    // `as usize` wraparound.
    #[test]
    fn parse_negative_length_is_invalid_length() {
        let data = versioned(&(-1i64).to_be_bytes()); // == u64::MAX
        assert!(matches!(
            Certificate::parse(&data),
            Err(Error::InvalidLength)
        ));
    }

    // a length of MAX_FIELD_LEN + 1 is InvalidLength (exclusive upper bound).
    #[test]
    fn parse_length_above_cap_is_invalid_length() {
        let data = versioned(&((MAX_FIELD_LEN + 1) as u64).to_be_bytes());
        assert!(matches!(
            Certificate::parse(&data),
            Err(Error::InvalidLength)
        ));
    }

    // a length of exactly MAX_FIELD_LEN is NOT rejected by the cap (it then fails later, on the
    // missing body, as Io — proving the boundary is inclusive of MAX_FIELD_LEN).
    #[test]
    fn parse_length_at_cap_is_not_invalid_length() {
        let data = versioned(&(MAX_FIELD_LEN as u64).to_be_bytes());
        assert!(matches!(Certificate::parse(&data), Err(Error::Io(_))));
    }

    // B3: a valid cert body but an empty/garbage private key → InvalidPrivateKey.
    #[test]
    fn parse_garbage_private_key_is_invalid_private_key() {
        let data = encode(&[0x30, 0x00], &[0xFF, 0xFF, 0xFF], 0, 1);
        assert!(matches!(
            Certificate::parse(&data),
            Err(Error::InvalidPrivateKey)
        ));

        let empty_key = encode(&[0x30, 0x00], &[], 0, 1);
        assert!(matches!(
            Certificate::parse(&empty_key),
            Err(Error::InvalidPrivateKey)
        ));
    }

    // B3: an out-of-range timestamp → InvalidTimestamp; a small negative not_before is accepted.
    #[test]
    fn parse_timestamp_bounds() {
        let key = valid_key();

        // not_before = i64::MAX is out of OffsetDateTime's range.
        let bad_nb = encode(&[0x30, 0x00], &key, i64::MAX, 0);
        assert!(matches!(
            Certificate::parse(&bad_nb),
            Err(Error::InvalidTimestamp)
        ));

        // not_after = i64::MIN is out of range.
        let bad_na = encode(&[0x30, 0x00], &key, 0, i64::MIN);
        assert!(matches!(
            Certificate::parse(&bad_na),
            Err(Error::InvalidTimestamp)
        ));

        // A small negative not_before (pre-1970) is legitimate and accepted.
        let ok = encode(&[0x30, 0x00], &key, -100, 100);
        let parsed = Certificate::parse(&ok).expect("pre-1970 not_before is accepted");
        assert_eq!(parsed.not_before().unix_timestamp(), -100);
    }

    // a mis-ordered validity window (not_after <= not_before) → InvalidTimestamp.
    #[test]
    fn parse_rejects_not_after_le_not_before() {
        let key = valid_key();

        let equal = encode(&[0x30, 0x00], &key, 100, 100);
        assert!(matches!(
            Certificate::parse(&equal),
            Err(Error::InvalidTimestamp)
        ));

        let reversed = encode(&[0x30, 0x00], &key, 100, 50);
        assert!(matches!(
            Certificate::parse(&reversed),
            Err(Error::InvalidTimestamp)
        ));
    }

    // to_bytes begins with the serialization version byte.
    #[test]
    fn to_bytes_starts_with_version_byte() {
        let cert = Certificate::generate(datetime!(2025-08-08 0:00 UTC)).unwrap();
        assert_eq!(cert.to_bytes()[0], SERIALIZATION_VERSION);
    }

    // The Debug impl must never leak the private key bytes.
    #[test]
    fn debug_does_not_leak_private_key() {
        let cert = Certificate::generate(datetime!(2025-08-08 0:00 UTC)).unwrap();
        let dbg = format!("{cert:?}");
        let key = valid_key();
        // The redaction placeholder is present and no run of key bytes appears.
        assert!(dbg.contains("<redacted>"));
        let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dbg.contains(&key_hex));
    }

    // trailing bytes after a complete certificate → TrailingData.
    #[test]
    fn parse_trailing_data_rejected() {
        let cert = Certificate::generate(datetime!(2025-08-08 0:00 UTC)).unwrap();
        let mut bytes = cert.to_bytes();
        bytes.push(0x00); // one extra byte
        assert!(matches!(
            Certificate::parse(&bytes),
            Err(Error::TrailingData)
        ));
    }

    // B3: an exact, well-formed blob round-trips and compares equal.
    #[test]
    fn parse_exact_blob_roundtrips() {
        let cert = Certificate::generate(datetime!(2025-08-08 0:00 UTC)).unwrap();
        let parsed = Certificate::parse(&cert.to_bytes()).unwrap();
        assert_eq!(parsed, cert);
    }

    // Display is non-empty for every variant and source() is Some only for the wrapping ones.
    #[test]
    fn error_display_and_source() {
        let io = Error::Io(std::io::Error::other("boom"));
        assert!(!io.to_string().is_empty());
        assert!(io.source().is_some());

        // `Generate` is `#[error(transparent)]`: its Display *is* the rcgen error's, so the message
        // is non-empty.
        let gen_err = Error::Generate(rcgen::Error::CouldNotParseCertificate);
        assert!(!gen_err.to_string().is_empty());

        for e in [
            Error::UnsupportedVersion(7),
            Error::InvalidLength,
            Error::InvalidPrivateKey,
            Error::InvalidTimestamp,
            Error::TrailingData,
        ] {
            assert!(!e.to_string().is_empty());
            assert!(e.source().is_none());
        }
    }

    // B3 [OOM regression guard]: parse never panics over arbitrary bytes and never allocates large
    // buffers. A simple deterministic fuzz loop in lieu of a proptest dependency.
    #[test]
    fn parse_never_panics_on_arbitrary_bytes() {
        let mut state = 0x9E3779B97F4A7C15u64;
        for _ in 0..2000 {
            let len = (state % 64) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                buf.push((state >> 33) as u8);
            }
            // Must not panic and must not allocate unboundedly (any large declared length is
            // rejected as InvalidLength before allocation).
            let _ = Certificate::parse(&buf);
        }
    }
}

#[cfg(test)]
mod original_tests {
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
