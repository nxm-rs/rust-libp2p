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
    io::{Cursor, Read, Write},
};

use libp2p_core::multihash::Multihash;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Digest;
use time::{Duration, OffsetDateTime};

// Certificates MUST use the NamedCurve encoding for elliptic curve parameters. The libp2p
// WebTransport spec requires an ECDSA (non-RSA) self-signed certificate; browsers additionally
// require P-256 for the `serverCertificateHashes` path.
static SIGNATURE_ALGORITHM: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

pub(crate) const MULTIHASH_SHA256_CODE: u64 = 0x12;
// The libp2p WebTransport spec allows up to 14 days, but browsers (Chromium) reject certificates
// whose validity window is at/above the 2-week boundary for the `serverCertificateHashes` path, so
// we stay comfortably under it (this also leaves margin for clock skew).
const CERT_VALID_PERIOD: Duration = Duration::days(13);

pub type CertHash = Multihash<64>;

// I would like to avoid interacting with the file system as much as possible.
// My suggestion would be:
// - libp2p::webtransport::Transport::new takes a list of certificates (of type
//   libp2p::webtransport::Certificate)
// - libp2p::webtransport::Certificate::generate allows users generate a new certificate with
//   certain parameters (validity date etc)
// - libp2p::webtransport::Certificate::{parse,to_bytes} allow users to serialize and deserialize
//   certificates
#[derive(Debug, PartialEq, Eq)]
pub struct Certificate {
    der: CertificateDer<'static>,
    private_key_der: PrivateKeyDer<'static>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
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
            private_key_der: self.private_key_der.clone_key(),
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
    /// [spec]: https://github.com/libp2p/specs/blob/master/webtransport/README.md
    pub fn generate(not_before: OffsetDateTime) -> Result<Self, Error> {
        let not_after = not_before
            .checked_add(CERT_VALID_PERIOD)
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
        let private_key_der =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        Ok(Self {
            der,
            private_key_der,
            not_before,
            not_after,
        })
    }

    pub fn get_certificate_der(&self) -> CertificateDer<'static> {
        self.der.clone()
    }

    pub fn get_private_key_der(&self) -> &PrivateKeyDer<'_> {
        &self.private_key_der
    }

    pub fn cert_hash(&self) -> CertHash {
        Multihash::wrap(
            MULTIHASH_SHA256_CODE,
            sha2::Sha256::digest(self.der.as_ref()).as_ref(),
        )
        .expect("fingerprint's len to be 32 bytes")
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        Self::write_data(&mut bytes, self.der.as_ref()).expect("Write cert data");
        Self::write_data(&mut bytes, self.private_key_der.secret_der())
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
        let private_key = PrivateKeyDer::try_from(private_key_data).unwrap();
        let not_before = OffsetDateTime::from_unix_timestamp(nb).unwrap();
        let not_after = OffsetDateTime::from_unix_timestamp(na).unwrap();

        Ok(Self {
            der: cert,
            private_key_der: private_key,
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
    use time::macros::datetime;

    #[test]
    fn test_certificate_parsing() {
        let not_before = datetime!(2025-08-08 0:00 UTC);
        let cert = super::Certificate::generate(not_before).unwrap();

        let binary_data = cert.to_bytes();
        let actual = super::Certificate::parse(binary_data.as_slice()).unwrap();

        assert_eq!(actual, cert);
    }
}
