//! WinZip AES encryption (AE-1 and AE-2), the scheme 7-Zip, WinZip,
//! libarchive and Velociraptor write for password-protected zips.
//!
//! An encrypted entry's data is: salt, a 2-byte password verifier, the
//! AES-CTR ciphertext, then a 10-byte HMAC-SHA1 of the ciphertext. Keys come
//! from PBKDF2-HMAC-SHA1 (1,000 rounds) over the password and salt. The
//! counter is little-endian and starts at 1. AE-1 also keeps the CRC-32 of
//! the plaintext; AE-2 zeroes it and relies on the HMAC alone.
//!
//! The primitives are RustCrypto's (`aes`, `ctr`, `hmac`, `pbkdf2`, `sha1`):
//! cryptography is not written in-house (decision D11).

use std::io::{self, Read};

use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use hmac::{Hmac, Mac};
use sha1::Sha1;

/// Compression method recorded for AES entries; the real one is in the
/// extra field.
pub(crate) const METHOD: u16 = 99;
/// Extra field holding the AES parameters.
const EXTRA_ID: u16 = 0x9901;
const VENDOR_ID: &[u8; 2] = b"AE";
const PBKDF2_ROUNDS: u32 = 1000;
const VERIFIER_SIZE: u64 = 2;
/// Truncated HMAC-SHA1 stored after the ciphertext.
pub(crate) const AUTH_CODE_SIZE: u64 = 10;
/// The CTR counter block starts at 1, little-endian.
const INITIAL_COUNTER: [u8; 16] = {
    let mut block = [0u8; 16];
    block[0] = 1;
    block
};

/// AES key size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// AES-128.
    Aes128,
    /// AES-192.
    Aes192,
    /// AES-256.
    Aes256,
}

impl Strength {
    const fn key_size(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    const fn salt_size(self) -> u64 {
        self.key_size() as u64 / 2
    }
}

/// AES parameters of one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes {
    /// Key size.
    pub strength: Strength,
    /// Whether the entry is AE-2 (CRC-32 zeroed, HMAC only).
    pub ae2: bool,
    /// The compression method applied before encryption.
    pub method: u16,
}

impl Aes {
    /// Bytes the scheme adds around the ciphertext.
    pub(crate) const fn overhead(self) -> u64 {
        self.strength.salt_size() + VERIFIER_SIZE + AUTH_CODE_SIZE
    }

    /// Bytes before the ciphertext: salt and verifier.
    pub(crate) const fn header_size(self) -> u64 {
        self.strength.salt_size() + VERIFIER_SIZE
    }
}

/// The AES parameters in an entry's extra field, if any.
pub(crate) fn parse_extra(extra: &[u8]) -> Option<Aes> {
    let mut rest = extra;
    while rest.len() >= 4 {
        let id = u16::from_le_bytes([rest[0], rest[1]]);
        let length = usize::from(u16::from_le_bytes([rest[2], rest[3]]));
        let field = rest.get(4..4 + length)?;
        rest = &rest[4 + length..];
        if id != EXTRA_ID || field.len() < 7 || &field[2..4] != VENDOR_ID {
            continue;
        }
        let strength = match field[4] {
            1 => Strength::Aes128,
            2 => Strength::Aes192,
            3 => Strength::Aes256,
            _ => return None,
        };
        return Some(Aes {
            strength,
            ae2: u16::from_le_bytes([field[0], field[1]]) == 2,
            method: u16::from_le_bytes([field[5], field[6]]),
        });
    }
    None
}

/// AES-CTR with WinZip's little-endian counter, for any key size.
pub(crate) enum Cipher {
    Aes128(ctr::Ctr128LE<aes::Aes128>),
    Aes192(ctr::Ctr128LE<aes::Aes192>),
    Aes256(ctr::Ctr128LE<aes::Aes256>),
}

impl Cipher {
    /// Decrypt `buf` in place at the current position.
    pub(crate) fn apply(&mut self, buf: &mut [u8]) {
        match self {
            Self::Aes128(c) => c.apply_keystream(buf),
            Self::Aes192(c) => c.apply_keystream(buf),
            Self::Aes256(c) => c.apply_keystream(buf),
        }
    }

    /// Move to byte `position` of the plaintext.
    pub(crate) fn seek(&mut self, position: u64) {
        match self {
            Self::Aes128(c) => c.seek(position),
            Self::Aes192(c) => c.seek(position),
            Self::Aes256(c) => c.seek(position),
        }
    }
}

/// The keys of one entry.
pub(crate) struct Keys {
    pub(crate) cipher: Cipher,
    pub(crate) mac: Hmac<Sha1>,
}

/// Derive the keys of an entry from its `salt_and_verifier` header.
///
/// # Errors
/// [`io::ErrorKind::PermissionDenied`] when the password is wrong.
pub(crate) fn keys(aes: Aes, password: &[u8], salt_and_verifier: &[u8]) -> io::Result<Keys> {
    let salt_size = aes.strength.salt_size() as usize;
    let (salt, verifier) = salt_and_verifier.split_at(salt_size);
    let key_size = aes.strength.key_size();
    let mut derived = vec![0u8; 2 * key_size + VERIFIER_SIZE as usize];
    pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, PBKDF2_ROUNDS, &mut derived);
    let (encryption_key, rest) = derived.split_at(key_size);
    let (mac_key, expected_verifier) = rest.split_at(key_size);
    if expected_verifier != verifier {
        return Err(wrong_password());
    }
    let cipher = match aes.strength {
        Strength::Aes128 => Cipher::Aes128(ctr::Ctr128LE::new(
            encryption_key.into(),
            &INITIAL_COUNTER.into(),
        )),
        Strength::Aes192 => Cipher::Aes192(ctr::Ctr128LE::new(
            encryption_key.into(),
            &INITIAL_COUNTER.into(),
        )),
        Strength::Aes256 => Cipher::Aes256(ctr::Ctr128LE::new(
            encryption_key.into(),
            &INITIAL_COUNTER.into(),
        )),
    };
    let mac = Hmac::<Sha1>::new_from_slice(mac_key).expect("HMAC accepts any key size");
    Ok(Keys { cipher, mac })
}

/// Check the truncated HMAC stored after the ciphertext.
///
/// # Errors
/// [`io::ErrorKind::InvalidData`] when it doesn't match.
pub(crate) fn check_auth_code(mac: Hmac<Sha1>, stored: &[u8]) -> io::Result<()> {
    let computed = mac.finalize().into_bytes();
    if computed[..AUTH_CODE_SIZE as usize] == *stored {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zip entry authentication code mismatch: content corrupted or altered",
        ))
    }
}

pub(crate) fn wrong_password() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "wrong password for encrypted zip entry",
    )
}

/// Streams the plaintext of an entry, authenticating the ciphertext.
pub(crate) struct Decrypt<R> {
    inner: R,
    keys: Keys,
    /// Ciphertext bytes not read yet.
    remaining: u64,
    authenticated: bool,
}

impl<R: Read> Decrypt<R> {
    /// `inner` is positioned at the ciphertext, which is `length` bytes long
    /// and followed by the authentication code.
    pub(crate) const fn new(inner: R, keys: Keys, length: u64) -> Self {
        Self {
            inner,
            keys,
            remaining: length,
            authenticated: false,
        }
    }

    /// Read what's left of the ciphertext and check the authentication
    /// code. Called once the plaintext has been consumed.
    ///
    /// # Errors
    /// On read errors or an authentication failure.
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if self.authenticated {
            return Ok(());
        }
        io::copy(self, &mut io::sink())?;
        let mut stored = [0u8; AUTH_CODE_SIZE as usize];
        self.inner.read_exact(&mut stored)?;
        check_auth_code(self.keys.mac.clone(), &stored)?;
        self.authenticated = true;
        Ok(())
    }
}

impl<R: Read> Read for Decrypt<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let wanted = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        if wanted == 0 {
            return Ok(0);
        }
        let count = self.inner.read(&mut buf[..wanted])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "encrypted zip entry truncated",
            ));
        }
        self.keys.mac.update(&buf[..count]);
        self.keys.cipher.apply(&mut buf[..count]);
        self.remaining -= count as u64;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_extra_field() {
        // AE-2, "AE", AES-256, deflated.
        let extra = [0x01, 0x99, 7, 0, 2, 0, b'A', b'E', 3, 8, 0];
        let aes = parse_extra(&extra).unwrap();
        assert_eq!(aes.strength, Strength::Aes256);
        assert!(aes.ae2);
        assert_eq!(aes.method, 8);
        assert_eq!(aes.overhead(), 16 + 2 + 10);
    }

    #[test]
    fn ignores_other_and_truncated_fields() {
        assert_eq!(parse_extra(&[0x01, 0x00, 0, 0]), None);
        assert_eq!(parse_extra(&[0x01, 0x99, 7, 0, 2, 0]), None);
        assert_eq!(
            parse_extra(&[0x01, 0x99, 7, 0, 2, 0, b'X', b'Y', 3, 8, 0]),
            None
        );
    }
}
