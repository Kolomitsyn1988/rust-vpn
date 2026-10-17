//! Key derivation and authenticated encryption.

use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use xsalsa20poly1305::aead::Aead;
use xsalsa20poly1305::{Key, KeyInit, Nonce, XSalsa20Poly1305};
use zeroize::{Zeroize, Zeroizing};

/// Length of the derived AEAD key.
pub const KEY_LEN: usize = 32;
/// Length of the per-frame nonce (XSalsa20 uses a 192-bit nonce).
pub const NONCE_LEN: usize = 24;
/// Length of the Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// Minimum accepted pre-shared key length.
pub const MIN_PSK_LEN: usize = 16;

const HKDF_SALT: &[u8] = b"rust-vpn v1 hkdf salt";
const HKDF_INFO: &[u8] = b"rust-vpn v1 session key";

/// Errors related to keys and encryption.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("PSK must be at least {MIN_PSK_LEN} bytes long, got {0}")]
    PskTooShort(usize),
    #[error("cannot read PSK file: {0}")]
    PskIo(#[from] std::io::Error),
    #[error("decryption failed (wrong PSK or corrupted frame)")]
    DecryptFailed,
}

/// An AEAD key derived from the pre-shared key.
///
/// Cheap to clone; the key material is zeroized on drop.
#[derive(Clone)]
pub struct Cipher {
    key: [u8; KEY_LEN],
}

impl Cipher {
    /// Derives a session key from a pre-shared key via HKDF-SHA256.
    pub fn new(psk: &[u8]) -> Result<Self, CryptoError> {
        if psk.len() < MIN_PSK_LEN {
            return Err(CryptoError::PskTooShort(psk.len()));
        }
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), psk);
        let mut key = [0u8; KEY_LEN];
        hkdf.expand(HKDF_INFO, &mut key)
            .expect("32 bytes always fit in HKDF-SHA256 output");
        Ok(Self { key })
    }

    /// Encrypts plaintext with a fresh random nonce.
    ///
    /// Returns `nonce || ciphertext || tag`.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XSalsa20Poly1305::new(Key::from_slice(&self.key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("XSalsa20-Poly1305 encryption cannot fail");
        let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        sealed
    }

    /// Decrypts a value produced by [`Cipher::seal`].
    pub fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::DecryptFailed);
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let cipher = XSalsa20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::DecryptFailed)
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Interprets a `--psk` value.
///
/// If the value looks like a hex string, it is decoded directly.
/// Otherwise it is treated as a path to a file containing the key
/// (hex with optional whitespace, or raw bytes).
pub fn parse_psk(value: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let value = value.trim();
    if is_hex(value) {
        if let Ok(bytes) = hex_decode(value) {
            return Ok(Zeroizing::new(bytes));
        }
    }
    let raw = std::fs::read(value).map_err(CryptoError::PskIo)?;
    let text = String::from_utf8_lossy(&raw);
    let compact: String = text.split_whitespace().collect();
    if is_hex(&compact) {
        if let Ok(bytes) = hex_decode(&compact) {
            return Ok(Zeroizing::new(bytes));
        }
    }
    Ok(Zeroizing::new(raw))
}

fn is_hex(value: &str) -> bool {
    !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
