//! Shared building blocks for the VPN client and server.
//!
//! Wire format (protocol v1): every frame is
//! `[u32 LE ciphertext length][24-byte nonce][ciphertext + tag]`,
//! where ciphertext is XSalsa20-Poly1305 output and the plaintext
//! starts with a one-byte message kind. See [`frame`] for details.

pub mod crypto;
pub mod frame;
pub mod relay;
pub mod target;

pub use crypto::{parse_psk, Cipher, CryptoError};
pub use frame::{FrameError, Framed, Message};
pub use target::{Host, Target};
