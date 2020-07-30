// Wrappers around sodiumoxide cryptographic primitives
//
// These zero-cost abstraction structs enforce correct usage as much as possible
// via type constraints.
mod agreement;
mod derivation;
mod header;
mod message;
mod sign;

pub use crate::crypto::{
    agreement::{PublicKey, SecretKey, SessionKey},
    derivation::{ChainKey, RootKey},
    header::{EncryptedHeader, Header, HeaderKey},
    message::{Message, MessageKey, Nonce, Plaintext},
    sign::{Handshake, Prekey, SignedPublicKey, SigningPublicKey, SigningSecretKey},
};
