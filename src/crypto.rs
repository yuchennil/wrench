// Wrappers around sodiumoxide cryptographic primitives
//
// These zero-cost abstraction structs enforce correct usage as much as possible
// via type constraints.
mod agreement;
mod derivation;
mod header;
mod message;

pub use crate::crypto::{
    agreement::{
        Handshake, Prekey, PublicKey, SecretKey, SessionKey, SignedPublicKey, SigningPublicKey,
        SigningSecretKey,
    },
    derivation::{ChainKey, RootKey},
    header::{EncryptedHeader, Header, HeaderKey},
    message::{Message, MessageKey, Nonce, Plaintext},
};
