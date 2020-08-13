// Wrappers around sodiumoxide cryptographic primitives
//
// These zero-cost abstraction structs enforce correct usage as much as possible
// via type constraints.
mod agreement;
mod derivation;
mod header;
mod id;
mod message;
mod sign;

pub use crate::crypto::{
    agreement::{PublicKey, SecretKey},
    derivation::{ChainKey, RootKey, SessionKey},
    header::{EncryptedHeader, Header, HeaderKey},
    id::SessionId,
    message::{AssociatedData, Message, MessageKey, Nonce, Plaintext},
    sign::{Handshake, Prekey, SigningPublicKey, SigningSecretKey},
};
