// Wrappers around sodiumoxide cryptographic primitives
//
// These zero-cost abstraction structs enforce correct usage as much as possible
// via type constraints.
mod agree;
mod derive;
mod envelope;
mod header;
mod id;
mod message;
mod serde;
mod sign;

pub use crate::crypto::{
    agree::{PublicKey, SecretKey},
    derive::{ChainKey, RootKey, SessionKey},
    envelope::Envelope,
    header::{EncryptedHeader, Header, HeaderKey},
    id::{Handshake, Prekey, SessionId, UserId},
    message::{AssociatedData, Message, MessageKey, Nonce, Plaintext},
    serde::SerdeKey,
    sign::{SigningPublicKey, SigningSecretKey},
};
