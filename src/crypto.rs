// Wrappers around sodiumoxide cryptographic primitives
//
// These zero-cost abstraction structs enforce correct usage as much as possible
// via type constraints.
mod agreement;
mod associated_data;
mod derivation;
mod header;
mod message;
mod sign;

pub use crate::crypto::{
    agreement::{PublicKey, SecretKey},
    associated_data::AssociatedDataService,
    derivation::{ChainKey, RootKey, SessionKey},
    header::{EncryptedHeader, Header, HeaderKey},
    message::{Message, MessageKey, Nonce, Plaintext},
    sign::{Handshake, Prekey, SigningPublicKey, SigningSecretKey},
};
