use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{kdf, secretbox};
use std::hash::{Hash, Hasher};

use crate::crypto::{agreement::PublicKey, derivation::RootKey, message::Nonce};

#[derive(Serialize, Deserialize)]
pub struct Header {
    pub public_key: PublicKey,
    pub previous_nonce: Nonce,
    pub nonce: Nonce,
}

pub struct EncryptedHeader {
    pub ciphertext: Vec<u8>,
    nonce: secretbox::Nonce,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HeaderKey(secretbox::Key);

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for HeaderKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.0).0.hash(state);
    }
}

impl HeaderKey {
    pub(in crate::crypto) fn derive_from_digest(digest: &kdf::Key) -> HeaderKey {
        let (id, context) = (RootKey::HEADER_ID, RootKey::CONTEXT);

        let mut header_key = secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut header_key.0, id, context, &digest).unwrap();
        HeaderKey(header_key)
    }

    pub(crate) fn invalid() -> HeaderKey {
        HeaderKey(secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap())
    }

    #[cfg(test)]
    pub(crate) fn generate() -> HeaderKey {
        HeaderKey(secretbox::gen_key())
    }

    pub fn encrypt(&self, header: Header) -> EncryptedHeader {
        let serialized_header = serde_json::to_vec(&header).unwrap();
        let nonce = secretbox::gen_nonce();
        let ciphertext = secretbox::seal(&serialized_header, &nonce, &self.0);

        EncryptedHeader { ciphertext, nonce }
    }

    pub fn decrypt(&self, encrypted_header: &EncryptedHeader) -> Result<Header, ()> {
        let serialized_header = secretbox::open(
            &encrypted_header.ciphertext,
            &encrypted_header.nonce,
            &self.0,
        )?;
        serde_json::from_slice(&serialized_header).or(Err(()))
    }
}
