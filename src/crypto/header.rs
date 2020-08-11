use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;
use std::hash::{Hash, Hasher};

use crate::crypto::{
    agreement::PublicKey,
    derivation::{RootKey, RootSubkeyId, SessionKey, SessionSubkeyId},
    message::Nonce,
};
use crate::error::Error::{self, *};

#[derive(Serialize, Deserialize)]
pub struct Header {
    pub public_key: PublicKey,
    pub previous_nonce: Nonce,
    pub nonce: Nonce,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedHeader {
    ciphertext: Vec<u8>,
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
    pub(in crate::crypto) fn derive_from_session(
        session_key: &SessionKey,
        id: SessionSubkeyId,
    ) -> HeaderKey {
        let mut header_key = secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap();
        session_key.derive_into_slice(&mut header_key.0, id);
        HeaderKey(header_key)
    }

    pub(in crate::crypto) fn derive_from_root(root_key: &RootKey) -> HeaderKey {
        let mut header_key = secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap();
        root_key.derive_into_slice(&mut header_key.0, RootSubkeyId::Header);
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

    pub fn decrypt(&self, encrypted_header: &EncryptedHeader) -> Result<Header, Error> {
        let serialized_header = secretbox::open(
            &encrypted_header.ciphertext,
            &encrypted_header.nonce,
            &self.0,
        )
        .or(Err(InvalidKey))?;
        serde_json::from_slice(&serialized_header).or(Err(Deserialization))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;

    #[test]
    fn encrypt_header() {
        let public_key = SecretKey::generate_pair().0;
        let previous_nonce = Nonce::new(137);
        let nonce = Nonce::new(255);
        let header = Header {
            public_key: public_key.clone(),
            previous_nonce,
            nonce,
        };
        let header_key = HeaderKey::generate();
        let encrypted_header = header_key.encrypt(header);
        let decrypted_header = header_key.decrypt(&encrypted_header).unwrap();

        assert!(public_key == decrypted_header.public_key);
        assert!(previous_nonce == decrypted_header.previous_nonce);
        assert!(nonce == decrypted_header.nonce);
    }

    #[test]
    fn encrypt_header_wrong_header_key() {
        let header = Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(137),
            nonce: Nonce::new(255),
        };
        let header_key = HeaderKey::generate();
        let eve_header_key = HeaderKey::generate();
        let encrypted_header = header_key.encrypt(header);

        assert!(eve_header_key.decrypt(&encrypted_header).is_err());
    }

    #[test]
    fn encrypt_header_wrong_header_nonce() {
        let header = Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(137),
            nonce: Nonce::new(255),
        };
        let header_key = HeaderKey::generate();
        let mut encrypted_header = header_key.encrypt(header);
        encrypted_header.nonce = secretbox::gen_nonce();

        assert!(header_key.decrypt(&encrypted_header).is_err());
    }
}
