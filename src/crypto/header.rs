use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;

use crate::crypto::{
    agree::PublicKey,
    derive::{RootKey, RootSubkeyId, SessionKey, SessionSubkeyId},
    message::Nonce,
    serde::SerdeKey,
};
use crate::error::Error;

#[derive(Deserialize, Serialize)]
pub struct Header {
    pub public_key: PublicKey,
    pub previous_nonce: Nonce,
    pub nonce: Nonce,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct EncryptedHeader(Vec<u8>);

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct HeaderKey(SerdeKey);

impl HeaderKey {
    pub(in crate::crypto) fn derive_from_session(
        session_key: &SessionKey,
        id: SessionSubkeyId,
    ) -> HeaderKey {
        let mut header_key = secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap();
        session_key.derive_into_slice(&mut header_key.0, id);
        HeaderKey(SerdeKey::new(header_key))
    }

    pub(in crate::crypto) fn derive_from_root(root_key: &RootKey) -> HeaderKey {
        let mut header_key = secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap();
        root_key.derive_into_slice(&mut header_key.0, RootSubkeyId::Header);
        HeaderKey(SerdeKey::new(header_key))
    }

    pub(crate) fn invalid() -> HeaderKey {
        HeaderKey(SerdeKey::invalid())
    }

    #[cfg(test)]
    pub(crate) fn generate() -> HeaderKey {
        HeaderKey(SerdeKey::generate())
    }

    pub fn encrypt(&self, header: Header) -> EncryptedHeader {
        EncryptedHeader(self.0.encrypt(header))
    }

    pub fn decrypt(&self, encrypted_header: &EncryptedHeader) -> Result<Header, Error> {
        self.0.decrypt(&encrypted_header.0)
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
}
