use serde::{Deserialize, Serialize};
use sodiumoxide::{
    crypto::aead,
    utils::{add_le, memzero},
};
use std::{hash::Hash, ops::Add};

#[cfg(test)]
use crate::crypto::{
    agree::SecretKey,
    header::{Header, HeaderKey},
};
use crate::crypto::{
    derive::{ChainKey, ChainSubkeyId},
    header::EncryptedHeader,
    id::{Handshake, SessionId},
};
use crate::error::Error::{self, *};

pub struct Plaintext(pub Vec<u8>);

impl Drop for Plaintext {
    fn drop(&mut self) {
        memzero(&mut self.0);
    }
}

#[derive(Deserialize, Serialize)]
pub struct Message {
    pub encrypted_header: EncryptedHeader,
    pub ciphertext: Ciphertext,
    pub handshake: Option<Handshake>,
}

impl Message {
    #[cfg(test)]
    pub(crate) fn generate() -> Message {
        MessageKey::generate_twins().0.encrypt(
            Plaintext("plaintext".as_bytes().to_vec()),
            AssociatedData::new(
                SessionId::generate(),
                HeaderKey::generate().encrypt(Header {
                    public_key: SecretKey::generate_pair().0,
                    previous_nonce: Nonce::new(0),
                    nonce: Nonce::new(0),
                }),
                Nonce::new(0),
            ),
        )
    }
}

#[derive(Deserialize, Serialize)]
pub struct Ciphertext(Vec<u8>);

#[derive(Clone, Serialize)]
pub struct AssociatedData {
    session_id: SessionId,
    encrypted_header: EncryptedHeader,
    nonce: Nonce,
}

impl AssociatedData {
    pub fn new(
        session_id: SessionId,
        encrypted_header: EncryptedHeader,
        nonce: Nonce,
    ) -> AssociatedData {
        AssociatedData {
            session_id,
            encrypted_header,
            nonce,
        }
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, PartialOrd, Serialize)]
pub struct Nonce(aead::Nonce);

impl Add for &Nonce {
    type Output = Nonce;

    fn add(self, other: &Nonce) -> Nonce {
        let mut result = (self.0).0;
        add_le(&mut result, &(other.0).0).unwrap();
        Nonce(aead::Nonce::from_slice(&result).unwrap())
    }
}

impl Nonce {
    pub fn new(n: u8) -> Nonce {
        let mut slice = [0; aead::NONCEBYTES];
        slice[0] = n;
        Nonce(aead::Nonce::from_slice(&slice).unwrap())
    }

    pub fn increment(&mut self) {
        self.0.increment_le_inplace()
    }
}

#[derive(PartialEq)]
pub struct MessageKey(aead::Key);

impl MessageKey {
    pub(in crate::crypto) fn derive_from_chain(chain_key: &ChainKey) -> MessageKey {
        let mut message_key = aead::Key::from_slice(&[0; aead::KEYBYTES]).unwrap();
        chain_key.derive_into_slice(&mut message_key.0, ChainSubkeyId::Message);
        MessageKey(message_key)
    }

    #[cfg(test)]
    pub(crate) fn generate_twins() -> (MessageKey, MessageKey) {
        let message_key = aead::gen_key();
        (MessageKey(message_key.clone()), MessageKey(message_key))
    }

    pub fn encrypt(self, plaintext: Plaintext, associated_data: AssociatedData) -> Message {
        let ciphertext = Ciphertext(aead::seal(
            &plaintext.0,
            Some(&serde_json::to_vec(&associated_data).unwrap()),
            &associated_data.nonce.0,
            &self.0,
        ));
        Message {
            encrypted_header: associated_data.encrypted_header,
            ciphertext,
            handshake: None,
        }
    }

    pub fn decrypt(
        self,
        ciphertext: Ciphertext,
        associated_data: AssociatedData,
    ) -> Result<Plaintext, Error> {
        Ok(Plaintext(
            aead::open(
                &ciphertext.0,
                Some(&serde_json::to_vec(&associated_data).unwrap()),
                &associated_data.nonce.0,
                &self.0,
            )
            .or(Err(InvalidKey))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Header, HeaderKey, SecretKey};

    #[test]
    fn nonce_equality() {
        let mut nonce = Nonce::new(0);
        nonce.increment();
        assert!(nonce == Nonce::new(1));

        let mut nonce = Nonce::new(255);
        nonce.increment();
        assert!(nonce == &Nonce::new(128) + &Nonce::new(128));
    }

    #[test]
    fn nonce_ordering() {
        assert!(Nonce::new(36) < Nonce::new(37));

        // TODO file a PR to fix sodiumoxide's Nonce PartialOrd. The Nonce implementation
        // is little-endian but calls a lexicographic cmp over its byte vector.
        // assert!(Nonce::new(255) < &Nonce::new(128) + &Nonce::new(128));
    }

    #[test]
    fn encrypt_message() {
        let nonce = Nonce::new(137);
        let header = Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(0),
            nonce,
        };
        let encrypted_header = HeaderKey::generate().encrypt(header);
        let associated_data = AssociatedData::new(SessionId::generate(), encrypted_header, nonce);
        let plaintext = Plaintext("plaintext".as_bytes().to_vec());
        let (message_key, message_key_duplicate) = MessageKey::generate_twins();

        let message = message_key.encrypt(plaintext, associated_data.clone());
        let decrypted_plaintext = message_key_duplicate
            .decrypt(message.ciphertext, associated_data)
            .unwrap();

        assert_eq!(decrypted_plaintext.0, "plaintext".as_bytes().to_vec());
    }

    #[test]
    fn encrypt_message_wrong_key() {
        let nonce = Nonce::new(137);
        let header = Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(0),
            nonce,
        };
        let encrypted_header = HeaderKey::generate().encrypt(header);
        let associated_data = AssociatedData::new(SessionId::generate(), encrypted_header, nonce);
        let plaintext = Plaintext("plaintext".as_bytes().to_vec());
        let (message_key, _) = MessageKey::generate_twins();
        let (eve_message_key, _) = MessageKey::generate_twins();

        let message = message_key.encrypt(plaintext, associated_data.clone());

        assert!(eve_message_key
            .decrypt(message.ciphertext, associated_data)
            .is_err());
    }

    #[test]
    fn encrypt_message_wrong_nonce() {
        let nonce = Nonce::new(137);
        let eve_nonce = Nonce::new(255);
        let header = Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(0),
            nonce,
        };
        let encrypted_header = HeaderKey::generate().encrypt(header);
        let session_id = SessionId::generate();
        let associated_data =
            AssociatedData::new(session_id.clone(), encrypted_header.clone(), nonce);
        let eve_associated_data = AssociatedData::new(session_id, encrypted_header, eve_nonce);
        let plaintext = Plaintext("plaintext".as_bytes().to_vec());
        let (message_key, message_key_duplicate) = MessageKey::generate_twins();

        let message = message_key.encrypt(plaintext, associated_data);

        assert!(message_key_duplicate
            .decrypt(message.ciphertext, eve_associated_data)
            .is_err());
    }

    #[test]
    fn encrypt_message_wrong_encrypted_header() {
        let nonce = Nonce::new(137);
        let header = Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(0),
            nonce,
        };
        let eve_header = Header {
            public_key: SecretKey::generate_pair().0.clone(),
            previous_nonce: Nonce::new(0),
            nonce,
        };
        let encrypted_header = HeaderKey::generate().encrypt(header);
        let eve_encrypted_header = HeaderKey::generate().encrypt(eve_header);
        let session_id = SessionId::generate();
        let associated_data = AssociatedData::new(session_id.clone(), encrypted_header, nonce);
        let eve_associated_data = AssociatedData::new(session_id, eve_encrypted_header, nonce);
        let plaintext = Plaintext("plaintext".as_bytes().to_vec());
        let (message_key, message_key_duplicate) = MessageKey::generate_twins();

        let message = message_key.encrypt(plaintext, associated_data);

        assert!(message_key_duplicate
            .decrypt(message.ciphertext, eve_associated_data)
            .is_err());
    }

    #[test]
    fn encrypt_message_wrong_associated_data() {
        let nonce = Nonce::new(137);
        let header = Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(0),
            nonce,
        };
        let encrypted_header = HeaderKey::generate().encrypt(header);
        let associated_data =
            AssociatedData::new(SessionId::generate(), encrypted_header.clone(), nonce);
        let eve_associated_data =
            AssociatedData::new(SessionId::generate(), encrypted_header, nonce);
        let plaintext = Plaintext("plaintext".as_bytes().to_vec());
        let (message_key, message_key_duplicate) = MessageKey::generate_twins();

        let message = message_key.encrypt(plaintext, associated_data);

        assert!(message_key_duplicate
            .decrypt(message.ciphertext, eve_associated_data)
            .is_err());
    }
}
