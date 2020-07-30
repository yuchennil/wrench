use serde::{Deserialize, Serialize};
use sodiumoxide::{
    crypto::{aead, kdf},
    utils::add_le,
};
use std::{hash::Hash, ops::Add};

use crate::crypto::{derivation::ChainKey, header::EncryptedHeader};

pub struct Plaintext(pub Vec<u8>);
struct Ciphertext(Vec<u8>);

pub struct Message {
    pub encrypted_header: EncryptedHeader,
    ciphertext: Ciphertext,
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

pub struct MessageKey(aead::Key);

impl MessageKey {
    pub(in crate::crypto) fn derive_from_chain(chain_key: &ChainKey) -> MessageKey {
        let (id, context) = (ChainKey::MESSAGE_ID, ChainKey::CONTEXT);

        let mut message_key = aead::Key::from_slice(&[0; aead::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut message_key.0, id, context, &chain_key.0).unwrap();
        MessageKey(message_key)
    }

    #[cfg(test)]
    pub(crate) fn generate() -> MessageKey {
        MessageKey(aead::gen_key())
    }

    pub fn encrypt(
        self,
        plaintext: Plaintext,
        encrypted_header: EncryptedHeader,
        nonce: Nonce,
    ) -> Message {
        let ciphertext = Ciphertext(aead::seal(
            &plaintext.0,
            Some(&encrypted_header.ciphertext),
            &nonce.0,
            &self.0,
        ));
        Message {
            encrypted_header,
            ciphertext,
        }
    }

    pub fn decrypt(self, message: Message, nonce: Nonce) -> Result<Plaintext, ()> {
        Ok(Plaintext(aead::open(
            &message.ciphertext.0,
            Some(&message.encrypted_header.ciphertext),
            &nonce.0,
            &self.0,
        )?))
    }
}
