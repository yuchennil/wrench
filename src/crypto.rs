use serde::{Deserialize, Serialize};
use sodiumoxide::{
    crypto::{aead, kdf, kx, secretbox},
    utils::memcmp,
};

// TODO remove as many pubs as possible in this module

pub struct Plaintext(pub Vec<u8>);
pub struct Ciphertext(pub Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct Header {
    pub public_key: kx::PublicKey,
    pub previous_nonce: Nonce,
    pub nonce: Nonce,
}

impl Header {
    pub fn new(public_key: kx::PublicKey, previous_nonce: Nonce, nonce: Nonce) -> Header {
        Header {
            public_key,
            previous_nonce,
            nonce,
        }
    }
}

pub struct EncryptedHeader {
    pub ciphertext: Vec<u8>,
    pub nonce: secretbox::Nonce,
}

impl EncryptedHeader {
    pub fn encrypt(header: &Header, header_key: &secretbox::Key) -> EncryptedHeader {
        let serialized_header = serde_json::to_string(header).unwrap().into_bytes();
        let nonce = secretbox::gen_nonce();
        let ciphertext = secretbox::seal(&serialized_header, &nonce, &header_key);

        EncryptedHeader { ciphertext, nonce }
    }

    pub fn decrypt(&self, header_key: &secretbox::Key) -> Result<Header, ()> {
        let serialized_header = secretbox::open(&self.ciphertext, &self.nonce, header_key)?;
        match serde_json::from_slice(&serialized_header) {
            Ok(header) => Ok(header),
            Err(_) => Err(()),
        }
    }
}

pub struct Message {
    pub encrypted_header: EncryptedHeader,
    pub ciphertext: Ciphertext,
}

impl Message {
    pub fn new(encrypted_header: EncryptedHeader, ciphertext: Ciphertext) -> Message {
        Message {
            encrypted_header,
            ciphertext,
        }
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, PartialOrd, Serialize)]
pub struct Nonce(aead::Nonce);

impl Nonce {
    pub fn new_zero() -> Nonce {
        Nonce(aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap())
    }

    pub fn equals_zero(&self) -> bool {
        memcmp(&(self.0).0, &[0; aead::NONCEBYTES])
    }

    pub fn increment(&mut self) {
        self.0.increment_le_inplace()
    }
}

pub struct MessageKey(aead::Key);

impl MessageKey {
    pub fn derive_from(chain_key: &kdf::Key) -> MessageKey {
        const CONTEXT: [u8; 8] = *b"chainkdf";

        let mut message_key = aead::Key::from_slice(&[0; aead::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut message_key.0, 2, CONTEXT, chain_key).unwrap();
        MessageKey(message_key)
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
        Message::new(encrypted_header, ciphertext)
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
