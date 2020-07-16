use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{aead, kx, secretbox};

// TODO remove as many pubs as possible in this module

pub struct Plaintext(pub Vec<u8>);
pub struct Ciphertext(pub Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct Header {
    pub public_key: kx::PublicKey,
    pub previous_nonce: aead::Nonce,
    pub nonce: aead::Nonce,
}

impl Header {
    pub fn new(
        public_key: kx::PublicKey,
        previous_nonce: aead::Nonce,
        nonce: aead::Nonce,
    ) -> Header {
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
