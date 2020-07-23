use serde::{Deserialize, Serialize};
use sodiumoxide::{
    crypto::{aead, generichash, kdf, kx, scalarmult, secretbox},
    utils::memcmp,
};
use std::hash::{Hash, Hasher};

// TODO remove as many pubs as possible in this module

pub struct Plaintext(pub Vec<u8>);
struct Ciphertext(pub Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct Header {
    pub public_key: PublicKey,
    pub previous_nonce: Nonce,
    pub nonce: Nonce,
}

pub struct EncryptedHeader {
    ciphertext: Vec<u8>,
    nonce: secretbox::Nonce,
}

#[derive(Clone, Eq)]
pub struct HeaderKey(secretbox::Key);

impl PartialEq for HeaderKey {
    fn eq(&self, other: &Self) -> bool {
        memcmp(&(self.0).0, &(other.0).0)
    }
}

impl HeaderKey {
    pub fn derive_from(digest: &kdf::Key) -> HeaderKey {
        const CONTEXT: [u8; 8] = *b"rootkdf_";

        let mut header_key = secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut header_key.0, 3, CONTEXT, &digest).unwrap();
        HeaderKey(header_key)
    }

    // For crate testing only. Not a public interface since all header keys should be derived.
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
        match serde_json::from_slice(&serialized_header) {
            Ok(header) => Ok(header),
            Err(_) => Err(()),
        }
    }
}

pub struct Message {
    pub encrypted_header: EncryptedHeader,
    ciphertext: Ciphertext,
}

impl Message {
    fn new(encrypted_header: EncryptedHeader, ciphertext: Ciphertext) -> Message {
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
    pub fn derive_from(chain_key: &ChainKey) -> MessageKey {
        const CONTEXT: [u8; 8] = *b"chainkdf";

        let mut message_key = aead::Key::from_slice(&[0; aead::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut message_key.0, 2, CONTEXT, &chain_key.0).unwrap();
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

pub struct ChainKey(kdf::Key);

impl ChainKey {
    pub fn derive_from_chain(prev_chain_key: &ChainKey) -> ChainKey {
        const CONTEXT: [u8; 8] = *b"chainkdf";

        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut chain_key.0, 1, CONTEXT, &prev_chain_key.0).unwrap();
        ChainKey(chain_key)
    }

    pub fn derive_from_digest(digest: &kdf::Key) -> ChainKey {
        const CONTEXT: [u8; 8] = *b"rootkdf_";

        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut chain_key.0, 2, CONTEXT, &digest).unwrap();
        ChainKey(chain_key)
    }

    // For crate testing only. Not a public interface since all chain keys should be derived.
    pub(crate) fn generate() -> ChainKey {
        ChainKey(kdf::gen_key())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RootKey(kdf::Key);

impl RootKey {
    pub fn derive_from(digest: &kdf::Key) -> RootKey {
        const CONTEXT: [u8; 8] = *b"rootkdf_";

        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut chain_key.0, 1, CONTEXT, &digest).unwrap();
        RootKey(chain_key)
    }

    // For crate testing only. Not a public interface since all root keys should be derived.
    pub(crate) fn generate() -> RootKey {
        RootKey(kdf::gen_key())
    }

    pub fn key_derivation(
        &self,
        session_key: SessionKey,
    ) -> Result<(RootKey, ChainKey, HeaderKey), ()> {
        let mut state = generichash::State::new(kdf::KEYBYTES, Some(&(self.0).0))?;
        state.update(&(session_key.0).0)?;
        let digest = kdf::Key::from_slice(&state.finalize()?[..]).unwrap();

        let root_key = RootKey::derive_from(&digest);
        let chain_key = ChainKey::derive_from_digest(&digest);
        let header_key = HeaderKey::derive_from(&digest);

        Ok((root_key, chain_key, header_key))
    }
}

#[derive(Clone, Deserialize, Eq, Serialize)]
pub struct PublicKey(scalarmult::GroupElement);

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        memcmp(&(self.0).0, &(other.0).0)
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.0).0.hash(state);
    }
}

pub struct SecretKey(scalarmult::Scalar);

impl SecretKey {
    pub fn generate_pair() -> (PublicKey, SecretKey) {
        let (public_key, secret_key) = kx::gen_keypair();
        (
            PublicKey(scalarmult::GroupElement::from_slice(&public_key.0).unwrap()),
            SecretKey(scalarmult::Scalar::from_slice(&secret_key.0).unwrap()),
        )
    }

    pub fn key_exchange(&self, public_key: &PublicKey) -> Result<SessionKey, ()> {
        Ok(SessionKey(scalarmult::scalarmult(&self.0, &public_key.0)?))
    }
}

pub struct SessionKey(scalarmult::GroupElement);

impl SessionKey {
    pub fn derive_key(key_0: SessionKey, key_1: SessionKey, key_2: SessionKey) -> RootKey {
        let mut state = generichash::State::new(kdf::KEYBYTES, None).unwrap();
        state.update(&(key_0.0).0).unwrap();
        state.update(&(key_1.0).0).unwrap();
        state.update(&(key_2.0).0).unwrap();

        RootKey(kdf::Key::from_slice(&state.finalize().unwrap().as_ref()).unwrap())
    }
}
