// Wrappers around sodiumoxide cryptographic primitives
//
// These zero-cost abstraction structs enforce correct usage as much as possible
// via type constraints.

use serde::{Deserialize, Serialize};
use sodiumoxide::{
    crypto::{aead, generichash, kdf, kx, scalarmult, secretbox, sign},
    utils::add_le,
};
use std::{
    hash::{Hash, Hasher},
    ops::Add,
};

pub struct Plaintext(pub Vec<u8>);
struct Ciphertext(Vec<u8>);

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

#[derive(Clone, Eq, PartialEq)]
pub struct HeaderKey(secretbox::Key);

impl Hash for HeaderKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.0).0.hash(state);
    }
}

impl HeaderKey {
    fn derive_from_digest(digest: &kdf::Key) -> HeaderKey {
        let (id, context) = (RootKey::HEADER_ID, RootKey::CONTEXT);

        let mut header_key = secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut header_key.0, id, context, &digest).unwrap();
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
        serde_json::from_slice(&serialized_header).or(Err(()))
    }
}

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
    fn derive_from_chain(chain_key: &ChainKey) -> MessageKey {
        let (id, context) = (ChainKey::MESSAGE_ID, ChainKey::CONTEXT);

        let mut message_key = aead::Key::from_slice(&[0; aead::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut message_key.0, id, context, &chain_key.0).unwrap();
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

pub struct ChainKey(kdf::Key);

impl ChainKey {
    const CONTEXT: [u8; 8] = *b"chainkdf";
    const CHAIN_ID: u64 = 1;
    const MESSAGE_ID: u64 = 2;

    fn derive_from_chain(prev_chain_key: &ChainKey) -> ChainKey {
        let (id, context) = (ChainKey::CHAIN_ID, ChainKey::CONTEXT);

        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut chain_key.0, id, context, &prev_chain_key.0).unwrap();
        ChainKey(chain_key)
    }

    fn derive_from_digest(digest: &kdf::Key) -> ChainKey {
        let (id, context) = (RootKey::CHAIN_ID, RootKey::CONTEXT);

        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut chain_key.0, id, context, &digest).unwrap();
        ChainKey(chain_key)
    }

    // For crate testing only. Not a public interface since all chain keys should be derived.
    pub(crate) fn generate() -> ChainKey {
        ChainKey(kdf::gen_key())
    }

    pub fn derive_keys(&self) -> (ChainKey, MessageKey) {
        let chain_key = ChainKey::derive_from_chain(self);
        let message_key = MessageKey::derive_from_chain(self);

        (chain_key, message_key)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RootKey(kdf::Key);

impl RootKey {
    const CONTEXT: [u8; 8] = *b"rootkdf_";
    const ROOT_ID: u64 = 1;
    const CHAIN_ID: u64 = 2;
    const HEADER_ID: u64 = 3;

    fn derive_from_digest(digest: &kdf::Key) -> RootKey {
        let (id, context) = (RootKey::ROOT_ID, RootKey::CONTEXT);

        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut chain_key.0, id, context, &digest).unwrap();
        RootKey(chain_key)
    }

    pub fn derive_keys(
        &self,
        session_key: SessionKey,
    ) -> Result<(RootKey, ChainKey, HeaderKey), ()> {
        let mut state = generichash::State::new(kdf::KEYBYTES, Some(&(self.0).0))?;
        state.update(&(session_key.0).0)?;
        let digest = kdf::Key::from_slice(&state.finalize()?[..]).unwrap();

        let root_key = RootKey::derive_from_digest(&digest);
        let chain_key = ChainKey::derive_from_digest(&digest);
        let header_key = HeaderKey::derive_from_digest(&digest);

        Ok((root_key, chain_key, header_key))
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKey(scalarmult::GroupElement);

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
    pub fn derive_keys(
        key_0: SessionKey,
        key_1: SessionKey,
        key_2: SessionKey,
    ) -> (RootKey, HeaderKey, HeaderKey) {
        let mut state = generichash::State::new(kdf::KEYBYTES, None).unwrap();
        state.update(&(key_0.0).0).unwrap();
        state.update(&(key_1.0).0).unwrap();
        state.update(&(key_2.0).0).unwrap();
        let digest = kdf::Key::from_slice(&state.finalize().unwrap()[..]).unwrap();

        let root_key = RootKey::derive_from_digest(&digest);
        let initiator_header_key = HeaderKey::derive_from_digest(&digest);
        let responder_header_key = HeaderKey::derive_from_digest(&digest);

        (root_key, initiator_header_key, responder_header_key)
    }
}

pub struct Prekey {
    pub signer: SigningPublicKey,
    pub identity: SignedPublicKey,
    pub ephemeral: SignedPublicKey,
}

pub struct Handshake {
    pub initiator_prekey: Prekey,
    pub responder_prekey: Prekey,
}

pub struct SignedPublicKey(Vec<u8>);

#[derive(Clone)]
pub struct SigningPublicKey(sign::PublicKey);

impl SigningPublicKey {
    pub fn verify(&self, signed_public_key: &SignedPublicKey) -> Result<PublicKey, ()> {
        let serialized_public_key = sign::verify(&signed_public_key.0, &self.0)?;
        serde_json::from_slice(&serialized_public_key).or(Err(()))
    }
}

pub struct SigningSecretKey(sign::SecretKey);

impl SigningSecretKey {
    pub fn generate_pair() -> (SigningPublicKey, SigningSecretKey) {
        let (signing_public_key, signing_secret_key) = sign::gen_keypair();
        (
            SigningPublicKey(signing_public_key),
            SigningSecretKey(signing_secret_key),
        )
    }

    pub fn sign(&self, public_key: &PublicKey) -> SignedPublicKey {
        let serialized_public_key = serde_json::to_vec(public_key).unwrap();
        SignedPublicKey(sign::sign(&serialized_public_key, &self.0))
    }
}
