use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{generichash, kdf, kx, scalarmult, sign};
use std::hash::{Hash, Hasher};

use crate::crypto::{derivation::RootKey, header::HeaderKey};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKey(scalarmult::GroupElement);

#[allow(clippy::derive_hash_xor_eq)]
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

    #[cfg(test)]
    pub(crate) fn invalid_pair() -> (PublicKey, SecretKey) {
        let public_key = [0; scalarmult::GROUPELEMENTBYTES];
        let secret_key = [0; scalarmult::SCALARBYTES];
        (
            PublicKey(scalarmult::GroupElement::from_slice(&public_key).unwrap()),
            SecretKey(scalarmult::Scalar::from_slice(&secret_key).unwrap()),
        )
    }

    pub fn key_exchange(&self, public_key: &PublicKey) -> Result<SessionKey, ()> {
        Ok(SessionKey(scalarmult::scalarmult(&self.0, &public_key.0)?))
    }
}

pub struct SessionKey(pub scalarmult::GroupElement);

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

#[derive(Clone)]
pub struct Prekey {
    pub signer: SigningPublicKey,
    pub identity: SignedPublicKey,
    pub ephemeral: SignedPublicKey,
}

pub struct Handshake {
    pub initiator_prekey: Prekey,
    pub responder_prekey: Prekey,
}

#[derive(Clone)]
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

    #[cfg(test)]
    pub(crate) fn invalid_pair() -> (SigningPublicKey, SigningSecretKey) {
        let signing_public_key = sign::PublicKey::from_slice(&[0; sign::PUBLICKEYBYTES]).unwrap();
        let signing_secret_key = sign::SecretKey::from_slice(&[0; sign::SECRETKEYBYTES]).unwrap();
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
