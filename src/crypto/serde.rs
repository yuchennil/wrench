use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sodiumoxide::{crypto::secretbox, utils::memzero};
use std::hash::{Hash, Hasher};

use crate::error::Error::{self, *};

#[derive(Deserialize, Serialize)]
struct SerdeCiphertext(Vec<u8>, secretbox::Nonce);

#[derive(Clone, Eq, PartialEq)]
pub struct SerdeKey(secretbox::Key);

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for SerdeKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.0).0.hash(state);
    }
}

impl SerdeKey {
    pub(in crate::crypto) fn new(key: secretbox::Key) -> SerdeKey {
        SerdeKey(key)
    }

    pub(crate) fn invalid() -> SerdeKey {
        SerdeKey(secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap())
    }

    #[cfg(test)]
    pub(crate) fn generate() -> SerdeKey {
        SerdeKey(secretbox::gen_key())
    }

    pub fn encrypt<T: Serialize>(&self, object: T) -> Vec<u8> {
        let mut serialized_object = serde_json::to_vec(&object).unwrap();
        let nonce = secretbox::gen_nonce();
        let ciphertext = secretbox::seal(&serialized_object, &nonce, &self.0);
        memzero(&mut serialized_object);
        serde_json::to_vec(&SerdeCiphertext(ciphertext, nonce)).unwrap()
    }

    pub fn decrypt<T: DeserializeOwned>(&self, slice: &[u8]) -> Result<T, Error> {
        let serde_ciphertext: SerdeCiphertext =
            serde_json::from_slice(slice).or(Err(Deserialization))?;
        let mut serialized_object =
            secretbox::open(&serde_ciphertext.0, &serde_ciphertext.1, &self.0)
                .or(Err(InvalidKey))?;
        let object = serde_json::from_slice(&serialized_object).or(Err(Deserialization))?;
        memzero(&mut serialized_object);
        Ok(object)
    }
}
