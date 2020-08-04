use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{kx, scalarmult};
use std::hash::{Hash, Hasher};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKey(scalarmult::GroupElement);

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.0).0.hash(state);
    }
}

impl PublicKey {
    #[cfg(test)]
    pub(crate) fn invalid() -> PublicKey {
        PublicKey(
            scalarmult::GroupElement::from_slice(&[0; scalarmult::GROUPELEMENTBYTES]).unwrap(),
        )
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
    /// This view is the best compromise I could find to restrict visibility and mutability.
    /// Alternatives considered include:
    /// - exposing the tuple struct within this module: allows unrestricted mutation
    /// - implementing the AsSlice trait: allows slice visibility outside this module
    pub(in crate::crypto) fn as_slice(&self) -> &[u8] {
        &(self.0).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_keys_agree() {
        let (alice_public_key, alice_secret_key) = SecretKey::generate_pair();
        let (bob_public_key, bob_secret_key) = SecretKey::generate_pair();

        let alice_session_key = alice_secret_key.key_exchange(&bob_public_key).unwrap();
        let bob_session_key = bob_secret_key.key_exchange(&alice_public_key).unwrap();

        assert!(alice_session_key.0 == bob_session_key.0);
    }

    #[test]
    fn mitm_public_keys() {
        let (_alice_public_key, alice_secret_key) = SecretKey::generate_pair();
        let (_bob_public_key, bob_secret_key) = SecretKey::generate_pair();
        let (eve_public_key, _eve_secret_key) = SecretKey::generate_pair();

        let alice_session_key = alice_secret_key.key_exchange(&eve_public_key).unwrap();
        let bob_session_key = bob_secret_key.key_exchange(&eve_public_key).unwrap();

        assert!(alice_session_key.0 != bob_session_key.0);
    }

    #[test]
    fn invalid_public_key() {
        let (_alice_public_key, alice_secret_key) = SecretKey::generate_pair();
        let eve_public_key = PublicKey::invalid();

        assert!(alice_secret_key.key_exchange(&eve_public_key).is_err());
    }
}
