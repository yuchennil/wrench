use sodiumoxide::crypto::sign;

use crate::crypto::agreement::PublicKey;
use crate::error::Error;
use crate::error::Error::*;

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
    #[cfg(test)]
    pub(crate) fn invalid() -> SigningPublicKey {
        SigningPublicKey(sign::PublicKey::from_slice(&[0; sign::PUBLICKEYBYTES]).unwrap())
    }

    pub fn verify(&self, signed_public_key: &SignedPublicKey) -> Result<PublicKey, Error> {
        let serialized_public_key = sign::verify(&signed_public_key.0, &self.0).or(Err(Unknown))?;
        serde_json::from_slice(&serialized_public_key).or(Err(Unknown))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;

    #[test]
    fn sign_and_verify() {
        let (signing_public_key, signing_secret_key) = SigningSecretKey::generate_pair();
        let (public_key, _secret_key) = SecretKey::generate_pair();
        let signed_public_key = signing_secret_key.sign(&public_key);
        let verified_public_key = signing_public_key.verify(&signed_public_key).unwrap();

        assert!(public_key == verified_public_key);
    }

    #[test]
    fn wrong_signer() {
        let (_signing_public_key, signing_secret_key) = SigningSecretKey::generate_pair();
        let (public_key, _secret_key) = SecretKey::generate_pair();
        let signed_public_key = signing_secret_key.sign(&public_key);
        let (eve_signing_public_key, _eve_signing_secret_key) = SigningSecretKey::generate_pair();

        assert!(eve_signing_public_key.verify(&signed_public_key).is_err());
    }

    #[test]
    fn invalid_signer() {
        let (_signing_public_key, signing_secret_key) = SigningSecretKey::generate_pair();
        let (public_key, _secret_key) = SecretKey::generate_pair();
        let signed_public_key = signing_secret_key.sign(&public_key);
        let invalid_signing_public_key = SigningPublicKey::invalid();

        assert!(invalid_signing_public_key
            .verify(&signed_public_key)
            .is_err());
    }
}
