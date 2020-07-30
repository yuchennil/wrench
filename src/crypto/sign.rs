use sodiumoxide::crypto::sign;

use crate::crypto::agreement::PublicKey;

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
