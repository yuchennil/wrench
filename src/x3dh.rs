use sodiumoxide::init;
use std::collections;

use crate::crypto::{
    Handshake, HeaderKey, Prekey, PublicKey, RootKey, SecretKey, SessionKey, SigningPublicKey,
    SigningSecretKey,
};
use crate::session::Session;

pub struct User {
    signing_public_key: SigningPublicKey,
    signing_secret_key: SigningSecretKey,
    identity_public_key: PublicKey,
    identity_secret_key: SecretKey,
    ephemeral_keypairs: collections::HashMap<PublicKey, SecretKey>,
}

impl User {
    pub fn new() -> Result<User, ()> {
        init()?;
        let (signing_public_key, signing_secret_key) = SigningSecretKey::generate_pair();
        let (identity_public_key, identity_secret_key) = SecretKey::generate_pair();
        Ok(User {
            signing_public_key,
            signing_secret_key,
            identity_public_key,
            identity_secret_key,
            ephemeral_keypairs: collections::HashMap::new(),
        })
    }

    pub fn publish_prekey(&mut self) -> Prekey {
        let (ephemeral_public_key, ephemeral_secret_key, prekey) = self.generate_prekey();
        self.ephemeral_keypairs
            .insert(ephemeral_public_key, ephemeral_secret_key);
        prekey
    }

    pub fn initiate(&self, responder_prekey: Prekey) -> Result<(Session, Handshake), ()> {
        let (_, ephemeral_secret_key, initiator_prekey) = self.generate_prekey();

        let responder_ephemeral_key = responder_prekey
            .signer
            .verify(&responder_prekey.ephemeral)?;

        let (root_key, initiator_header_key, responder_header_key) = self.x3dh(
            UserState::Initiator,
            &ephemeral_secret_key,
            &responder_prekey,
        )?;

        let handshake = Handshake {
            responder_prekey,
            initiator_prekey,
        };

        Ok((
            Session::new_initiator(
                responder_ephemeral_key,
                root_key,
                initiator_header_key,
                responder_header_key,
            )?,
            handshake,
        ))
    }

    pub fn respond(&mut self, handshake: Handshake) -> Result<Session, ()> {
        let ephemeral_public_key = self
            .signing_public_key
            .verify(&handshake.responder_prekey.ephemeral)?;
        let ephemeral_secret_key = self
            .ephemeral_keypairs
            .remove(&ephemeral_public_key)
            .ok_or(())?;
        let (root_key, initiator_header_key, responder_header_key) = self.x3dh(
            UserState::Responder,
            &ephemeral_secret_key,
            &handshake.initiator_prekey,
        )?;

        Session::new_responder(
            ephemeral_public_key,
            ephemeral_secret_key,
            root_key,
            responder_header_key,
            initiator_header_key,
        )
    }

    fn generate_prekey(&self) -> (PublicKey, SecretKey, Prekey) {
        let (ephemeral_public_key, ephemeral_secret_key) = SecretKey::generate_pair();
        let prekey = Prekey {
            signer: self.signing_public_key.clone(),
            identity: self.signing_secret_key.sign(&self.identity_public_key),
            ephemeral: self.signing_secret_key.sign(&ephemeral_public_key),
        };

        (ephemeral_public_key, ephemeral_secret_key, prekey)
    }

    fn x3dh(
        &self,
        user_state: UserState,
        ephemeral_secret_key: &SecretKey,
        prekey: &Prekey,
    ) -> Result<(RootKey, HeaderKey, HeaderKey), ()> {
        let identity_public_key = prekey.signer.verify(&prekey.identity)?;
        let ephemeral_public_key = prekey.signer.verify(&prekey.ephemeral)?;

        let identity_ephemeral = self
            .identity_secret_key
            .key_exchange(&ephemeral_public_key)?;
        let ephemeral_identity = ephemeral_secret_key.key_exchange(&identity_public_key)?;
        let ephemeral_ephemeral = ephemeral_secret_key.key_exchange(&ephemeral_public_key)?;

        // Swap based on user_state to present the same argument order to the kdf.
        let (initiator_responder, responder_initiator) = match user_state {
            UserState::Initiator => (identity_ephemeral, ephemeral_identity),
            UserState::Responder => (ephemeral_identity, identity_ephemeral),
        };

        Ok(SessionKey::derive_keys(
            initiator_responder,
            responder_initiator,
            ephemeral_ephemeral,
        ))
    }
}

enum UserState {
    Initiator,
    Responder,
}
