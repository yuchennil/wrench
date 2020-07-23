use sodiumoxide::init;
use std::collections;

use crate::crypto::{
    PublicKey, RootKey, SecretKey, SessionKey, SignedPublicKey, SigningPublicKey, SigningSecretKey,
};

pub struct Handshake {
    signing_public_key: SigningPublicKey,
    signing_secret_key: SigningSecretKey,
    public_key: PublicKey,
    secret_key: SecretKey,
    ephemeral_keypairs: collections::HashMap<PublicKey, SecretKey>,
}

impl Handshake {
    pub fn new() -> Result<Handshake, ()> {
        init()?;
        let (signing_public_key, signing_secret_key) = SigningSecretKey::generate_pair();
        let (public_key, secret_key) = SecretKey::generate_pair();
        Ok(Handshake {
            signing_public_key,
            signing_secret_key,
            public_key,
            secret_key,
            ephemeral_keypairs: collections::HashMap::new(),
        })
    }

    pub fn generate_prekey(&mut self) -> Prekey {
        let (ephemeral_public_key, ephemeral_secret_key) = SecretKey::generate_pair();
        self.ephemeral_keypairs
            .insert(ephemeral_public_key.clone(), ephemeral_secret_key);

        Prekey {
            identity: self.signing_secret_key.sign(&self.public_key),
            ephemeral: self.signing_secret_key.sign(&ephemeral_public_key),
        }
    }

    pub fn initiate(
        &mut self,
        responder_prekey: Prekey,
    ) -> Result<(RootKey, PublicKey, InitialMessage), ()> {
        let (ephemeral_public_key, ephemeral_secret_key) = SecretKey::generate_pair();
        let signed_responder_ephemeral_key = responder_prekey.ephemeral.clone();
        let responder_ephemeral_key = responder_prekey
            .identity
            .signer
            .verify(&signed_responder_ephemeral_key)?;

        let root_key = self.x3dh(
            HandshakeState::Initiator,
            &ephemeral_secret_key,
            responder_prekey,
        )?;

        let initial_message = InitialMessage {
            initiator_prekey: Prekey {
                identity: self.signing_secret_key.sign(&self.public_key),
                ephemeral: self.signing_secret_key.sign(&ephemeral_public_key),
            },
            responder_ephemeral_key: signed_responder_ephemeral_key,
        };

        Ok((root_key, responder_ephemeral_key, initial_message))
    }

    pub fn respond(
        &mut self,
        initial_message: InitialMessage,
    ) -> Result<(RootKey, (PublicKey, SecretKey)), ()> {
        let ephemeral_public_key = self
            .signing_public_key
            .verify(&initial_message.responder_ephemeral_key)?;
        let ephemeral_secret_key = self
            .ephemeral_keypairs
            .remove(&ephemeral_public_key)
            .ok_or(())?;
        let initiator_prekey = initial_message.initiator_prekey;

        let root_key = self.x3dh(
            HandshakeState::Responder,
            &ephemeral_secret_key,
            initiator_prekey,
        )?;

        Ok((root_key, (ephemeral_public_key, ephemeral_secret_key)))
    }

    fn x3dh(
        &mut self,
        handshake_state: HandshakeState,
        own_ephemeral_secret_key: &SecretKey,
        peer_prekey: Prekey,
    ) -> Result<RootKey, ()> {
        let peer_identity_public_key = peer_prekey.identity.signer.verify(&peer_prekey.identity)?;
        let peer_ephemeral_public_key =
            peer_prekey.identity.signer.verify(&peer_prekey.ephemeral)?;

        let identity_ephemeral = self.secret_key.key_exchange(&peer_ephemeral_public_key)?;
        let ephemeral_identity =
            own_ephemeral_secret_key.key_exchange(&peer_identity_public_key)?;
        let ephemeral_ephemeral =
            own_ephemeral_secret_key.key_exchange(&peer_ephemeral_public_key)?;

        // Swap based on handshake_state to present the same argument order to the kdf.
        let (initiator_responder, responder_initiator) = match handshake_state {
            HandshakeState::Initiator => (identity_ephemeral, ephemeral_identity),
            HandshakeState::Responder => (ephemeral_identity, identity_ephemeral),
        };

        Ok(SessionKey::derive_key(
            initiator_responder,
            responder_initiator,
            ephemeral_ephemeral,
        ))
    }
}

pub struct Prekey {
    identity: SignedPublicKey,
    ephemeral: SignedPublicKey,
}

pub struct InitialMessage {
    initiator_prekey: Prekey,
    responder_ephemeral_key: SignedPublicKey,
}

enum HandshakeState {
    Initiator,
    Responder,
}

#[cfg(test)]
mod tests {
    use super::Handshake;

    #[test]
    fn vanilla_handshake() {
        let mut alice = Handshake::new().unwrap();
        let mut bob = Handshake::new().unwrap();

        let bob_prekey = bob.generate_prekey();

        let alice_initiate = alice.initiate(bob_prekey);
        assert!(alice_initiate.is_ok());
        let (alice_root_key, bob_ephemeral_key, initial_message) = alice_initiate.unwrap();

        let bob_respond = bob.respond(initial_message);
        assert!(bob_respond.is_ok());
        let (bob_root_key, bob_ephemeral_keypair) = bob_respond.unwrap();

        assert!(alice_root_key == bob_root_key);
        assert!(bob_ephemeral_key == bob_ephemeral_keypair.0);
    }
}
