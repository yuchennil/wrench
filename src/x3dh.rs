use sodiumoxide::init;
use std::collections;

use crate::crypto::{
    PublicKey, RootKey, SecretKey, SessionKey, SignedPublicKey, SigningPublicKey, SigningSecretKey,
};

pub struct Handshake {
    identity_keypair: IdentityKeypair,
    ephemeral_keypairs: collections::HashMap<PublicKey, SecretKey>,
}

impl Handshake {
    pub fn new(identity_keypair: IdentityKeypair) -> Handshake {
        Handshake {
            identity_keypair,
            ephemeral_keypairs: collections::HashMap::new(),
        }
    }

    pub fn generate_prekey(&mut self) -> Prekey {
        let (ephemeral_public_key, ephemeral_secret_key) = SecretKey::generate_pair();
        self.ephemeral_keypairs
            .insert(ephemeral_public_key.clone(), ephemeral_secret_key);

        Prekey {
            identity: self.identity_keypair.public(),
            ephemeral: self.identity_keypair.sign(&ephemeral_public_key),
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
                identity: self.identity_keypair.public(),
                ephemeral: self.identity_keypair.sign(&ephemeral_public_key),
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
            .identity_keypair
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

        let identity_ephemeral = self
            .identity_keypair
            .key_exchange(&peer_ephemeral_public_key)?;
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

pub struct IdentityKeypair {
    sign_public_key: SigningPublicKey,
    sign_secret_key: SigningSecretKey,
    kx_public_key: PublicKey,
    kx_secret_key: SecretKey,
}

impl IdentityKeypair {
    pub fn new() -> Result<IdentityKeypair, ()> {
        init()?;
        let (sign_public_key, sign_secret_key) = SigningSecretKey::generate_pair();
        let (kx_public_key, kx_secret_key) = SecretKey::generate_pair();
        Ok(IdentityKeypair {
            sign_public_key,
            sign_secret_key,
            kx_public_key,
            kx_secret_key,
        })
    }

    fn public(&self) -> SignedPublicKey {
        self.sign(&self.kx_public_key)
    }

    fn sign(&self, public_key: &PublicKey) -> SignedPublicKey {
        self.sign_secret_key.sign(&public_key)
    }

    fn verify(&self, signed_public_key: &SignedPublicKey) -> Result<PublicKey, ()> {
        self.sign_public_key.verify(&signed_public_key)
    }

    fn key_exchange(&self, other: &PublicKey) -> Result<SessionKey, ()> {
        self.kx_secret_key.key_exchange(other)
    }
}

enum HandshakeState {
    Initiator,
    Responder,
}

#[cfg(test)]
mod tests {
    use super::{Handshake, IdentityKeypair};
    use sodiumoxide::init;

    #[test]
    fn vanilla_handshake() {
        assert!(init().is_ok());
        let mut alice = Handshake::new(IdentityKeypair::new().unwrap());
        let mut bob = Handshake::new(IdentityKeypair::new().unwrap());

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
