use sodiumoxide::crypto::{generichash, kdf, kx, scalarmult};
use std::collections;

pub struct Handshake {
    identity_keypair: (kx::PublicKey, kx::SecretKey),
    ephemeral_keypairs: collections::HashMap<kx::PublicKey, kx::SecretKey>,
}

impl Handshake {
    pub fn new(identity_keypair: (kx::PublicKey, kx::SecretKey)) -> Handshake {
        Handshake {
            identity_keypair,
            ephemeral_keypairs: collections::HashMap::new(),
        }
    }

    pub fn generate_prekey(&mut self) -> PreKey {
        let (ephemeral_public_key, ephemeral_secret_key) = kx::gen_keypair();
        self.ephemeral_keypairs
            .insert(ephemeral_public_key, ephemeral_secret_key);

        PreKey {
            identity_key: self.identity_keypair.0,
            ephemeral_key: ephemeral_public_key,
        }
    }

    pub fn initiate(&mut self, responder_prekey: PreKey) -> Result<(kdf::Key, InitialMessage), ()> {
        let initiator_prekey = self.generate_prekey();
        let initiator_ephemeral_key = initiator_prekey.ephemeral_key;
        let responder_ephemeral_key = responder_prekey.ephemeral_key;

        let session_key = self.x3dh(
            HandshakeState::Initiator,
            initiator_ephemeral_key,
            responder_prekey,
        )?;
        let initial_message = InitialMessage {
            initiator_prekey,
            responder_ephemeral_key,
        };

        Ok((session_key, initial_message))
    }

    pub fn respond(&mut self, initial_message: InitialMessage) -> Result<kdf::Key, ()> {
        let responder_ephemeral_key = initial_message.responder_ephemeral_key;
        let initiator_prekey = initial_message.initiator_prekey;

        self.x3dh(
            HandshakeState::Responder,
            responder_ephemeral_key,
            initiator_prekey,
        )
    }

    fn x3dh(
        &mut self,
        handshake_state: HandshakeState,
        own_ephemeral_public_key: kx::PublicKey,
        peer_prekey: PreKey,
    ) -> Result<kdf::Key, ()> {
        let own_ephemeral_secret_key =
            match self.ephemeral_keypairs.remove(&own_ephemeral_public_key) {
                Some(secret_key) => secret_key,
                None => return Err(()),
            };

        let identity_ephemeral =
            Handshake::diffie_hellman(&self.identity_keypair.1, peer_prekey.ephemeral_key);
        let ephemeral_identity =
            Handshake::diffie_hellman(&own_ephemeral_secret_key, peer_prekey.identity_key);
        let ephemeral_ephemeral =
            Handshake::diffie_hellman(&own_ephemeral_secret_key, peer_prekey.ephemeral_key);

        // Swap based on handshake_state to present the same argument order to the kdf.
        let (initiator_responder, responder_initiator) = match handshake_state {
            HandshakeState::Initiator => (identity_ephemeral, ephemeral_identity),
            HandshakeState::Responder => (ephemeral_identity, identity_ephemeral),
        };

        Ok(Handshake::derive_key(
            initiator_responder,
            responder_initiator,
            ephemeral_ephemeral,
        ))
    }

    fn diffie_hellman(secret_key: &kx::SecretKey, public_key: kx::PublicKey) -> kx::SessionKey {
        let secret_scalar = scalarmult::Scalar::from_slice(&secret_key.0).unwrap();
        let public_group_element = scalarmult::GroupElement::from_slice(&public_key.0).unwrap();
        let shared_secret = scalarmult::scalarmult(&secret_scalar, &public_group_element).unwrap();

        kx::SessionKey::from_slice(&shared_secret.0).unwrap()
    }

    fn derive_key(key_0: kx::SessionKey, key_1: kx::SessionKey, key_2: kx::SessionKey) -> kdf::Key {
        let mut state = generichash::State::new(kdf::KEYBYTES, None).unwrap();
        state.update(&key_0.0).unwrap();
        state.update(&key_1.0).unwrap();
        state.update(&key_2.0).unwrap();

        kdf::Key::from_slice(&state.finalize().unwrap().as_ref()).unwrap()
    }
}

pub struct PreKey {
    identity_key: kx::PublicKey,
    ephemeral_key: kx::PublicKey,
}

pub struct InitialMessage {
    initiator_prekey: PreKey,
    responder_ephemeral_key: kx::PublicKey,
}

enum HandshakeState {
    Initiator,
    Responder,
}

#[cfg(test)]
mod tests {
    use super::Handshake;
    use sodiumoxide::{crypto::kx, init, utils::memcmp};

    #[test]
    fn vanilla_handshake() {
        assert!(init().is_ok());
        let mut alice = Handshake::new(kx::gen_keypair());
        let mut bob = Handshake::new(kx::gen_keypair());

        let bob_prekey = bob.generate_prekey();

        let alice_initiate = alice.initiate(bob_prekey);
        assert!(alice_initiate.is_ok());
        let (alice_session_key, initial_message) = alice_initiate.unwrap();

        let bob_respond = bob.respond(initial_message);
        assert!(bob_respond.is_ok());
        let bob_session_key = bob_respond.unwrap();

        assert!(memcmp(&alice_session_key.0, &bob_session_key.0));
    }
}
