use sodiumoxide::{
    crypto::{generichash, kdf, kx, scalarmult, sign},
    init,
    utils::memcmp,
};
use std::collections;

pub struct Handshake {
    identity_keypair: IdentityKeypair,
    ephemeral_keypairs: collections::HashMap<kx::PublicKey, kx::SecretKey>,
}

impl Handshake {
    pub fn new(identity_keypair: IdentityKeypair) -> Handshake {
        Handshake {
            identity_keypair,
            ephemeral_keypairs: collections::HashMap::new(),
        }
    }

    pub fn generate_prekey(&mut self) -> Prekey {
        let (ephemeral_public_key, ephemeral_secret_key) = kx::gen_keypair();
        self.ephemeral_keypairs
            .insert(ephemeral_public_key, ephemeral_secret_key);

        Prekey {
            identity: self.identity_keypair.public(),
            ephemeral: self.identity_keypair.sign(ephemeral_public_key),
        }
    }

    pub fn initiate(
        &mut self,
        responder_prekey: Prekey,
    ) -> Result<(kdf::Key, kx::PublicKey, InitialMessage), ()> {
        let (ephemeral_public_key, ephemeral_secret_key) = kx::gen_keypair();
        let signed_responder_ephemeral_key = responder_prekey.ephemeral.clone();
        let responder_ephemeral_key =
            signed_responder_ephemeral_key.verify(responder_prekey.identity.sign)?;

        let session_key = self.x3dh(
            HandshakeState::Initiator,
            &ephemeral_secret_key,
            responder_prekey,
        )?;

        let initial_message = InitialMessage {
            initiator_prekey: Prekey {
                identity: self.identity_keypair.public(),
                ephemeral: self.identity_keypair.sign(ephemeral_public_key),
            },
            responder_ephemeral_key: signed_responder_ephemeral_key,
        };

        Ok((session_key, responder_ephemeral_key, initial_message))
    }

    pub fn respond(
        &mut self,
        initial_message: InitialMessage,
    ) -> Result<(kdf::Key, (kx::PublicKey, kx::SecretKey)), ()> {
        let signed_ephemeral_public_key = initial_message.responder_ephemeral_key;
        let ephemeral_public_key =
            signed_ephemeral_public_key.verify(self.identity_keypair.sign.0)?;
        let ephemeral_secret_key = self
            .ephemeral_keypairs
            .remove(&ephemeral_public_key)
            .ok_or(())?;
        let initiator_prekey = initial_message.initiator_prekey;

        let session_key = self.x3dh(
            HandshakeState::Responder,
            &ephemeral_secret_key,
            initiator_prekey,
        )?;

        Ok((session_key, (ephemeral_public_key, ephemeral_secret_key)))
    }

    fn x3dh(
        &mut self,
        handshake_state: HandshakeState,
        own_ephemeral_secret_key: &kx::SecretKey,
        peer_prekey: Prekey,
    ) -> Result<kdf::Key, ()> {
        let sign_key = peer_prekey.identity.sign;
        let peer_identity_public_key = peer_prekey.identity.verify(sign_key)?;
        let peer_ephemeral_public_key = peer_prekey.ephemeral.verify(sign_key)?;

        let identity_ephemeral = self.identity_keypair.kx(peer_ephemeral_public_key)?;
        let ephemeral_identity =
            Handshake::diffie_hellman(own_ephemeral_secret_key, peer_identity_public_key)?;
        let ephemeral_ephemeral =
            Handshake::diffie_hellman(own_ephemeral_secret_key, peer_ephemeral_public_key)?;

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

    fn diffie_hellman(
        secret_key: &kx::SecretKey,
        public_key: kx::PublicKey,
    ) -> Result<kx::SessionKey, ()> {
        let secret_scalar = scalarmult::Scalar::from_slice(&secret_key.0).ok_or(())?;
        let public_group_element = scalarmult::GroupElement::from_slice(&public_key.0).ok_or(())?;
        let shared_secret = scalarmult::scalarmult(&secret_scalar, &public_group_element)?;

        kx::SessionKey::from_slice(&shared_secret.0).ok_or(())
    }

    fn derive_key(key_0: kx::SessionKey, key_1: kx::SessionKey, key_2: kx::SessionKey) -> kdf::Key {
        let mut state = generichash::State::new(kdf::KEYBYTES, None).unwrap();
        state.update(&key_0.0).unwrap();
        state.update(&key_1.0).unwrap();
        state.update(&key_2.0).unwrap();

        kdf::Key::from_slice(&state.finalize().unwrap().as_ref()).unwrap()
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

#[derive(Clone)]
struct SignedPublicKey {
    sign: sign::PublicKey,
    kx: Vec<u8>,
}

impl SignedPublicKey {
    fn new(sign: sign::PublicKey, kx: Vec<u8>) -> SignedPublicKey {
        SignedPublicKey { sign, kx }
    }

    fn verify(&self, signer: sign::PublicKey) -> Result<kx::PublicKey, ()> {
        if !memcmp(&self.sign.0, &signer.0) {
            return Err(());
        }

        kx::PublicKey::from_slice(&sign::verify(&self.kx, &self.sign)?).ok_or(())
    }
}

pub struct IdentityKeypair {
    sign: (sign::PublicKey, sign::SecretKey),
    kx: (kx::PublicKey, kx::SecretKey),
}

impl IdentityKeypair {
    pub fn new() -> Result<IdentityKeypair, ()> {
        init()?;
        Ok(IdentityKeypair {
            sign: sign::gen_keypair(),
            kx: kx::gen_keypair(),
        })
    }

    fn public(&self) -> SignedPublicKey {
        SignedPublicKey::new(self.sign.0, sign::sign(&(self.kx.0).0, &self.sign.1))
    }

    fn sign(&self, other: kx::PublicKey) -> SignedPublicKey {
        SignedPublicKey::new(self.sign.0, sign::sign(&other.0, &self.sign.1))
    }

    fn kx(&self, other: kx::PublicKey) -> Result<kx::SessionKey, ()> {
        Handshake::diffie_hellman(&self.kx.1, other)
    }
}

enum HandshakeState {
    Initiator,
    Responder,
}

#[cfg(test)]
mod tests {
    use super::{Handshake, IdentityKeypair};
    use sodiumoxide::{init, utils::memcmp};

    #[test]
    fn vanilla_handshake() {
        assert!(init().is_ok());
        let mut alice = Handshake::new(IdentityKeypair::new().unwrap());
        let mut bob = Handshake::new(IdentityKeypair::new().unwrap());

        let bob_prekey = bob.generate_prekey();

        let alice_initiate = alice.initiate(bob_prekey);
        assert!(alice_initiate.is_ok());
        let (alice_session_key, bob_ephemeral_key, initial_message) = alice_initiate.unwrap();

        let bob_respond = bob.respond(initial_message);
        assert!(bob_respond.is_ok());
        let (bob_session_key, bob_ephemeral_keypair) = bob_respond.unwrap();

        assert!(memcmp(&alice_session_key.0, &bob_session_key.0));
        assert!(memcmp(&bob_ephemeral_key.0, &(bob_ephemeral_keypair.0).0));
    }
}
