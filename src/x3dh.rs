use std::collections;

use crate::crypto::{
    Handshake, Prekey, PublicKey, SecretKey, SessionId, SessionKey, SigningSecretKey, UserId,
};
use crate::error::Error::{self, *};
use crate::session::Session;

/// Manage identity keys for a user
///
/// Before initiating a session with Bob, Alice must first acquire Bob's prekey, which may be
/// hosted on an untrusted server. Assuming Alice has an out-of-band method for trusting Bob's
/// signing key (included in the prekey), she generates a session and sends a handshake
/// containing her own prekey, which provides enough information for Bob to initiate
/// a matching session.
///
/// To maintain forward secrecy, each user discards the ephemeral keys used to facilitate the
/// exchange. Even if both identity keys are later compromised, an attacker Eve cannot reconstruct
/// this session.
pub struct User {
    user_id: UserId,
    sign_secret_key: SigningSecretKey,
    agree_secret_key: SecretKey,
    ephemeral_keypairs: collections::HashMap<PublicKey, SecretKey>,
}

impl User {
    pub fn new() -> User {
        let (sign, sign_secret_key) = SigningSecretKey::generate_pair();
        let (agree, agree_secret_key) = SecretKey::generate_pair();
        let user_id = UserId::new(sign, sign_secret_key.sign(&agree));
        User {
            user_id,
            sign_secret_key,
            agree_secret_key,
            ephemeral_keypairs: collections::HashMap::new(),
        }
    }

    pub fn publish_prekey(&mut self) -> Prekey {
        let (ephemeral_public_key, ephemeral_secret_key, prekey) = self.generate_prekey();
        self.ephemeral_keypairs
            .insert(ephemeral_public_key, ephemeral_secret_key);
        prekey
    }

    pub fn initiate(&self, responder_prekey: Prekey) -> Result<Session, Error> {
        let (_, ephemeral_secret_key, initiator_prekey) = self.generate_prekey();
        let responder_ephemeral_key = responder_prekey
            .user_id
            .sign
            .verify(&responder_prekey.ephemeral)?;
        let session_key = self.x3dh(
            UserState::Initiator,
            &ephemeral_secret_key,
            &responder_prekey,
        )?;
        let session_id = SessionId::new(self.user_id.clone(), responder_prekey.user_id.clone());
        let handshake = Handshake {
            initiator_prekey,
            responder_prekey,
        };

        Session::new_initiator(session_id, session_key, responder_ephemeral_key, handshake)
    }

    pub fn respond(&mut self, handshake: Handshake) -> Result<Session, Error> {
        let ephemeral_public_key = self
            .user_id
            .sign
            .verify(&handshake.responder_prekey.ephemeral)?;
        let ephemeral_secret_key = self
            .ephemeral_keypairs
            .remove(&ephemeral_public_key)
            .ok_or(MissingEphemeralKey)?;
        let session_key = self.x3dh(
            UserState::Responder,
            &ephemeral_secret_key,
            &handshake.initiator_prekey,
        )?;
        let session_id = SessionId::new(handshake.initiator_prekey.user_id, self.user_id.clone());

        Session::new_responder(
            session_id,
            session_key,
            ephemeral_public_key,
            ephemeral_secret_key,
        )
    }

    pub fn id(&self) -> UserId {
        self.user_id.clone()
    }

    pub fn agree_secret_key(&self) -> &SecretKey {
        &self.agree_secret_key
    }

    fn generate_prekey(&self) -> (PublicKey, SecretKey, Prekey) {
        let (ephemeral_public_key, ephemeral_secret_key) = SecretKey::generate_pair();
        let prekey = Prekey {
            user_id: self.user_id.clone(),
            ephemeral: self.sign_secret_key.sign(&ephemeral_public_key),
        };

        (ephemeral_public_key, ephemeral_secret_key, prekey)
    }

    fn x3dh(
        &self,
        user_state: UserState,
        ephemeral_secret_key: &SecretKey,
        prekey: &Prekey,
    ) -> Result<SessionKey, Error> {
        let identity_public_key = prekey.user_id.sign.verify(&prekey.user_id.agree)?;
        let ephemeral_public_key = prekey.user_id.sign.verify(&prekey.ephemeral)?;

        let identity_ephemeral = self.agree_secret_key.key_exchange(&ephemeral_public_key)?;
        let ephemeral_identity = ephemeral_secret_key.key_exchange(&identity_public_key)?;
        let ephemeral_ephemeral = ephemeral_secret_key.key_exchange(&ephemeral_public_key)?;

        // Swap based on user_state to present the same argument order to the kdf.
        let (initiator_responder, responder_initiator) = match user_state {
            UserState::Initiator => (identity_ephemeral, ephemeral_identity),
            UserState::Responder => (ephemeral_identity, identity_ephemeral),
        };

        Ok(SessionKey::derive_from_shared_secrets(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningPublicKey;

    #[test]
    fn user_exchange() {
        let alice = User::new();
        let mut bob = User::new();

        let bob_prekey = bob.publish_prekey();
        let alice_session = alice
            .initiate(bob_prekey)
            .expect("Failed to initiate alice's session with bob prekey");
        let _bob_session = bob
            .respond(alice_session.handshake().unwrap())
            .expect("Failed for bob to respond to alice's handshake");
    }

    #[test]
    fn user_initiate_wrong_signer() {
        let alice = User::new();
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();

        let eve_signer = SigningSecretKey::generate_pair().0;
        let eve_prekey = Prekey {
            user_id: UserId::new(eve_signer, bob_prekey.user_id.agree),
            ephemeral: bob_prekey.ephemeral,
        };
        assert!(alice.initiate(eve_prekey).is_err());
    }

    #[test]
    fn user_initiate_wrong_identity() {
        let alice = User::new();
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();

        let eve_identity = SigningSecretKey::generate_pair()
            .1
            .sign(&SecretKey::generate_pair().0);
        let eve_prekey = Prekey {
            user_id: UserId::new(bob_prekey.user_id.sign, eve_identity),
            ephemeral: bob_prekey.ephemeral,
        };
        assert!(alice.initiate(eve_prekey).is_err());
    }

    #[test]
    fn user_initiate_wrong_ephemeral() {
        let alice = User::new();
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();

        let eve_ephemeral = SigningSecretKey::generate_pair()
            .1
            .sign(&SecretKey::generate_pair().0);
        let eve_prekey = Prekey {
            user_id: bob_prekey.user_id,
            ephemeral: eve_ephemeral,
        };
        assert!(alice.initiate(eve_prekey).is_err());
    }

    #[test]
    fn user_initiate_invalid_signer() {
        let alice = User::new();
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();

        let invalid_signer = SigningPublicKey::invalid();
        let invalid_prekey = Prekey {
            user_id: UserId::new(invalid_signer, bob_prekey.user_id.agree),
            ephemeral: bob_prekey.ephemeral,
        };
        assert!(alice.initiate(invalid_prekey).is_err());
    }

    #[test]
    fn user_initiate_invalid_identity() {
        let alice = User::new();

        let (signing_public_key, signing_secret_key) = SigningSecretKey::generate_pair();
        let invalid_identity = signing_secret_key.sign(&PublicKey::invalid());
        let ephemeral = signing_secret_key.sign(&SecretKey::generate_pair().0);
        let invalid_prekey = Prekey {
            user_id: UserId::new(signing_public_key, invalid_identity),
            ephemeral,
        };
        assert!(alice.initiate(invalid_prekey).is_err());
    }

    #[test]
    fn user_initiate_invalid_ephemeral() {
        let alice = User::new();

        let (signing_public_key, signing_secret_key) = SigningSecretKey::generate_pair();
        let identity = signing_secret_key.sign(&SecretKey::generate_pair().0);
        let invalid_ephemeral = signing_secret_key.sign(&PublicKey::invalid());
        let invalid_prekey = Prekey {
            user_id: UserId::new(signing_public_key, identity),
            ephemeral: invalid_ephemeral,
        };
        assert!(alice.initiate(invalid_prekey).is_err());
    }

    #[test]
    fn user_respond_wrong_signer() {
        let alice = User::new();
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();
        let alice_session = alice
            .initiate(bob_prekey)
            .expect("Failed to initiate alice's session with bob prekey");
        let handshake = alice_session.handshake().unwrap();

        let eve_signer = SigningSecretKey::generate_pair().0;
        let eve_handshake = Handshake {
            initiator_prekey: Prekey {
                user_id: UserId::new(eve_signer, handshake.initiator_prekey.user_id.agree),
                ephemeral: handshake.initiator_prekey.ephemeral,
            },
            responder_prekey: handshake.responder_prekey,
        };
        assert!(bob.respond(eve_handshake).is_err());
    }

    #[test]
    fn user_respond_wrong_identity() {
        let alice = User::new();
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();
        let alice_session = alice
            .initiate(bob_prekey)
            .expect("Failed to initiate alice's session with bob prekey");
        let handshake = alice_session.handshake().unwrap();

        let eve_identity = SigningSecretKey::generate_pair()
            .1
            .sign(&SecretKey::generate_pair().0);
        let eve_handshake = Handshake {
            initiator_prekey: Prekey {
                user_id: UserId::new(handshake.initiator_prekey.user_id.sign, eve_identity),
                ephemeral: handshake.initiator_prekey.ephemeral,
            },
            responder_prekey: handshake.responder_prekey,
        };
        assert!(bob.respond(eve_handshake).is_err());
    }

    #[test]
    fn user_respond_wrong_ephemeral() {
        let alice = User::new();
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();
        let alice_session = alice
            .initiate(bob_prekey)
            .expect("Failed to initiate alice's session with bob prekey");
        let handshake = alice_session.handshake().unwrap();

        let eve_ephemeral = SigningSecretKey::generate_pair()
            .1
            .sign(&SecretKey::generate_pair().0);
        let eve_handshake = Handshake {
            initiator_prekey: Prekey {
                user_id: handshake.initiator_prekey.user_id,
                ephemeral: eve_ephemeral,
            },
            responder_prekey: handshake.responder_prekey,
        };
        assert!(bob.respond(eve_handshake).is_err());
    }

    #[test]
    fn user_respond_wrong_responder_ephemeral() {
        let alice = User::new();
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();
        let alice_session = alice
            .initiate(bob_prekey)
            .expect("Failed to initiate alice's session with bob prekey");
        let handshake = alice_session.handshake().unwrap();

        let eve_ephemeral = SigningSecretKey::generate_pair()
            .1
            .sign(&SecretKey::generate_pair().0);
        let eve_handshake = Handshake {
            initiator_prekey: handshake.initiator_prekey,
            responder_prekey: Prekey {
                user_id: handshake.responder_prekey.user_id,
                ephemeral: eve_ephemeral,
            },
        };
        assert!(bob.respond(eve_handshake).is_err());
    }

    #[test]
    fn user_respond_replay_responder_prekey() {
        let alice = User::new();
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();
        let alice_session = alice
            .initiate(bob_prekey.clone())
            .expect("Failed to initiate alice's session with bob prekey");
        let _bob_session = bob
            .respond(alice_session.handshake().unwrap())
            .expect("Failed for bob to respond to alice's handshake");

        let eve = User::new();
        let eve_session = eve
            .initiate(bob_prekey)
            .expect("Failed to initiate eve's session with bob prekey");

        assert!(bob.respond(eve_session.handshake().unwrap()).is_err());
    }

    #[test]
    fn user_respond_invalid_signer() {
        let alice = User::new();
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();
        let alice_session = alice
            .initiate(bob_prekey)
            .expect("Failed to initiate alice's session with bob prekey");
        let handshake = alice_session.handshake().unwrap();

        let eve_signer = SigningPublicKey::invalid();
        let eve_handshake = Handshake {
            initiator_prekey: Prekey {
                user_id: UserId::new(eve_signer, handshake.initiator_prekey.user_id.agree),
                ephemeral: handshake.initiator_prekey.ephemeral,
            },
            responder_prekey: handshake.responder_prekey,
        };
        assert!(bob.respond(eve_handshake).is_err());
    }

    #[test]
    fn user_respond_invalid_identity() {
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();

        let (signing_public_key, signing_secret_key) = SigningSecretKey::generate_pair();
        let invalid_identity = signing_secret_key.sign(&PublicKey::invalid());
        let ephemeral = signing_secret_key.sign(&SecretKey::generate_pair().0);
        let eve_handshake = Handshake {
            initiator_prekey: Prekey {
                user_id: UserId::new(signing_public_key, invalid_identity),
                ephemeral,
            },
            responder_prekey: bob_prekey,
        };
        assert!(bob.respond(eve_handshake).is_err());
    }

    #[test]
    fn user_respond_invalid_ephemeral() {
        let mut bob = User::new();
        let bob_prekey = bob.publish_prekey();

        let (signing_public_key, signing_secret_key) = SigningSecretKey::generate_pair();
        let identity = signing_secret_key.sign(&SecretKey::generate_pair().0);
        let invalid_ephemeral = signing_secret_key.sign(&PublicKey::invalid());
        let eve_handshake = Handshake {
            initiator_prekey: Prekey {
                user_id: UserId::new(signing_public_key, identity),
                ephemeral: invalid_ephemeral,
            },
            responder_prekey: bob_prekey,
        };
        assert!(bob.respond(eve_handshake).is_err());
    }
}
