mod chain_ratchet;
mod normal_state;
mod prep_state;
mod public_ratchet;
mod skipped_keys;

use std::mem;

use crate::crypto::{AssociatedDataService, Message, Plaintext, PublicKey, SecretKey, SessionKey};
use crate::error::Error::{self, *};
use crate::session::{normal_state::NormalState, prep_state::PrepState};

/// Send and receive encrypted messages with one peer.
///
/// Messages may be dropped or arrive out of order, within reasonable limits.
///
/// The initiator of a session must send the first message. The responder may not send messages
/// until they have successfully decrypted their first message.
///
/// To prevent state corruption, any errors in encrypting or decrypting will cause the session to
/// enter an unrecoverable error state. Any future messages will also result in error.
///
/// These constraints can be seen in the following state diagrams:
///
/// #                SEND                                    RECEIVE
/// #   -->Initiating   Responding                   Initiating   Responding
/// #   |       |       |                                     |\ /|
/// #   ---------       |                                     | X |
/// #   ---------       |   ---------             ---------   |/ \|   ---------
/// #   |       |       V   |       |             |       |   V   V   |       |
/// #   ------>Normal   Error<-------             ------>Normal-->Error<-------
///
/// Message keys update with a double ratchet:
/// 1) Each received message contains a new public key used to deterministically update the
/// message keys' source of randomness (i.e., 'public ratchet').
/// 2) Each message sent or received updates its message key, derived deterministically from the
/// source of randomness (i.e., 'chain ratchet').
///
/// Even the message headers are encrypted, so that an interceptor may not be able to tell who the
/// participants of a session are.
pub struct Session {
    state: SessionState,
}

impl Session {
    pub fn new_initiator(
        receive_public_key: PublicKey,
        session_key: SessionKey,
        associated_data_service: AssociatedDataService,
    ) -> Result<Session, Error> {
        let state =
            PrepState::new_initiator(receive_public_key, session_key, associated_data_service)?;
        Ok(Session {
            state: SessionState::Initiating(state),
        })
    }

    pub fn new_responder(
        send_public_key: PublicKey,
        send_secret_key: SecretKey,
        session_key: SessionKey,
        associated_data_service: AssociatedDataService,
    ) -> Result<Session, Error> {
        let state = PrepState::new_responder(
            send_public_key,
            send_secret_key,
            session_key,
            associated_data_service,
        )?;
        Ok(Session {
            state: SessionState::Responding(state),
        })
    }

    pub fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Result<Message, Error> {
        use SessionState::*;
        match &mut self.state {
            Initiating(state) => Ok(state.ratchet_encrypt(plaintext)),
            Responding(_) => {
                self.state = Error;
                Err(InvalidState)
            }
            Normal(state) => Ok(state.ratchet_encrypt(plaintext)),
            Error => Err(InvalidState),
        }
    }

    pub fn ratchet_decrypt(&mut self, message: Message) -> Result<Plaintext, Error> {
        use SessionState::*;
        let mut next = Error;
        mem::swap(&mut self.state, &mut next);
        let (mut next, result) = match next {
            Initiating(state) | Responding(state) => match state.ratchet_decrypt(message) {
                Ok((state, plaintext)) => (Normal(state), Ok(plaintext)),
                Err(error) => (Error, Err(error)),
            },
            Normal(mut state) => match state.ratchet_decrypt(message) {
                Ok(plaintext) => (Normal(state), Ok(plaintext)),
                Err(error) => (Error, Err(error)),
            },
            Error => (Error, Err(InvalidState)),
        };
        mem::swap(&mut self.state, &mut next);
        result
    }
}

/// All Sessions are expected to reach Normal (the largest state), so there should be negligible
/// penalty allocating that memory for all Sessions
#[allow(clippy::large_enum_variant)]
enum SessionState {
    Initiating(PrepState),
    Responding(PrepState),
    Normal(NormalState),
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Header, HeaderKey, MessageKey, Nonce, SessionKey};

    #[test]
    fn session_state_initiating_encrypt() {
        let mut session = Session::new_initiator(
            SecretKey::generate_pair().0,
            SessionKey::generate(),
            AssociatedDataService::generate(),
        )
        .unwrap();

        let plaintext = Plaintext("plaintext".as_bytes().to_vec());

        if let SessionState::Initiating(_) = session.state {
            assert!(session.ratchet_encrypt(plaintext).is_ok());
        } else {
            panic!("Session state is not Initiating");
        }
    }

    #[test]
    fn session_state_initiating_decrypt() {
        let (bob_public_key, bob_secret_key) = SecretKey::generate_pair();
        let session_key = SessionKey::generate();
        let associated_data_service = AssociatedDataService::generate();

        let mut alice_session = Session::new_initiator(
            bob_public_key.clone(),
            session_key.clone(),
            associated_data_service.clone(),
        )
        .unwrap();
        let mut bob_session = Session::new_responder(
            bob_public_key,
            bob_secret_key,
            session_key,
            associated_data_service,
        )
        .unwrap();

        let message = alice_session
            .ratchet_encrypt(Plaintext("plaintext".as_bytes().to_vec()))
            .unwrap();
        bob_session.ratchet_decrypt(message).unwrap();
        let message = bob_session
            .ratchet_encrypt(Plaintext("plaintext".as_bytes().to_vec()))
            .unwrap();

        if let SessionState::Initiating(_) = alice_session.state {
            assert!(alice_session.ratchet_decrypt(message).is_ok());
        } else {
            panic!("Session state is not Initiating");
        }
    }

    #[test]
    fn session_state_responding_encrypt() {
        let (public_key, secret_key) = SecretKey::generate_pair();
        let mut session = Session::new_responder(
            public_key,
            secret_key,
            SessionKey::generate(),
            AssociatedDataService::generate(),
        )
        .unwrap();

        let plaintext = Plaintext("plaintext".as_bytes().to_vec());

        if let SessionState::Responding(_) = session.state {
            assert!(session.ratchet_encrypt(plaintext).is_err());
            match session.state {
                SessionState::Error => {}
                _ => panic!("Session state not Error after invalid action"),
            }
        } else {
            panic!("Session state is not Responding");
        }
    }

    #[test]
    fn session_state_responding_decrypt() {
        let (bob_public_key, bob_secret_key) = SecretKey::generate_pair();
        let session_key = SessionKey::generate();
        let associated_data_service = AssociatedDataService::generate();

        let mut alice_session = Session::new_initiator(
            bob_public_key.clone(),
            session_key.clone(),
            associated_data_service.clone(),
        )
        .unwrap();
        let mut bob_session = Session::new_responder(
            bob_public_key,
            bob_secret_key,
            session_key,
            associated_data_service,
        )
        .unwrap();

        let message = alice_session
            .ratchet_encrypt(Plaintext("plaintext".as_bytes().to_vec()))
            .unwrap();

        if let SessionState::Responding(_) = bob_session.state {
            assert!(bob_session.ratchet_decrypt(message).is_ok());
        } else {
            panic!("Session state is not Responding");
        }
    }

    #[test]
    fn session_state_normal_encrypt() {
        let (bob_public_key, bob_secret_key) = SecretKey::generate_pair();
        let session_key = SessionKey::generate();
        let associated_data_service = AssociatedDataService::generate();

        let mut alice_session = Session::new_initiator(
            bob_public_key.clone(),
            session_key.clone(),
            associated_data_service.clone(),
        )
        .unwrap();
        let mut bob_session = Session::new_responder(
            bob_public_key,
            bob_secret_key,
            session_key,
            associated_data_service,
        )
        .unwrap();

        let message = alice_session
            .ratchet_encrypt(Plaintext("plaintext".as_bytes().to_vec()))
            .unwrap();
        bob_session.ratchet_decrypt(message).unwrap();
        let plaintext = Plaintext("plaintext".as_bytes().to_vec());

        if let SessionState::Normal(_) = bob_session.state {
            assert!(bob_session.ratchet_encrypt(plaintext).is_ok());
        } else {
            panic!("Session state is not Normal");
        }
    }

    #[test]
    fn session_state_normal_decrypt() {
        let (bob_public_key, bob_secret_key) = SecretKey::generate_pair();
        let session_key = SessionKey::generate();
        let associated_data_service = AssociatedDataService::generate();

        let mut alice_session = Session::new_initiator(
            bob_public_key.clone(),
            session_key.clone(),
            associated_data_service.clone(),
        )
        .unwrap();
        let mut bob_session = Session::new_responder(
            bob_public_key,
            bob_secret_key,
            session_key,
            associated_data_service,
        )
        .unwrap();

        let message = alice_session
            .ratchet_encrypt(Plaintext("plaintext".as_bytes().to_vec()))
            .unwrap();
        bob_session.ratchet_decrypt(message).unwrap();
        let message = alice_session
            .ratchet_encrypt(Plaintext("plaintext".as_bytes().to_vec()))
            .unwrap();

        if let SessionState::Normal(_) = bob_session.state {
            assert!(bob_session.ratchet_decrypt(message).is_ok());
        } else {
            panic!("Session state is not Normal");
        }
    }

    #[test]
    fn session_state_error_encrypt() {
        let mut session = Session {
            state: SessionState::Error,
        };

        let plaintext = Plaintext("plaintext".as_bytes().to_vec());

        assert!(session.ratchet_encrypt(plaintext).is_err());
    }

    #[test]
    fn session_state_error_decrypt() {
        let mut session = Session {
            state: SessionState::Error,
        };

        let message = MessageKey::generate_twins().0.encrypt(
            Plaintext("plaintext".as_bytes().to_vec()),
            AssociatedDataService::generate().create(
                HeaderKey::generate().encrypt(Header {
                    public_key: SecretKey::generate_pair().0,
                    previous_nonce: Nonce::new(0),
                    nonce: Nonce::new(0),
                }),
                Nonce::new(0),
            ),
        );

        assert!(session.ratchet_decrypt(message).is_err());
    }
}
