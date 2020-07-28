use std::mem;

use crate::crypto::{Header, HeaderKey, Message, Nonce, Plaintext, PublicKey, RootKey, SecretKey};
use crate::keys::SkippedKeys;
use crate::ratchet::{ChainRatchet, PublicRatchet};

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
        root_key: RootKey,
        send_header_key: HeaderKey,
        receive_header_key: HeaderKey,
    ) -> Result<Session, ()> {
        use SessionState::*;
        let state = PrepState::new_initiator(
            receive_public_key,
            root_key,
            send_header_key,
            receive_header_key,
        )?;
        Ok(Session {
            state: Initiating(state),
        })
    }

    pub fn new_responder(
        send_public_key: PublicKey,
        send_secret_key: SecretKey,
        root_key: RootKey,
        send_header_key: HeaderKey,
        receive_header_key: HeaderKey,
    ) -> Result<Session, ()> {
        use SessionState::*;
        let state = PrepState::new_responder(
            send_public_key,
            send_secret_key,
            root_key,
            send_header_key,
            receive_header_key,
        )?;
        Ok(Session {
            state: Responding(state),
        })
    }

    pub fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Result<Message, ()> {
        use SessionState::*;
        match &mut self.state {
            Initiating(state) => Ok(state.ratchet_encrypt(plaintext)),
            Normal(state) => Ok(state.ratchet_encrypt(plaintext)),
            Responding(_) | Error => Err(()),
        }
    }

    pub fn ratchet_decrypt(&mut self, message: Message) -> Result<Plaintext, ()> {
        use SessionState::*;
        let mut next = Error;
        mem::swap(&mut self.state, &mut next);
        let (mut next, result) = match next {
            Initiating(state) | Responding(state) => match state.ratchet_decrypt(message) {
                Ok((state, plaintext)) => (Normal(state), Ok(plaintext)),
                Err(_) => (Error, Err(())),
            },
            Normal(mut state) => match state.ratchet_decrypt(message) {
                Ok(plaintext) => (Normal(state), Ok(plaintext)),
                Err(_) => (Error, Err(())),
            },
            Error => (Error, Err(())),
        };
        mem::swap(&mut self.state, &mut next);
        result
    }
}

enum SessionState {
    Initiating(PrepState),
    Responding(PrepState),
    Normal(NormalState),
    Error,
}

/// Preparatory session state before the first received reply.
///
/// Encryption of messages is possible (albeit disallowed for responders), but decryption
/// will consume self and transition to either a normal or error state.
struct PrepState {
    public: PublicRatchet,
    send: ChainRatchet,
    receive_header_key: HeaderKey,
}

impl PrepState {
    fn new_initiator(
        receive_public_key: PublicKey,
        root_key: RootKey,
        send_header_key: HeaderKey,
        receive_header_key: HeaderKey,
    ) -> Result<PrepState, ()> {
        let (send_public_key, send_secret_key) = SecretKey::generate_pair();
        let mut public = PublicRatchet::new(send_public_key, send_secret_key, root_key);
        let send = public.advance(receive_public_key, send_header_key)?;

        Ok(PrepState {
            public,
            send,
            receive_header_key,
        })
    }

    fn new_responder(
        send_public_key: PublicKey,
        send_secret_key: SecretKey,
        root_key: RootKey,
        send_header_key: HeaderKey,
        receive_header_key: HeaderKey,
    ) -> Result<PrepState, ()> {
        Ok(PrepState {
            public: PublicRatchet::new(send_public_key, send_secret_key, root_key),
            send: ChainRatchet::invalid(send_header_key),
            receive_header_key,
        })
    }

    fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (nonce, message_key) = self.send.ratchet();
        let header = Header {
            public_key: self.public.send_public_key.clone(),
            previous_nonce: Nonce::new(0),
            nonce,
        };
        let encrypted_header = self.send.header_key.encrypt(header);
        message_key.encrypt(plaintext, encrypted_header, nonce)
    }

    fn ratchet_decrypt(mut self, message: Message) -> Result<(NormalState, Plaintext), ()> {
        let header = self.receive_header_key.decrypt(&message.encrypted_header)?;
        if header.previous_nonce != Nonce::new(0) {
            // Previous nonce can only be nonzero after a full session handshake has occurred.
            return Err(());
        }

        let (send, mut receive, previous_send_nonce) = self.ratchet(header.public_key.clone())?;

        let mut skipped_keys = SkippedKeys::new();
        skipped_keys.skip_to_nonce(&mut receive, header.nonce)?;

        let (nonce, message_key) = receive.ratchet();
        let plaintext = message_key.decrypt(message, nonce)?;

        let state = NormalState {
            public: self.public,
            send,
            receive,
            previous_send_nonce,
            skipped_keys,
        };

        Ok((state, plaintext))
    }

    fn ratchet(
        &mut self,
        receive_public_key: PublicKey,
    ) -> Result<(ChainRatchet, ChainRatchet, Nonce), ()> {
        let previous_send_nonce = self.send.nonce;
        let (send, receive) = self.public.ratchet(
            receive_public_key,
            self.send.next_header_key.clone(),
            self.receive_header_key.clone(),
        )?;
        Ok((send, receive, previous_send_nonce))
    }
}

/// Session state during normal use.
///
/// Messages that are dropped or received out of order will cause ratchets to advance to
/// the highest seen nonce (within reasonable limits). Skipped message keys will be stored
/// until their messages arrive.
struct NormalState {
    public: PublicRatchet,
    send: ChainRatchet,
    receive: ChainRatchet,
    previous_send_nonce: Nonce,
    skipped_keys: SkippedKeys,
}

impl NormalState {
    fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (nonce, message_key) = self.send.ratchet();
        let header = Header {
            public_key: self.public.send_public_key.clone(),
            previous_nonce: self.previous_send_nonce,
            nonce,
        };
        let encrypted_header = self.send.header_key.encrypt(header);
        message_key.encrypt(plaintext, encrypted_header, nonce)
    }

    fn ratchet_decrypt(&mut self, message: Message) -> Result<Plaintext, ()> {
        let (nonce, message_key) = match self
            .skipped_keys
            .try_decrypt_header(&message.encrypted_header)
        {
            Some(nonce_message_key) => nonce_message_key,
            None => {
                let nonce = if let Ok(header) =
                    self.receive.header_key.decrypt(&message.encrypted_header)
                {
                    header.nonce
                } else if let Ok(header) = self
                    .receive
                    .next_header_key
                    .decrypt(&message.encrypted_header)
                {
                    self.skipped_keys
                        .skip_to_nonce(&mut self.receive, header.previous_nonce)?;
                    self.ratchet(header.public_key.clone())?;
                    header.nonce
                } else {
                    return Err(());
                };

                self.skipped_keys.skip_to_nonce(&mut self.receive, nonce)?;
                self.receive.ratchet()
            }
        };
        message_key.decrypt(message, nonce)
    }

    fn ratchet(&mut self, receive_public_key: PublicKey) -> Result<(), ()> {
        let previous_send_nonce = self.send.nonce;
        let (send, receive) = self.public.ratchet(
            receive_public_key,
            self.send.next_header_key.clone(),
            self.receive.next_header_key.clone(),
        )?;
        self.send = send;
        self.receive = receive;
        self.previous_send_nonce = previous_send_nonce;
        Ok(())
    }
}
