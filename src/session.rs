use std::mem;

use crate::crypto::{Header, HeaderKey, Message, Nonce, Plaintext, PublicKey, RootKey, SecretKey};
use crate::keys::SkippedMessageKeys;
use crate::ratchet::{ChainRatchet, PublicRatchet};

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
            Responding(_state) => Err(()),
            Normal(state) => Ok(state.ratchet_encrypt(plaintext)),
            Error => Err(()),
        }
    }

    pub fn ratchet_decrypt(&mut self, message: Message) -> Result<Plaintext, ()> {
        use SessionState::*;
        let mut next = Error;
        mem::swap(&mut self.state, &mut next);
        let (mut next, result) = match next {
            Initiating(state) | Responding(state) => match state.ratchet_decrypt(message) {
                Ok((state, plaintext)) => (Normal(state), Ok(plaintext)),
                Err(()) => (Error, Err(())),
            },
            Normal(mut state) => match state.ratchet_decrypt(message) {
                Ok(plaintext) => (Normal(state), Ok(plaintext)),
                Err(()) => (Error, Err(())),
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
            send: ChainRatchet::new_burner(send_header_key),
            receive_header_key,
        })
    }

    fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (nonce, message_key) = self.send.ratchet();
        let header = Header {
            public_key: self.public.send_public_key.clone(),
            previous_nonce: Nonce::new_zero(),
            nonce,
        };
        let encrypted_header = self.send.header_key.encrypt(header);
        message_key.encrypt(plaintext, encrypted_header, nonce)
    }

    fn ratchet_decrypt(mut self, message: Message) -> Result<(NormalState, Plaintext), ()> {
        let header = self.receive_header_key.decrypt(&message.encrypted_header)?;
        if header.previous_nonce != Nonce::new_zero() {
            // Previous nonce can only be nonzero after a full session handshake has occurred.
            return Err(());
        }

        let (mut receive, previous_send_nonce) = self.ratchet(header.public_key.clone())?;

        let mut skipped_message_keys = SkippedMessageKeys::new();
        skipped_message_keys.skip(&mut receive, header.nonce);

        let (nonce, message_key) = receive.ratchet();
        let plaintext = message_key.decrypt(message, nonce)?;

        let state = NormalState {
            public: self.public,
            send: self.send,
            receive,
            previous_send_nonce,
            skipped_message_keys,
        };

        Ok((state, plaintext))
    }

    fn ratchet(&mut self, receive_public_key: PublicKey) -> Result<(ChainRatchet, Nonce), ()> {
        let (receive, previous_send_nonce) = self.public.ratchet(
            &mut self.send,
            self.receive_header_key.clone(),
            receive_public_key,
        )?;
        Ok((receive, previous_send_nonce))
    }
}

struct NormalState {
    public: PublicRatchet,
    send: ChainRatchet,
    receive: ChainRatchet,
    previous_send_nonce: Nonce,
    skipped_message_keys: SkippedMessageKeys,
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
            .skipped_message_keys
            .decrypt_header(&message.encrypted_header)
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
                    self.skipped_message_keys
                        .skip(&mut self.receive, header.previous_nonce);
                    self.ratchet(header.public_key.clone())?;
                    header.nonce
                } else {
                    return Err(());
                };

                self.skipped_message_keys.skip(&mut self.receive, nonce);
                self.receive.ratchet()
            }
        };
        message_key.decrypt(message, nonce)
    }

    fn ratchet(&mut self, receive_public_key: PublicKey) -> Result<(), ()> {
        let (receive, previous_send_nonce) = self.public.ratchet(
            &mut self.send,
            self.receive.next_header_key.clone(),
            receive_public_key,
        )?;
        self.receive = receive;
        self.previous_send_nonce = previous_send_nonce;
        Ok(())
    }
}
