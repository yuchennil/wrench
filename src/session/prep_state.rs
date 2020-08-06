use crate::crypto::{Header, HeaderKey, Message, Nonce, Plaintext, PublicKey, RootKey, SecretKey};
use crate::error::Error;
use crate::error::Error::*;
use crate::session::{
    chain_ratchet::ChainRatchet, normal_state::NormalState, public_ratchet::PublicRatchet,
    skipped_keys::SkippedKeys,
};

/// Preparatory session state before the first received reply.
///
/// Encryption of messages is possible (albeit disallowed for responders), but decryption
/// will consume self and transition to either a normal or error state.
pub struct PrepState {
    public: PublicRatchet,
    send: ChainRatchet,
    receive_header_key: HeaderKey,
}

impl PrepState {
    pub fn new_initiator(
        receive_public_key: PublicKey,
        root_key: RootKey,
    ) -> Result<PrepState, Error> {
        let (send_public_key, send_secret_key) = SecretKey::generate_pair();
        let (root_key, initiator_header_key, responder_header_key) = root_key.derive_header_keys();
        let mut public = PublicRatchet::new(send_public_key, send_secret_key, root_key);
        let send = public.advance(receive_public_key, initiator_header_key)?;

        Ok(PrepState {
            public,
            send,
            receive_header_key: responder_header_key,
        })
    }

    pub fn new_responder(
        send_public_key: PublicKey,
        send_secret_key: SecretKey,
        root_key: RootKey,
    ) -> Result<PrepState, Error> {
        let (root_key, initiator_header_key, responder_header_key) = root_key.derive_header_keys();
        Ok(PrepState {
            public: PublicRatchet::new(send_public_key, send_secret_key, root_key),
            send: ChainRatchet::invalid(responder_header_key),
            receive_header_key: initiator_header_key,
        })
    }

    pub fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (nonce, message_key) = self.send.ratchet();
        let header = Header {
            public_key: self.public.send_public_key.clone(),
            previous_nonce: Nonce::new(0),
            nonce,
        };
        let encrypted_header = self.send.header_key.encrypt(header);
        message_key.encrypt(plaintext, encrypted_header, nonce)
    }

    pub fn ratchet_decrypt(mut self, message: Message) -> Result<(NormalState, Plaintext), Error> {
        let header = self.receive_header_key.decrypt(&message.encrypted_header)?;
        if header.previous_nonce != Nonce::new(0) {
            // Previous nonce can only be nonzero after a full session handshake has occurred.
            return Err(Unknown);
        }

        let (send, mut receive, previous_send_nonce) = self.ratchet(header.public_key.clone())?;

        let mut skipped_keys = SkippedKeys::new();
        skipped_keys.skip_to_nonce(&mut receive, header.nonce)?;

        let (nonce, message_key) = receive.ratchet();
        let plaintext = message_key.decrypt(message, nonce)?;

        let state = NormalState::new(
            self.public,
            send,
            receive,
            previous_send_nonce,
            skipped_keys,
        );

        Ok((state, plaintext))
    }

    fn ratchet(
        &mut self,
        receive_public_key: PublicKey,
    ) -> Result<(ChainRatchet, ChainRatchet, Nonce), Error> {
        let previous_send_nonce = self.send.nonce;
        let (send, receive) = self.public.ratchet(
            receive_public_key,
            self.send.next_header_key.clone(),
            self.receive_header_key.clone(),
        )?;
        Ok((send, receive, previous_send_nonce))
    }
}
