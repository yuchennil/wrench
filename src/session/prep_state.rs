use crate::crypto::{
    AssociatedDataService, Header, HeaderKey, Message, Nonce, Plaintext, PublicKey, SecretKey,
    SessionKey,
};
use crate::error::Error::{self, *};
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
    associated_data_service: AssociatedDataService,
}

impl PrepState {
    pub fn new_initiator(
        receive_public_key: PublicKey,
        session_key: SessionKey,
        associated_data_service: AssociatedDataService,
    ) -> Result<PrepState, Error> {
        let (send_public_key, send_secret_key) = SecretKey::generate_pair();
        let (root_key, initiator_header_key, responder_header_key) = session_key.derive_keys();
        let mut public = PublicRatchet::new(send_public_key, send_secret_key, root_key);
        let send = public.advance(receive_public_key, initiator_header_key)?;

        Ok(PrepState {
            public,
            send,
            receive_header_key: responder_header_key,
            associated_data_service,
        })
    }

    pub fn new_responder(
        send_public_key: PublicKey,
        send_secret_key: SecretKey,
        session_key: SessionKey,
        associated_data_service: AssociatedDataService,
    ) -> Result<PrepState, Error> {
        let (root_key, initiator_header_key, responder_header_key) = session_key.derive_keys();
        Ok(PrepState {
            public: PublicRatchet::new(send_public_key, send_secret_key, root_key),
            send: ChainRatchet::invalid(responder_header_key),
            receive_header_key: initiator_header_key,
            associated_data_service,
        })
    }

    pub fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (nonce, message_key) = self.send.ratchet();
        let encrypted_header = self.send.header_key.encrypt(Header {
            public_key: self.public.send_public_key.clone(),
            previous_nonce: Nonce::new(0),
            nonce,
        });
        let associated_data = self.associated_data_service.create(encrypted_header, nonce);
        message_key.encrypt(plaintext, associated_data)
    }

    pub fn ratchet_decrypt(mut self, message: Message) -> Result<(NormalState, Plaintext), Error> {
        let header = self.receive_header_key.decrypt(&message.encrypted_header)?;
        if header.previous_nonce != Nonce::new(0) {
            // Previous nonce can only be nonzero after a full session handshake has occurred.
            return Err(NonceOutOfRange);
        }

        let (send, mut receive, previous_send_nonce) = self.ratchet(header.public_key.clone())?;

        let mut skipped_keys = SkippedKeys::new();
        skipped_keys.skip_to_nonce(&mut receive, header.nonce)?;

        let (nonce, message_key) = receive.ratchet();
        let associated_data = self
            .associated_data_service
            .create(message.encrypted_header, nonce);
        let plaintext = message_key.decrypt(message.ciphertext, associated_data)?;

        let state = NormalState::new(
            self.public,
            send,
            receive,
            previous_send_nonce,
            skipped_keys,
            self.associated_data_service,
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
