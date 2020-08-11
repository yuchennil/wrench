use crate::crypto::{AssociatedDataService, Header, Message, Nonce, Plaintext, PublicKey};
use crate::error::Error::{self, *};
use crate::session::{
    chain_ratchet::ChainRatchet, public_ratchet::PublicRatchet, skipped_keys::SkippedKeys,
};

/// Session state during normal use.
///
/// Messages that are dropped or received out of order will cause ratchets to advance to
/// the highest seen nonce (within reasonable limits). Skipped message keys will be stored
/// until their messages arrive.
pub struct NormalState {
    public: PublicRatchet,
    send: ChainRatchet,
    receive: ChainRatchet,
    previous_send_nonce: Nonce,
    skipped_keys: SkippedKeys,
    associated_data_service: AssociatedDataService,
}

impl NormalState {
    pub fn new(
        public: PublicRatchet,
        send: ChainRatchet,
        receive: ChainRatchet,
        previous_send_nonce: Nonce,
        skipped_keys: SkippedKeys,
        associated_data_service: AssociatedDataService,
    ) -> NormalState {
        NormalState {
            public,
            send,
            receive,
            previous_send_nonce,
            skipped_keys,
            associated_data_service,
        }
    }

    pub fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (nonce, message_key) = self.send.ratchet();
        let encrypted_header = self.send.header_key.encrypt(Header {
            public_key: self.public.send_public_key.clone(),
            previous_nonce: self.previous_send_nonce,
            nonce,
        });
        let associated_data = self.associated_data_service.create(encrypted_header, nonce);
        message_key.encrypt(plaintext, associated_data)
    }

    pub fn ratchet_decrypt(&mut self, message: Message) -> Result<Plaintext, Error> {
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
                    return Err(MissingHeaderKey);
                };

                self.skipped_keys.skip_to_nonce(&mut self.receive, nonce)?;
                self.receive.ratchet()
            }
        };
        let associated_data = self
            .associated_data_service
            .create(message.encrypted_header, nonce);
        message_key.decrypt(message.ciphertext, associated_data)
    }

    fn ratchet(&mut self, receive_public_key: PublicKey) -> Result<(), Error> {
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
