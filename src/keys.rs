use std::collections;

use crate::crypto::{EncryptedHeader, HeaderKey, MessageKey, Nonce};
use crate::ratchet::ChainRatchet;

pub struct SkippedMessageKeys(
    collections::HashMap<HeaderKey, collections::HashMap<Nonce, MessageKey>>,
);

impl SkippedMessageKeys {
    const MAX_SKIP: u8 = 100;

    pub fn new() -> SkippedMessageKeys {
        SkippedMessageKeys(collections::HashMap::new())
    }

    pub fn try_decrypt_header(
        &mut self,
        encrypted_header: &EncryptedHeader,
    ) -> Option<(Nonce, MessageKey)> {
        let mut decrypted_bundle = None;
        for (header_key, message_keys) in &mut self.0 {
            if let Ok(header) = header_key.decrypt(encrypted_header) {
                decrypted_bundle = Some((header_key.clone(), message_keys, header));
                break;
            }
        }
        let (header_key, message_keys, header) = decrypted_bundle?;
        let message_key = message_keys.remove(&header.nonce)?;
        if message_keys.is_empty() {
            self.0.remove(&header_key);
        }
        Some((header.nonce, message_key))
    }

    pub fn skip_to_nonce(&mut self, receive: &mut ChainRatchet, nonce: Nonce) -> Result<(), ()> {
        if receive.nonce == nonce {
            return Ok(());
        } else if receive.nonce > nonce
            || &receive.nonce + &Nonce::new(SkippedMessageKeys::MAX_SKIP) < nonce
        {
            return Err(());
        }
        let message_keys = self
            .0
            .entry(receive.header_key.clone())
            .or_insert(collections::HashMap::new());
        while receive.nonce < nonce {
            let (nonce, message_key) = receive.ratchet();
            message_keys.insert(nonce, message_key);
        }
        Ok(())
    }
}
