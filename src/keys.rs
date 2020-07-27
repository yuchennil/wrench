use std::collections;

use crate::crypto::{EncryptedHeader, HeaderKey, MessageKey, Nonce};
use crate::ratchet::ChainRatchet;

pub struct SkippedMessageKeys(Vec<(HeaderKey, collections::HashMap<Nonce, MessageKey>)>);

impl SkippedMessageKeys {
    const MAX_SKIP: u8 = 100;

    pub fn new() -> SkippedMessageKeys {
        SkippedMessageKeys(Vec::new())
    }

    pub fn try_decrypt_header(
        &mut self,
        encrypted_header: &EncryptedHeader,
    ) -> Option<(Nonce, MessageKey)> {
        for (header_key, message_keys) in self.0.iter_mut() {
            if let Ok(header) = header_key.decrypt(encrypted_header) {
                let message_key = message_keys.remove(&header.nonce)?;
                // TODO garbage collect empty (header_key, message_keys) pairs
                return Some((header.nonce, message_key));
            }
        }
        None
    }

    pub fn skip_to_nonce(&mut self, receive: &mut ChainRatchet, nonce: Nonce) -> Result<(), ()> {
        if receive.nonce == nonce {
            return Ok(());
        } else if receive.nonce > nonce
            || &receive.nonce + &Nonce::new(SkippedMessageKeys::MAX_SKIP) < nonce
        {
            return Err(());
        }
        let message_keys = match self
            .0
            .iter_mut()
            .find(|(skipped_header_key, _)| receive.header_key == *skipped_header_key)
        {
            Some((_, message_keys)) => message_keys,
            None => {
                self.0
                    .push((receive.header_key.clone(), collections::HashMap::new()));
                &mut self.0.last_mut().unwrap().1
            }
        };
        while receive.nonce < nonce {
            let (nonce, message_key) = receive.ratchet();
            message_keys.insert(nonce, message_key);
        }
        Ok(())
    }
}
