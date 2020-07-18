use std::{collections, slice};

use crate::crypto::{EncryptedHeader, HeaderKey, MessageKey, Nonce};
use crate::ratchet::ChainRatchet;

pub struct SkippedMessageKeys(Vec<(HeaderKey, collections::HashMap<Nonce, MessageKey>)>);

impl SkippedMessageKeys {
    // TODO const MAX_SKIP: usize = 256;

    pub fn new() -> SkippedMessageKeys {
        SkippedMessageKeys(Vec::new())
    }

    pub fn decrypt_header(
        &mut self,
        encrypted_header: &EncryptedHeader,
    ) -> Option<(Nonce, MessageKey)> {
        for (header_key, message_keys) in self.iter_mut() {
            if let Ok(header) = header_key.decrypt(encrypted_header) {
                let message_key = message_keys.remove(&header.nonce)?;
                return Some((header.nonce, message_key));
            }
        }
        None
    }

    pub fn skip(&mut self, receive: &mut ChainRatchet, nonce: Nonce) {
        // TODO error handle MAX_SKIP to protect against denial of service
        // TODO garbage collect empty (skipped_header_key, message_keys) elements
        let message_keys = match self
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
    }

    fn iter_mut(&mut self) -> slice::IterMut<(HeaderKey, collections::HashMap<Nonce, MessageKey>)> {
        self.0.iter_mut()
    }
}
