use std::collections;

use crate::crypto::{EncryptedHeader, HeaderKey, MessageKey, Nonce};
use crate::ratchet::ChainRatchet;

/// Store message keys indexed by a header key and nonce.
///
/// For a given ChainRatchet, the header key stays constant while the nonce increments.
/// We collect all message keys between the current nonce and the target nonce, ratcheting
/// the ChainRatchet forward unless it requires more than MAX_SKIP ratchets (to prevent abuse).
///
/// As message headers are encrypted, the only way to check whether a matching message key exists
/// is to try all header keys until one successfully decrypts.
pub struct SkippedKeys(collections::HashMap<HeaderKey, collections::HashMap<Nonce, MessageKey>>);

impl SkippedKeys {
    const MAX_SKIP: u8 = 100;

    pub fn new() -> SkippedKeys {
        SkippedKeys(collections::HashMap::new())
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
            || &receive.nonce + &Nonce::new(SkippedKeys::MAX_SKIP) < nonce
        {
            return Err(());
        }
        let message_keys = self.0.entry(receive.header_key.clone()).or_default();
        while receive.nonce < nonce {
            let (nonce, message_key) = receive.ratchet();
            message_keys.insert(nonce, message_key);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ChainKey, Header, HeaderKey, SecretKey};
    use crate::ratchet::ChainRatchet;

    #[test]
    fn skipped_keys_decrypt_header_less() {
        let test_nonce = Nonce::new(5);
        let target_nonce = Nonce::new(4);

        let header_key = HeaderKey::generate();
        let encrypted_header = header_key.encrypt(Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(144),
            nonce: test_nonce,
        });
        let mut receive =
            ChainRatchet::new(ChainKey::generate(), header_key, HeaderKey::generate());
        let mut skipped_keys = SkippedKeys::new();
        skipped_keys
            .skip_to_nonce(&mut receive, target_nonce)
            .expect("Failed to skip to target nonce");

        assert!(skipped_keys.try_decrypt_header(&encrypted_header).is_none());
    }

    #[test]
    fn skipped_keys_decrypt_header_equal() {
        let test_nonce = Nonce::new(5);
        let target_nonce = Nonce::new(5);

        let header_key = HeaderKey::generate();
        let encrypted_header = header_key.encrypt(Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(144),
            nonce: test_nonce,
        });
        let mut receive =
            ChainRatchet::new(ChainKey::generate(), header_key, HeaderKey::generate());
        let mut skipped_keys = SkippedKeys::new();
        skipped_keys
            .skip_to_nonce(&mut receive, target_nonce)
            .expect("Failed to skip to target nonce");

        assert!(skipped_keys.try_decrypt_header(&encrypted_header).is_none());
    }

    #[test]
    fn skipped_keys_decrypt_header_greater() {
        let test_nonce = Nonce::new(5);
        let target_nonce = Nonce::new(6);

        let header_key = HeaderKey::generate();
        let encrypted_header = header_key.encrypt(Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(144),
            nonce: test_nonce,
        });
        let mut receive =
            ChainRatchet::new(ChainKey::generate(), header_key, HeaderKey::generate());
        let mut skipped_keys = SkippedKeys::new();
        skipped_keys
            .skip_to_nonce(&mut receive, target_nonce)
            .expect("Failed to skip to target nonce");

        let option_header = skipped_keys.try_decrypt_header(&encrypted_header);
        assert!(option_header.is_some());
        assert!(test_nonce == option_header.unwrap().0);
    }

    #[test]
    fn skipped_keys_decrypt_header_repeat() {
        let test_nonce = Nonce::new(5);
        let target_nonce = Nonce::new(6);

        let header_key = HeaderKey::generate();
        let encrypted_header = header_key.encrypt(Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(144),
            nonce: test_nonce,
        });
        let mut receive =
            ChainRatchet::new(ChainKey::generate(), header_key, HeaderKey::generate());
        let mut skipped_keys = SkippedKeys::new();
        skipped_keys
            .skip_to_nonce(&mut receive, target_nonce)
            .expect("Failed to skip to target nonce");

        skipped_keys.try_decrypt_header(&encrypted_header);
        assert!(skipped_keys.try_decrypt_header(&encrypted_header).is_none());
    }

    #[test]
    fn skipped_keys_decrypt_header_unrelated() {
        let test_nonce = Nonce::new(5);
        let target_nonce = Nonce::new(6);

        let encrypted_header = HeaderKey::generate().encrypt(Header {
            public_key: SecretKey::generate_pair().0,
            previous_nonce: Nonce::new(144),
            nonce: test_nonce,
        });
        let mut receive = ChainRatchet::new(
            ChainKey::generate(),
            HeaderKey::generate(),
            HeaderKey::generate(),
        );
        let mut skipped_keys = SkippedKeys::new();
        skipped_keys
            .skip_to_nonce(&mut receive, target_nonce)
            .expect("Failed to skip to target nonce");

        assert!(skipped_keys.try_decrypt_header(&encrypted_header).is_none());
    }

    #[test]
    fn skipped_keys_skip_to_nonce_less() {
        let test_nonce = Nonce::new(5);
        let target_nonce = Nonce::new(6);

        let mut receive = ChainRatchet::new(
            ChainKey::generate(),
            HeaderKey::generate(),
            HeaderKey::generate(),
        );
        let mut skipped_keys = SkippedKeys::new();
        skipped_keys
            .skip_to_nonce(&mut receive, target_nonce)
            .expect("Failed to skip to target nonce");

        assert!(skipped_keys
            .skip_to_nonce(&mut receive, test_nonce)
            .is_err());
    }

    #[test]
    fn skipped_keys_skip_to_nonce_equal() {
        let test_nonce = Nonce::new(5);
        let target_nonce = Nonce::new(5);

        let mut receive = ChainRatchet::new(
            ChainKey::generate(),
            HeaderKey::generate(),
            HeaderKey::generate(),
        );
        let mut skipped_keys = SkippedKeys::new();
        skipped_keys
            .skip_to_nonce(&mut receive, target_nonce)
            .expect("Failed to skip to target nonce");

        assert!(skipped_keys.skip_to_nonce(&mut receive, test_nonce).is_ok());
    }

    #[test]
    fn skipped_keys_skip_to_nonce_greater() {
        let test_nonce = Nonce::new(5);
        let target_nonce = Nonce::new(4);

        let mut receive = ChainRatchet::new(
            ChainKey::generate(),
            HeaderKey::generate(),
            HeaderKey::generate(),
        );
        let mut skipped_keys = SkippedKeys::new();
        skipped_keys
            .skip_to_nonce(&mut receive, target_nonce)
            .expect("Failed to skip to target nonce");

        assert!(skipped_keys.skip_to_nonce(&mut receive, test_nonce).is_ok());
    }

    #[test]
    fn skipped_keys_skip_to_nonce_way_greater() {
        let test_nonce = &Nonce::new(255) + &Nonce::new(255);
        let target_nonce = Nonce::new(5);

        let mut receive = ChainRatchet::new(
            ChainKey::generate(),
            HeaderKey::generate(),
            HeaderKey::generate(),
        );
        let mut skipped_keys = SkippedKeys::new();
        skipped_keys
            .skip_to_nonce(&mut receive, target_nonce)
            .expect("Failed to skip to target nonce");

        assert!(skipped_keys
            .skip_to_nonce(&mut receive, test_nonce)
            .is_err());
    }
}
