use crate::crypto::{ChainKey, HeaderKey, MessageKey, Nonce};

/// Ratchet a chain key every time a message is sent or received
///
/// Ratcheting gives a symmetric (nonce, message key) pair that can be used to either encrypt
/// or decrypt messages.
pub struct ChainRatchet {
    chain_key: ChainKey,
    pub nonce: Nonce,
    pub header_key: HeaderKey,
    pub next_header_key: HeaderKey,
}

impl ChainRatchet {
    pub fn new(
        chain_key: ChainKey,
        header_key: HeaderKey,
        next_header_key: HeaderKey,
    ) -> ChainRatchet {
        ChainRatchet {
            chain_key,
            nonce: Nonce::new(0),
            header_key,
            next_header_key,
        }
    }

    pub(crate) fn invalid(next_header_key: HeaderKey) -> ChainRatchet {
        ChainRatchet::new(ChainKey::invalid(), HeaderKey::invalid(), next_header_key)
    }

    pub fn ratchet(&mut self) -> (Nonce, MessageKey) {
        let nonce = self.nonce;
        self.nonce.increment();

        let (chain_key, message_key) = self.chain_key.derive_keys();
        self.chain_key = chain_key;

        (nonce, message_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HeaderKey;

    #[test]
    fn chain_ratchet_ratchet() {
        let mut chain = ChainRatchet::new(
            ChainKey::generate(),
            HeaderKey::generate(),
            HeaderKey::generate(),
        );

        let (nonce, message_key_0) = chain.ratchet();
        assert!(nonce == Nonce::new(0));
        let (nonce, message_key_1) = chain.ratchet();
        assert!(nonce == Nonce::new(1));
        let (nonce, message_key_2) = chain.ratchet();
        assert!(nonce == Nonce::new(2));
        assert!(message_key_0 != message_key_1);
        assert!(message_key_0 != message_key_2);
        assert!(message_key_1 != message_key_2);
    }
}
