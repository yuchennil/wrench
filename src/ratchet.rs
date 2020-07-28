use crate::crypto::{ChainKey, HeaderKey, MessageKey, Nonce, PublicKey, RootKey, SecretKey};

/// Ratchet both send and receive chain keys every time a message is received.
///
/// Every received message is accompanied by a public key (that should get refreshed via
/// the sender's own ratchet). For each ratchet we perform a key exchange to derive the
/// receive chain key, then generate a new send public keypair to derive the send chain key
/// for any future outbound messages.
pub struct PublicRatchet {
    pub send_public_key: PublicKey,
    send_secret_key: SecretKey,
    root_key: RootKey,
}

impl PublicRatchet {
    pub fn new(
        send_public_key: PublicKey,
        send_secret_key: SecretKey,
        root_key: RootKey,
    ) -> PublicRatchet {
        PublicRatchet {
            send_public_key,
            send_secret_key,
            root_key,
        }
    }

    pub fn ratchet(
        &mut self,
        send: &mut ChainRatchet,
        receive_next_header_key: HeaderKey,
        receive_public_key: PublicKey,
    ) -> Result<(ChainRatchet, Nonce), ()> {
        let previous_send_nonce = send.nonce;
        let receive = self.advance(receive_public_key.clone(), receive_next_header_key)?;
        let (send_public_key, send_secret_key) = SecretKey::generate_pair();
        self.send_public_key = send_public_key;
        self.send_secret_key = send_secret_key;
        *send = self.advance(receive_public_key, send.next_header_key.clone())?;

        Ok((receive, previous_send_nonce))
    }

    pub fn advance(
        &mut self,
        receive_public_key: PublicKey,
        header_key: HeaderKey,
    ) -> Result<ChainRatchet, ()> {
        let session_key = self.send_secret_key.key_exchange(&receive_public_key)?;
        let (root_key, chain_key, next_header_key) = self.root_key.derive_keys(session_key);
        self.root_key = root_key;

        Ok(ChainRatchet::new(chain_key, header_key, next_header_key))
    }
}

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
    use crate::crypto::{HeaderKey, SecretKey};

    #[test]
    fn public_ratchet_advance() {
        let (alice_public_key, alice_secret_key) = SecretKey::generate_pair();
        let (bob_public_key, bob_secret_key) = SecretKey::generate_pair();
        let root_key = RootKey::generate();
        let header_key = HeaderKey::generate();

        let mut alice_public_ratchet =
            PublicRatchet::new(alice_public_key.clone(), alice_secret_key, root_key.clone());
        let mut bob_public_ratchet =
            PublicRatchet::new(bob_public_key.clone(), bob_secret_key, root_key);

        let mut alice_chain_ratchet = alice_public_ratchet
            .advance(bob_public_key, header_key.clone())
            .expect("Failed to advance alice's public ratchet");
        let mut bob_chain_ratchet = bob_public_ratchet
            .advance(alice_public_key, header_key.clone())
            .expect("Failed to advance bob's public ratchet");

        let (alice_nonce, _alice_message_key) = alice_chain_ratchet.ratchet();
        let (bob_nonce, _bob_message_key) = bob_chain_ratchet.ratchet();

        assert!(header_key == alice_chain_ratchet.header_key);
        assert!(header_key == bob_chain_ratchet.header_key);
        assert!(alice_chain_ratchet.next_header_key == bob_chain_ratchet.next_header_key);
        assert!(alice_nonce == bob_nonce);
        // TODO check message keys are identical without opening up API
        // assert!(alice_message_key == bob_message_key);
    }

    #[test]
    fn public_ratchet_advance_invalid_public_key() {
        let (alice_public_key, alice_secret_key) = SecretKey::generate_pair();
        let eve_public_key = PublicKey::invalid();

        let mut alice_public_ratchet =
            PublicRatchet::new(alice_public_key, alice_secret_key, RootKey::generate());

        assert!(alice_public_ratchet
            .advance(eve_public_key, HeaderKey::generate())
            .is_err());
    }
}
