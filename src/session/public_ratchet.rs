use crate::crypto::{HeaderKey, PublicKey, RootKey, SecretKey};
use crate::error::Error;
use crate::session::chain_ratchet::ChainRatchet;

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
        receive_public_key: PublicKey,
        send_next_header_key: HeaderKey,
        receive_next_header_key: HeaderKey,
    ) -> Result<(ChainRatchet, ChainRatchet), Error> {
        let receive = self.advance(receive_public_key.clone(), receive_next_header_key)?;
        let (send_public_key, send_secret_key) = SecretKey::generate_pair();
        self.send_public_key = send_public_key;
        self.send_secret_key = send_secret_key;
        let send = self.advance(receive_public_key, send_next_header_key)?;

        Ok((send, receive))
    }

    pub fn advance(
        &mut self,
        receive_public_key: PublicKey,
        header_key: HeaderKey,
    ) -> Result<ChainRatchet, Error> {
        let shared_secret = self.send_secret_key.key_exchange(&receive_public_key)?;
        let (root_key, chain_key, next_header_key) = self.root_key.derive_keys(shared_secret);
        self.root_key = root_key;

        Ok(ChainRatchet::new(chain_key, header_key, next_header_key))
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

        let mut alice_public =
            PublicRatchet::new(alice_public_key.clone(), alice_secret_key, root_key.clone());
        let mut bob_public = PublicRatchet::new(bob_public_key.clone(), bob_secret_key, root_key);

        let mut alice_chain = alice_public
            .advance(bob_public_key.clone(), header_key.clone())
            .expect("Failed to advance alice's public ratchet");
        let mut bob_chain = bob_public
            .advance(alice_public_key.clone(), header_key.clone())
            .expect("Failed to advance bob's public ratchet");

        let (alice_nonce, alice_message_key) = alice_chain.ratchet();
        let (bob_nonce, bob_message_key) = bob_chain.ratchet();

        assert!(alice_public_key == alice_public.send_public_key);
        assert!(bob_public_key == bob_public.send_public_key);
        assert!(header_key == alice_chain.header_key);
        assert!(header_key == bob_chain.header_key);
        assert!(alice_chain.next_header_key == bob_chain.next_header_key);
        assert!(alice_nonce == bob_nonce);
        assert!(alice_message_key == bob_message_key);
    }

    #[test]
    fn public_ratchet_advance_invalid_public_key() {
        let (alice_public_key, alice_secret_key) = SecretKey::generate_pair();
        let eve_public_key = PublicKey::invalid();

        let mut alice_public =
            PublicRatchet::new(alice_public_key, alice_secret_key, RootKey::generate());

        assert!(alice_public
            .advance(eve_public_key, HeaderKey::generate())
            .is_err());
    }

    #[test]
    fn public_ratchet_ratchet() {
        let (alice_public_key, alice_secret_key) = SecretKey::generate_pair();
        let (bob_public_key, bob_secret_key) = SecretKey::generate_pair();
        let root_key = RootKey::generate();
        let header_key = HeaderKey::generate();

        let mut alice_public =
            PublicRatchet::new(alice_public_key.clone(), alice_secret_key, root_key.clone());
        let mut alice_send = alice_public
            .advance(bob_public_key.clone(), header_key.clone())
            .expect("Failed to advance alice's public ratchet");

        let mut bob_public = PublicRatchet::new(bob_public_key.clone(), bob_secret_key, root_key);
        let (_bob_send, mut bob_receive) = bob_public
            .ratchet(
                alice_public_key.clone(),
                HeaderKey::invalid(),
                header_key.clone(),
            )
            .expect("Failed to ratchet bob's public ratchet");

        let (alice_nonce, alice_message_key) = alice_send.ratchet();
        let (bob_nonce, bob_message_key) = bob_receive.ratchet();

        assert!(alice_public_key == alice_public.send_public_key);
        assert!(bob_public_key != bob_public.send_public_key); // After ratcheting bob's key changes
        assert!(header_key == alice_send.header_key);
        assert!(header_key == bob_receive.header_key);
        assert!(alice_send.next_header_key == bob_receive.next_header_key);
        assert!(alice_nonce == bob_nonce);
        assert!(alice_message_key == bob_message_key);
    }

    #[test]
    fn public_ratchet_ratchet_invalid_public_key() {
        let (alice_public_key, alice_secret_key) = SecretKey::generate_pair();
        let eve_public_key = PublicKey::invalid();

        let mut alice_public =
            PublicRatchet::new(alice_public_key, alice_secret_key, RootKey::generate());

        assert!(alice_public
            .ratchet(eve_public_key, HeaderKey::generate(), HeaderKey::generate())
            .is_err());
    }
}
