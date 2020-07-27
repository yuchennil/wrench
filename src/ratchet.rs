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
        let (root_key, chain_key, next_header_key) = self.root_key.derive_keys(session_key)?;
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

    pub fn new_burner(next_header_key: HeaderKey) -> ChainRatchet {
        ChainRatchet::new(ChainKey::generate(), HeaderKey::generate(), next_header_key)
    }

    pub fn ratchet(&mut self) -> (Nonce, MessageKey) {
        let nonce = self.nonce;
        self.nonce.increment();

        let (chain_key, message_key) = self.chain_key.derive_keys();
        self.chain_key = chain_key;

        (nonce, message_key)
    }
}
