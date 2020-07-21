use crate::crypto::{ChainKey, HeaderKey, MessageKey, Nonce, PublicKey, RootKey, SecretKey};

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
    ) -> (ChainRatchet, Nonce) {
        let previous_send_nonce = send.nonce;
        let receive = self.advance(receive_public_key.clone(), receive_next_header_key);
        let (send_public_key, send_secret_key) = SecretKey::generate_pair();
        self.send_public_key = send_public_key;
        self.send_secret_key = send_secret_key;
        *send = self.advance(receive_public_key, send.next_header_key.clone());

        (receive, previous_send_nonce)
    }

    pub fn advance(
        &mut self,
        receive_public_key: PublicKey,
        header_key: HeaderKey,
    ) -> ChainRatchet {
        let session_key = self.send_secret_key.key_exchange(receive_public_key);
        let (root_key, chain_key, next_header_key) = self.root_key.key_derivation(session_key);
        self.root_key = root_key;

        ChainRatchet::new(chain_key, header_key, next_header_key)
    }
}

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
            nonce: Nonce::new_zero(),
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

        let message_key = MessageKey::derive_from(&self.chain_key);
        self.chain_key = ChainKey::derive_from_chain(&self.chain_key);

        (nonce, message_key)
    }
}
