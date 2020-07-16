use sodiumoxide::crypto::{generichash, kdf, kx, scalarmult};

use crate::crypto::{ChainKey, HeaderKey, MessageKey, Nonce};

pub struct PublicRatchet {
    send_keypair: (kx::PublicKey, kx::SecretKey),
    root_ratchet: RootRatchet,
}

impl PublicRatchet {
    pub fn new(send_keypair: (kx::PublicKey, kx::SecretKey), root_key: kdf::Key) -> PublicRatchet {
        PublicRatchet {
            send_keypair,
            root_ratchet: RootRatchet::new(root_key),
        }
    }

    pub fn advance(
        &mut self,
        receive_public_key: kx::PublicKey,
        header_key: HeaderKey,
    ) -> ChainRatchet {
        let session_key = self.key_exchange(receive_public_key);
        let (chain_key, next_header_key) = self.root_ratchet.advance(session_key);

        ChainRatchet::new(chain_key, header_key, next_header_key)
    }

    pub fn ratchet(
        &mut self,
        send_ratchet: &mut ChainRatchet,
        receive_next_header_key: HeaderKey,
        receive_public_key: kx::PublicKey,
    ) -> (ChainRatchet, Nonce) {
        let previous_send_nonce = send_ratchet.nonce;
        let receive_ratchet = self.advance(receive_public_key, receive_next_header_key);
        self.send_keypair = kx::gen_keypair();
        *send_ratchet = self.advance(receive_public_key, send_ratchet.next_header_key());

        (receive_ratchet, previous_send_nonce)
    }

    pub fn send_public_key(&self) -> kx::PublicKey {
        self.send_keypair.0
    }

    fn key_exchange(&self, receive_public_key: kx::PublicKey) -> kx::SessionKey {
        let send_secret_scalar = scalarmult::Scalar::from_slice(&(self.send_keypair.1).0).unwrap();
        let receive_public_group_element =
            scalarmult::GroupElement::from_slice(&receive_public_key.0).unwrap();
        let shared_secret =
            scalarmult::scalarmult(&send_secret_scalar, &receive_public_group_element).unwrap();

        kx::SessionKey::from_slice(&shared_secret.0).unwrap()
    }
}

pub struct RootRatchet {
    root_key: kdf::Key,
}

impl RootRatchet {
    fn new(root_key: kdf::Key) -> RootRatchet {
        RootRatchet { root_key }
    }

    fn advance(&mut self, session_key: kx::SessionKey) -> (ChainKey, HeaderKey) {
        let (root_key, chain_key, header_key) = self.key_derivation(session_key);

        self.root_key = root_key;
        (chain_key, header_key)
    }

    fn key_derivation(&self, session_key: kx::SessionKey) -> (kdf::Key, ChainKey, HeaderKey) {
        const CONTEXT: [u8; 8] = *b"rootkdf_";

        let mut state = generichash::State::new(kdf::KEYBYTES, Some(&self.root_key.0)).unwrap();
        state.update(&session_key.0).unwrap();
        let digest = kdf::Key::from_slice(&state.finalize().unwrap()[..]).unwrap();

        let mut root_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut root_key.0, 1, CONTEXT, &digest).unwrap();

        let chain_key = ChainKey::derive_from_digest(&digest);

        let header_key = HeaderKey::derive_from(&digest);

        (root_key, chain_key, header_key)
    }
}

pub struct ChainRatchet {
    chain_key: ChainKey,
    nonce: Nonce,
    header_key: HeaderKey,
    next_header_key: HeaderKey,
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

    pub fn advance(&mut self) -> (Nonce, MessageKey) {
        let nonce = self.nonce;
        self.nonce.increment();

        let (chain_key, message_key) = self.key_derivation();
        self.chain_key = chain_key;

        (nonce, message_key)
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn header_key(&self) -> HeaderKey {
        self.header_key.clone()
    }

    pub fn next_header_key(&self) -> HeaderKey {
        self.next_header_key.clone()
    }

    fn key_derivation(&self) -> (ChainKey, MessageKey) {
        let chain_key = ChainKey::derive_from_chain(&self.chain_key);
        let message_key = MessageKey::derive_from(&self.chain_key);

        (chain_key, message_key)
    }
}
