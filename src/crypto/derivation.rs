use sodiumoxide::crypto::{generichash, kdf};

use crate::crypto::{agreement::SessionKey, header::HeaderKey, message::MessageKey, UserState};

pub struct ChainKey(kdf::Key);

impl ChainKey {
    pub const CONTEXT: [u8; 8] = *b"chainkdf";
    pub const CHAIN_ID: u64 = 1;
    pub const MESSAGE_ID: u64 = 2;

    fn derive_from_chain(prev_chain_key: &ChainKey) -> ChainKey {
        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        prev_chain_key.derive(&mut chain_key.0, ChainKey::CHAIN_ID);
        ChainKey(chain_key)
    }

    fn derive_from_root(root_key: &RootKey) -> ChainKey {
        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        root_key.derive(&mut chain_key.0, RootKey::CHAIN_ID);
        ChainKey(chain_key)
    }

    pub(crate) fn invalid() -> ChainKey {
        ChainKey(kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap())
    }

    #[cfg(test)]
    pub(crate) fn generate() -> ChainKey {
        ChainKey(kdf::gen_key())
    }

    pub fn derive_keys(&self) -> (ChainKey, MessageKey) {
        let chain_key = ChainKey::derive_from_chain(self);
        let message_key = MessageKey::derive_from_chain(self);

        (chain_key, message_key)
    }

    pub(in crate::crypto) fn derive(&self, mut key_slice: &mut [u8], id: u64) {
        kdf::derive_from_key(&mut key_slice, id, ChainKey::CONTEXT, &self.0).unwrap();
    }
}

#[derive(Clone)]
pub struct RootKey(kdf::Key);

impl RootKey {
    pub const CONTEXT: [u8; 8] = *b"rootkdf_";
    pub const ROOT_ID: u64 = 1;
    pub const CHAIN_ID: u64 = 2;
    pub const INITIATOR_HEADER_ID: u64 = 3;
    pub const RESPONDER_HEADER_ID: u64 = 4;

    pub fn derive_from_sessions(
        key_0: SessionKey,
        key_1: SessionKey,
        key_2: SessionKey,
    ) -> RootKey {
        let mut state = generichash::State::new(kdf::KEYBYTES, None).unwrap();
        state.update(&(key_0.0).0).unwrap();
        state.update(&(key_1.0).0).unwrap();
        state.update(&(key_2.0).0).unwrap();
        let digest = state.finalize().unwrap();

        RootKey(kdf::Key::from_slice(&digest[..]).unwrap())
    }

    fn derive_from_root(prev_root_key: &RootKey) -> RootKey {
        let mut root_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        prev_root_key.derive(&mut root_key.0, RootKey::ROOT_ID);
        RootKey(root_key)
    }

    #[cfg(test)]
    pub(crate) fn generate() -> RootKey {
        RootKey(kdf::gen_key())
    }

    pub fn derive_header_keys(&self) -> (RootKey, HeaderKey, HeaderKey) {
        let root_key = RootKey::derive_from_root(&self);
        let initiator_header_key = HeaderKey::derive_from_root(&self, UserState::Initiator);
        let responder_header_key = HeaderKey::derive_from_root(&self, UserState::Responder);

        (root_key, initiator_header_key, responder_header_key)
    }

    pub fn derive_keys(&self, session_key: SessionKey) -> (RootKey, ChainKey, HeaderKey) {
        let mut state = generichash::State::new(kdf::KEYBYTES, Some(&(self.0).0)).unwrap();
        state.update(&(session_key.0).0).unwrap();
        let root = RootKey(kdf::Key::from_slice(&state.finalize().unwrap()[..]).unwrap());

        let root_key = RootKey::derive_from_root(&root);
        let chain_key = ChainKey::derive_from_root(&root);
        // Since the root key gets updated it doesn't matter whether we use the initiator or
        // responder header key. Successive calls will give distinct keys.
        let header_key = HeaderKey::derive_from_root(&root, UserState::Initiator);

        (root_key, chain_key, header_key)
    }

    pub(in crate::crypto) fn derive(&self, mut key_slice: &mut [u8], id: u64) {
        kdf::derive_from_key(&mut key_slice, id, RootKey::CONTEXT, &self.0).unwrap();
    }
}
