use sodiumoxide::crypto::{generichash, kdf};

use crate::crypto::{agreement::SessionKey, header::HeaderKey, message::MessageKey};

pub struct ChainKey(kdf::Key);

impl ChainKey {
    const CONTEXT: [u8; 8] = *b"chainkdf";

    fn derive_from_chain(prev_chain_key: &ChainKey) -> ChainKey {
        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        prev_chain_key.derive_into_slice(&mut chain_key.0, ChainSubkeyId::Chain);
        ChainKey(chain_key)
    }

    fn derive_from_root(root_key: &RootKey) -> ChainKey {
        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        root_key.derive_into_slice(&mut chain_key.0, RootSubkeyId::Chain);
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

    pub(in crate::crypto) fn derive_into_slice(&self, mut key_slice: &mut [u8], id: ChainSubkeyId) {
        kdf::derive_from_key(&mut key_slice, id as u64, ChainKey::CONTEXT, &self.0).unwrap();
    }
}

#[derive(Clone)]
pub struct RootKey(kdf::Key);

impl RootKey {
    const CONTEXT: [u8; 8] = *b"rootkdf_";

    pub fn derive_from_sessions(
        key_0: SessionKey,
        key_1: SessionKey,
        key_2: SessionKey,
    ) -> RootKey {
        let mut state = generichash::State::new(kdf::KEYBYTES, None).unwrap();
        state.update(key_0.as_slice()).unwrap();
        state.update(key_1.as_slice()).unwrap();
        state.update(key_2.as_slice()).unwrap();
        let digest = state.finalize().unwrap();

        RootKey(kdf::Key::from_slice(&digest[..]).unwrap())
    }

    fn derive_from_root(prev_root_key: &RootKey) -> RootKey {
        let mut root_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        prev_root_key.derive_into_slice(&mut root_key.0, RootSubkeyId::Root);
        RootKey(root_key)
    }

    #[cfg(test)]
    pub(crate) fn generate() -> RootKey {
        RootKey(kdf::gen_key())
    }

    pub fn derive_header_keys(&self) -> (RootKey, HeaderKey, HeaderKey) {
        let root_key = RootKey::derive_from_root(&self);
        let initiator_header_key =
            HeaderKey::derive_from_root(&self, RootSubkeyId::InitiatorHeader);
        let responder_header_key =
            HeaderKey::derive_from_root(&self, RootSubkeyId::ResponderHeader);

        (root_key, initiator_header_key, responder_header_key)
    }

    pub fn derive_keys(&self, session_key: SessionKey) -> (RootKey, ChainKey, HeaderKey) {
        let mut state = generichash::State::new(kdf::KEYBYTES, Some(&(self.0).0)).unwrap();
        state.update(session_key.as_slice()).unwrap();
        let root = RootKey(kdf::Key::from_slice(&state.finalize().unwrap()[..]).unwrap());

        let root_key = RootKey::derive_from_root(&root);
        let chain_key = ChainKey::derive_from_root(&root);
        // Since the root key gets updated it doesn't matter whether we use the initiator or
        // responder header key. Successive calls will give distinct keys.
        let header_key = HeaderKey::derive_from_root(&root, RootSubkeyId::InitiatorHeader);

        (root_key, chain_key, header_key)
    }

    pub(in crate::crypto) fn derive_into_slice(&self, mut key_slice: &mut [u8], id: RootSubkeyId) {
        kdf::derive_from_key(&mut key_slice, id as u64, RootKey::CONTEXT, &self.0).unwrap();
    }
}

pub enum ChainSubkeyId {
    Chain,
    Message,
}

pub enum RootSubkeyId {
    Root,
    Chain,
    InitiatorHeader,
    ResponderHeader,
}
