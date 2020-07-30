use sodiumoxide::crypto::{generichash, kdf};

use crate::crypto::{agreement::SessionKey, header::HeaderKey, message::MessageKey};

pub struct ChainKey(pub kdf::Key);

impl ChainKey {
    pub const CONTEXT: [u8; 8] = *b"chainkdf";
    pub const CHAIN_ID: u64 = 1;
    pub const MESSAGE_ID: u64 = 2;

    pub(in crate::crypto) fn derive_from_chain(prev_chain_key: &ChainKey) -> ChainKey {
        let (id, context) = (ChainKey::CHAIN_ID, ChainKey::CONTEXT);

        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut chain_key.0, id, context, &prev_chain_key.0).unwrap();
        ChainKey(chain_key)
    }

    pub(in crate::crypto) fn derive_from_digest(digest: &kdf::Key) -> ChainKey {
        let (id, context) = (RootKey::CHAIN_ID, RootKey::CONTEXT);

        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut chain_key.0, id, context, &digest).unwrap();
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
}

#[derive(Clone, Eq, PartialEq)]
pub struct RootKey(kdf::Key);

impl RootKey {
    pub const CONTEXT: [u8; 8] = *b"rootkdf_";
    pub const ROOT_ID: u64 = 1;
    pub const CHAIN_ID: u64 = 2;
    pub const HEADER_ID: u64 = 3;

    pub(in crate::crypto) fn derive_from_digest(digest: &kdf::Key) -> RootKey {
        let (id, context) = (RootKey::ROOT_ID, RootKey::CONTEXT);

        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut chain_key.0, id, context, &digest).unwrap();
        RootKey(chain_key)
    }

    #[cfg(test)]
    pub(crate) fn generate() -> RootKey {
        RootKey(kdf::gen_key())
    }

    pub fn derive_keys(&self, session_key: SessionKey) -> (RootKey, ChainKey, HeaderKey) {
        let mut state = generichash::State::new(kdf::KEYBYTES, Some(&(self.0).0)).unwrap();
        state.update(&(session_key.0).0).unwrap();
        let digest = kdf::Key::from_slice(&state.finalize().unwrap()[..]).unwrap();

        let root_key = RootKey::derive_from_digest(&digest);
        let chain_key = ChainKey::derive_from_digest(&digest);
        let header_key = HeaderKey::derive_from_digest(&digest);

        (root_key, chain_key, header_key)
    }
}
