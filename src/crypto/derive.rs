use sodiumoxide::crypto::{generichash, kdf};

use crate::crypto::{agree::SharedSecret, header::HeaderKey, message::MessageKey};

#[derive(Clone, PartialEq)]
pub struct SessionKey(kdf::Key);

impl SessionKey {
    const CONTEXT: [u8; 8] = *b"sessionk";

    pub fn derive_from_shared_secrets(
        key_0: SharedSecret,
        key_1: SharedSecret,
        key_2: SharedSecret,
    ) -> SessionKey {
        let mut state = generichash::State::new(kdf::KEYBYTES, None).unwrap();
        state.update(key_0.as_slice()).unwrap();
        state.update(key_1.as_slice()).unwrap();
        state.update(key_2.as_slice()).unwrap();
        let digest = state.finalize().unwrap();

        SessionKey(kdf::Key::from_slice(&digest[..]).unwrap())
    }

    #[cfg(test)]
    pub(crate) fn generate() -> SessionKey {
        SessionKey(kdf::gen_key())
    }

    pub fn derive_keys(&self) -> (RootKey, HeaderKey, HeaderKey) {
        let root_key = RootKey::derive_from_session(&self);
        let initiator_header_key =
            HeaderKey::derive_from_session(&self, SessionSubkeyId::InitiatorHeader);
        let responder_header_key =
            HeaderKey::derive_from_session(&self, SessionSubkeyId::ResponderHeader);

        (root_key, initiator_header_key, responder_header_key)
    }

    pub(in crate::crypto) fn derive_into_slice(
        &self,
        mut key_slice: &mut [u8],
        id: SessionSubkeyId,
    ) {
        kdf::derive_from_key(&mut key_slice, id as u64, SessionKey::CONTEXT, &self.0).unwrap();
    }
}

#[derive(Clone, PartialEq)]
pub struct RootKey(kdf::Key);

impl RootKey {
    const CONTEXT: [u8; 8] = *b"rootkdf_";

    fn derive_from_session(session_key: &SessionKey) -> RootKey {
        let mut root_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        session_key.derive_into_slice(&mut root_key.0, SessionSubkeyId::Root);
        RootKey(root_key)
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

    pub fn derive_keys(&self, shared_secret: SharedSecret) -> (RootKey, ChainKey, HeaderKey) {
        let mut state = generichash::State::new(kdf::KEYBYTES, Some(&(self.0).0)).unwrap();
        state.update(shared_secret.as_slice()).unwrap();
        let root = RootKey(kdf::Key::from_slice(&state.finalize().unwrap()[..]).unwrap());

        let root_key = RootKey::derive_from_root(&root);
        let chain_key = ChainKey::derive_from_root(&root);
        let header_key = HeaderKey::derive_from_root(&root);

        (root_key, chain_key, header_key)
    }

    pub(in crate::crypto) fn derive_into_slice(&self, mut key_slice: &mut [u8], id: RootSubkeyId) {
        kdf::derive_from_key(&mut key_slice, id as u64, RootKey::CONTEXT, &self.0).unwrap();
    }
}

#[derive(PartialEq)]
pub struct ChainKey(kdf::Key);

impl ChainKey {
    const CONTEXT: [u8; 8] = *b"chainkdf";

    fn derive_from_root(root_key: &RootKey) -> ChainKey {
        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        root_key.derive_into_slice(&mut chain_key.0, RootSubkeyId::Chain);
        ChainKey(chain_key)
    }

    fn derive_from_chain(prev_chain_key: &ChainKey) -> ChainKey {
        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        prev_chain_key.derive_into_slice(&mut chain_key.0, ChainSubkeyId::Chain);
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

pub enum SessionSubkeyId {
    Root,
    InitiatorHeader,
    ResponderHeader,
}

pub enum RootSubkeyId {
    Root,
    Chain,
    Header,
}

pub enum ChainSubkeyId {
    Chain,
    Message,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;

    #[test]
    fn session_derive_keys() {
        let session_key = SessionKey::generate();
        let (alice_root_key, alice_initiator_header_key, alice_responder_header_key) =
            session_key.derive_keys();
        let (bob_root_key, bob_initiator_header_key, bob_responder_header_key) =
            session_key.derive_keys();

        assert!(alice_root_key == bob_root_key);
        assert!(alice_initiator_header_key != alice_responder_header_key);
        assert!(bob_initiator_header_key != bob_responder_header_key);
        assert!(alice_initiator_header_key == bob_initiator_header_key);
        assert!(alice_responder_header_key == bob_responder_header_key);
    }

    #[test]
    fn root_derive_keys() {
        let root_key = RootKey::generate();
        let shared_secret = SecretKey::generate_pair()
            .1
            .key_exchange(&SecretKey::generate_pair().0)
            .unwrap();
        let (next_root_key, chain_key, header_key) = root_key.derive_keys(shared_secret);
        let shared_secret = SecretKey::generate_pair()
            .1
            .key_exchange(&SecretKey::generate_pair().0)
            .unwrap();
        let (_, next_chain_key, next_header_key) = next_root_key.derive_keys(shared_secret);

        assert!(root_key != next_root_key);
        assert!(chain_key != next_chain_key);
        assert!(header_key != next_header_key);
    }

    #[test]
    fn chain_derive_keys() {
        let chain_key = ChainKey::generate();
        let (next_chain_key, message_key) = chain_key.derive_keys();
        let (_, next_message_key) = next_chain_key.derive_keys();

        assert!(chain_key != next_chain_key);
        assert!(message_key != next_message_key);
    }
}
