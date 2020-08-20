use std::collections;

use crate::{
    crypto::{Envelope, Handshake, Plaintext, Prekey, SealedEnvelope, UserId},
    error::Error::{self, *},
    session::Session,
    x3dh::User,
};

pub struct SessionManager {
    user: User,
    peers: collections::HashMap<UserId, Session>,
}

impl SessionManager {
    const NUM_PREKEYS: usize = 100;

    pub fn new() -> Result<SessionManager, Error> {
        Ok(SessionManager {
            user: User::new()?,
            peers: collections::HashMap::new(),
        })
    }

    pub fn id(&self) -> UserId {
        self.user.id()
    }

    pub fn publish_prekeys(&mut self) -> Vec<Prekey> {
        let mut prekeys = Vec::new();
        for _ in 0..SessionManager::NUM_PREKEYS {
            prekeys.push(self.user.publish_prekey());
        }
        prekeys
    }

    pub fn initiate(&mut self, prekey: Prekey) -> Result<(), Error> {
        let peer_id = prekey.user_id.clone();
        let session = self.user.initiate(prekey)?;
        self.peers.insert(peer_id, session);
        Ok(())
    }

    pub fn close(&mut self, peer_id: UserId) -> Result<(), Error> {
        self.peers.remove(&peer_id).ok_or(MissingSession)?;
        Ok(())
    }

    pub fn send(&mut self, peer_id: UserId, plaintext: Plaintext) -> Result<SealedEnvelope, Error> {
        let session = self.peers.get_mut(&peer_id).ok_or(MissingSession)?;
        let message = session.ratchet_encrypt(plaintext)?;
        let envelope = Envelope {
            sender: self.user.id(),
            message,
        };
        Ok(envelope.seal_to(peer_id))
    }

    pub fn receive(
        &mut self,
        sealed_envelope: SealedEnvelope,
    ) -> Result<(UserId, Plaintext), Error> {
        let envelope = sealed_envelope.open_by(self.user.agree_secret_key())?;
        if let Some(handshake) = envelope.message.handshake.clone() {
            self.respond(handshake)?;
        }
        let session = self.peers.get_mut(&envelope.sender).ok_or(MissingSession)?;
        let plaintext = session.ratchet_decrypt(envelope.message)?;
        Ok((envelope.sender, plaintext))
    }

    fn respond(&mut self, handshake: Handshake) -> Result<(), Error> {
        let peer_id = handshake.initiator_prekey.user_id.clone();
        if self.peers.get(&peer_id).is_some() {
            return Ok(());
        }
        let session = self.user.respond(handshake)?;
        self.peers.insert(peer_id, session);
        Ok(())
    }
}
