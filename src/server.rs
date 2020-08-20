use std::{collections, mem};

use crate::crypto::{Prekey, SealedEnvelope, UserId};

pub struct Server {
    users: collections::HashMap<UserId, (Vec<Prekey>, Vec<SealedEnvelope>)>,
}

impl Default for Server {
    fn default() -> Server {
        Server::new()
    }
}

impl Server {
    pub fn new() -> Server {
        Server {
            users: collections::HashMap::new(),
        }
    }

    pub fn add_prekeys(&mut self, user_id: &UserId, prekeys: Vec<Prekey>) {
        self.users
            .entry(user_id.clone())
            .or_default()
            .0
            .extend(prekeys);
    }

    pub fn get_prekey(&mut self, user_id: &UserId) -> Option<Prekey> {
        self.users.get_mut(user_id)?.0.pop()
    }

    pub fn add_mail(&mut self, user_id: &UserId, envelope: SealedEnvelope) -> Option<()> {
        self.users.get_mut(user_id)?.1.push(envelope);
        Some(())
    }

    pub fn get_mail(&mut self, user_id: &UserId) -> Option<Vec<SealedEnvelope>> {
        let mut mail = Vec::new();
        mem::swap(&mut self.users.get_mut(user_id)?.1, &mut mail);
        Some(mail)
    }
}
