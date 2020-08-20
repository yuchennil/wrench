use std::{collections, mem};

use crate::crypto::{Prekey, SealedEnvelope, UserId};
use crate::error::Error::{self, *};

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

    pub fn get_prekey(&mut self, user_id: &UserId) -> Result<Prekey, Error> {
        self.users
            .get_mut(user_id)
            .ok_or(MissingUser)?
            .0
            .pop()
            .ok_or(NoMorePrekeys)
    }

    pub fn add_mail(&mut self, envelope: SealedEnvelope) -> Result<(), Error> {
        self.users
            .get_mut(&envelope.receiver())
            .ok_or(MissingUser)?
            .1
            .push(envelope);
        Ok(())
    }

    pub fn get_mail(&mut self, user_id: &UserId) -> Result<Vec<SealedEnvelope>, Error> {
        let mut mail = Vec::new();
        mem::swap(
            &mut self.users.get_mut(user_id).ok_or(MissingUser)?.1,
            &mut mail,
        );
        Ok(mail)
    }
}
