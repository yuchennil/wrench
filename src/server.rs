use std::{collections, mem};

use crate::crypto::{Prekey, SealedEnvelope, UserId};
use crate::error::Error::{self, *};

pub enum Request {
    AddPrekeys(UserId, Vec<Prekey>),
    GetPrekey(UserId),
    AddMail(SealedEnvelope),
    GetMail(UserId),
}

pub enum Response {
    Success,
    Error(Error),
    Prekey(Prekey),
    Mail(Vec<SealedEnvelope>),
}

impl Response {
    pub fn prekey(self) -> Result<Prekey, Error> {
        match self {
            Response::Prekey(prekey) => Ok(prekey),
            _ => Err(InvalidServer),
        }
    }

    pub fn mail(self) -> Result<Vec<SealedEnvelope>, Error> {
        match self {
            Response::Mail(envelopes) => Ok(envelopes),
            _ => Err(InvalidServer),
        }
    }
}

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

    pub fn handle(&mut self, request: Request) -> Response {
        use Request::*;
        use Response::*;
        match request {
            AddPrekeys(user_id, prekeys) => {
                self.add_prekeys(user_id, prekeys);
                Success
            }
            GetPrekey(user_id) => match self.get_prekey(user_id) {
                Ok(prekey) => Prekey(prekey),
                Err(error) => Error(error),
            },
            AddMail(envelope) => match self.add_mail(envelope) {
                Ok(()) => Success,
                Err(error) => Error(error),
            },
            GetMail(user_id) => match self.get_mail(user_id) {
                Ok(envelopes) => Mail(envelopes),
                Err(error) => Error(error),
            },
        }
    }

    fn add_prekeys(&mut self, user_id: UserId, prekeys: Vec<Prekey>) {
        self.users.entry(user_id).or_default().0.extend(prekeys);
    }

    fn get_prekey(&mut self, user_id: UserId) -> Result<Prekey, Error> {
        self.users
            .get_mut(&user_id)
            .ok_or(MissingUser)?
            .0
            .pop()
            .ok_or(NoMorePrekeys)
    }

    fn add_mail(&mut self, envelope: SealedEnvelope) -> Result<(), Error> {
        self.users
            .get_mut(&envelope.receiver())
            .ok_or(MissingUser)?
            .1
            .push(envelope);
        Ok(())
    }

    fn get_mail(&mut self, user_id: UserId) -> Result<Vec<SealedEnvelope>, Error> {
        let mut mail = Vec::new();
        mem::swap(
            &mut self.users.get_mut(&user_id).ok_or(MissingUser)?.1,
            &mut mail,
        );
        Ok(mail)
    }
}
