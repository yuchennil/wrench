use serde::Serialize;

#[cfg(test)]
use crate::crypto::sign::SigningSecretKey;
use crate::crypto::{header::EncryptedHeader, message::Nonce, sign::SigningPublicKey};

#[derive(Clone, Serialize)]
pub struct AssociatedData {
    initiator: SigningPublicKey,
    responder: SigningPublicKey,
    pub encrypted_header: EncryptedHeader,
    pub nonce: Nonce,
}

#[derive(Clone)]
pub struct AssociatedDataService {
    initiator: SigningPublicKey,
    responder: SigningPublicKey,
}

impl AssociatedDataService {
    pub fn new(initiator: SigningPublicKey, responder: SigningPublicKey) -> AssociatedDataService {
        AssociatedDataService {
            initiator,
            responder,
        }
    }

    #[cfg(test)]
    pub(crate) fn generate() -> AssociatedDataService {
        AssociatedDataService {
            initiator: SigningSecretKey::generate_pair().0,
            responder: SigningSecretKey::generate_pair().0,
        }
    }

    pub fn create(&self, encrypted_header: EncryptedHeader, nonce: Nonce) -> AssociatedData {
        AssociatedData {
            initiator: self.initiator.clone(),
            responder: self.responder.clone(),
            encrypted_header,
            nonce,
        }
    }
}
