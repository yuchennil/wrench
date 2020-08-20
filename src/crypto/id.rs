use serde::{Deserialize, Serialize};

use crate::crypto::sign::{SignedPublicKey, SigningPublicKey};
#[cfg(test)]
use crate::crypto::{agree::SecretKey, sign::SigningSecretKey};

#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserId {
    pub sign: SigningPublicKey,
    pub agree: SignedPublicKey,
}

impl UserId {
    pub fn new(sign: SigningPublicKey, agree: SignedPublicKey) -> UserId {
        UserId { sign, agree }
    }

    #[cfg(test)]
    pub(crate) fn generate() -> UserId {
        let (sign, sign_secret_key) = SigningSecretKey::generate_pair();
        let agree = sign_secret_key.sign(&SecretKey::generate_pair().0);
        UserId { sign, agree }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SessionId {
    initiator: UserId,
    responder: UserId,
}

impl SessionId {
    pub fn new(initiator: UserId, responder: UserId) -> SessionId {
        SessionId {
            initiator,
            responder,
        }
    }

    #[cfg(test)]
    pub(crate) fn generate() -> SessionId {
        SessionId {
            initiator: UserId::generate(),
            responder: UserId::generate(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Prekey {
    pub user_id: UserId,
    pub ephemeral: SignedPublicKey,
}

impl Prekey {
    #[cfg(test)]
    pub(crate) fn generate() -> Prekey {
        Prekey {
            user_id: UserId::generate(),
            ephemeral: SigningSecretKey::generate_pair()
                .1
                .sign(&SecretKey::generate_pair().0),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Handshake {
    pub initiator_prekey: Prekey,
    pub responder_prekey: Prekey,
}

impl Handshake {
    #[cfg(test)]
    pub(crate) fn generate() -> Handshake {
        Handshake {
            initiator_prekey: Prekey::generate(),
            responder_prekey: Prekey::generate(),
        }
    }
}
