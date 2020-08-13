use serde::Serialize;

use crate::crypto::sign::SigningPublicKey;
#[cfg(test)]
use crate::crypto::sign::SigningSecretKey;

#[derive(Clone, Serialize)]
pub struct UserId {
    signing_public_key: SigningPublicKey,
}

impl UserId {
    pub fn new(signing_public_key: SigningPublicKey) -> UserId {
        UserId { signing_public_key }
    }

    #[cfg(test)]
    pub(crate) fn generate() -> UserId {
        UserId {
            signing_public_key: SigningSecretKey::generate_pair().0,
        }
    }
}

#[derive(Clone, Serialize)]
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
