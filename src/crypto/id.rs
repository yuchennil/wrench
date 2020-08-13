use serde::Serialize;

use crate::crypto::sign::SigningPublicKey;
#[cfg(test)]
use crate::crypto::sign::SigningSecretKey;

#[derive(Clone, Serialize)]
pub struct SessionId {
    initiator: SigningPublicKey,
    responder: SigningPublicKey,
}

impl SessionId {
    pub fn new(initiator: SigningPublicKey, responder: SigningPublicKey) -> SessionId {
        SessionId {
            initiator,
            responder,
        }
    }

    #[cfg(test)]
    pub(crate) fn generate() -> SessionId {
        SessionId {
            initiator: SigningSecretKey::generate_pair().0,
            responder: SigningSecretKey::generate_pair().0,
        }
    }
}
