use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_;

use crate::crypto::{agree::SecretKey, id::UserId, message::Message};
use crate::error::Error::{self, *};

#[derive(Deserialize, Serialize)]
pub struct Envelope {
    pub sender: UserId,
    pub message: Message,
}

impl Envelope {
    pub fn seal_to(self, receiver: UserId) -> SealedEnvelope {
        let receiver_identity_key =
            box_::PublicKey::from_slice(receiver.sign.verify(&receiver.agree).unwrap().as_slice())
                .unwrap();
        let (ephemeral_key, ephemeral_secret_key) = box_::gen_keypair();
        let nonce = box_::gen_nonce();
        let plaintext = serde_json::to_vec(&self).unwrap();
        let ciphertext = box_::seal(
            &plaintext,
            &nonce,
            &receiver_identity_key,
            &ephemeral_secret_key,
        );

        SealedEnvelope {
            receiver,
            ciphertext,
            ephemeral_key,
            nonce,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct SealedEnvelope {
    receiver: UserId,
    ciphertext: Vec<u8>,
    ephemeral_key: box_::PublicKey,
    nonce: box_::Nonce,
}

impl SealedEnvelope {
    pub fn open_by(self, receiver_secret_key: &SecretKey) -> Result<Envelope, Error> {
        let receiver_secret_key =
            box_::SecretKey::from_slice(receiver_secret_key.as_slice()).unwrap();
        let plaintext = box_::open(
            &self.ciphertext,
            &self.nonce,
            &self.ephemeral_key,
            &receiver_secret_key,
        )
        .or(Err(InvalidKey))?;

        serde_json::from_slice(&plaintext).or(Err(Deserialization))
    }

    pub fn receiver(&self) -> UserId {
        self.receiver.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Message, SigningSecretKey, UserId};

    #[test]
    fn seal_open_envelope() {
        let sender = UserId::generate();
        let (receiver_sign, receiver_sign_secret_key) = SigningSecretKey::generate_pair();
        let (receiver_agree, receiver_agree_secret_key) = SecretKey::generate_pair();
        let receiver = UserId::new(
            receiver_sign,
            receiver_sign_secret_key.sign(&receiver_agree),
        );
        let message = Message::generate();

        let envelope = Envelope { sender, message };
        let sealed_envelope = envelope.seal_to(receiver);

        assert!(sealed_envelope.open_by(&receiver_agree_secret_key).is_ok())
    }

    #[test]
    fn seal_open_envelope_wrong_key() {
        let sender = UserId::generate();
        let receiver = UserId::generate();
        let message = Message::generate();

        let envelope = Envelope { sender, message };
        let sealed_envelope = envelope.seal_to(receiver);

        assert!(sealed_envelope
            .open_by(&SecretKey::generate_pair().1)
            .is_err())
    }
}
