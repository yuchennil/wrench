use serde::{Deserialize, Serialize};
use sodiumoxide::{
    crypto::{aead, generichash, kdf, kx, scalarmult},
    init,
    utils::memcmp,
};
use std::collections;

pub struct Session {
    send_public_key: kx::PublicKey,
    send_secret_key: kx::SecretKey,
    receive_public_key: Option<kx::PublicKey>,
    root_key: kdf::Key,
    send_chain_key: Option<kdf::Key>,
    receive_chain_key: Option<kdf::Key>,
    send_nonce: aead::Nonce,
    receive_nonce: aead::Nonce,
    previous_send_nonce: aead::Nonce,
    skipped_message_keys: collections::HashMap<(kx::PublicKey, aead::Nonce), aead::Key>,
}

impl Session {
    // TODO const MAX_SKIP: usize = 256;

    pub fn new_initiator(
        shared_key: kdf::Key,
        receive_public_key: kx::PublicKey,
    ) -> Result<Session, ()> {
        init()?;

        let (send_public_key, send_secret_key) = kx::gen_keypair();
        let (root_key, send_chain_key) = Session::root_kdf(
            shared_key,
            Session::key_exchange(&send_secret_key, &receive_public_key),
        );
        let send_nonce = aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap();
        let receive_nonce = aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap();
        let previous_send_nonce = aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap();

        Ok(Session {
            send_public_key,
            send_secret_key,
            receive_public_key: Some(receive_public_key),
            root_key,
            send_chain_key: Some(send_chain_key),
            receive_chain_key: None,
            send_nonce,
            receive_nonce,
            previous_send_nonce,
            skipped_message_keys: collections::HashMap::new(),
        })
    }

    pub fn new_responder(
        shared_key: kdf::Key,
        send_public_key: kx::PublicKey,
        send_secret_key: kx::SecretKey,
    ) -> Result<Session, ()> {
        init()?;

        let send_nonce = aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap();
        let receive_nonce = aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap();
        let previous_send_nonce = aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap();

        Ok(Session {
            send_public_key,
            send_secret_key,
            receive_public_key: None,
            root_key: shared_key,
            send_chain_key: None,
            receive_chain_key: None,
            send_nonce,
            receive_nonce,
            previous_send_nonce,
            skipped_message_keys: collections::HashMap::new(),
        })
    }

    pub fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (send_chain_key, message_key) = Session::chain_kdf(self.send_chain_key.unwrap());
        self.send_chain_key = Some(send_chain_key);
        let header = Header(
            self.send_public_key,
            self.previous_send_nonce,
            self.send_nonce,
        );
        let serialized_header = serde_json::to_string(&header).unwrap().into_bytes();
        let ciphertext = Ciphertext(aead::seal(
            &plaintext.0,
            Some(&serialized_header),
            &self.send_nonce,
            &message_key,
        ));
        self.send_nonce.increment_le_inplace();
        Message::new(header, ciphertext)
    }

    pub fn ratchet_decrypt(&mut self, message: Message) -> Option<Plaintext> {
        let Header(public_key, previous_nonce, nonce) = message.header;
        let serialized_header = serde_json::to_string(&message.header).unwrap().into_bytes();
        if let Some(message_key) = self.try_skipped_message_keys(&public_key, &nonce) {
            return match aead::open(
                &message.ciphertext.0,
                Some(&serialized_header),
                &nonce,
                &message_key,
            ) {
                Ok(plaintext) => Some(Plaintext(plaintext)),
                Err(_) => None,
            };
        }
        if self.receive_public_key.is_none()
            || !memcmp(&public_key.0, &self.receive_public_key.unwrap().0)
        {
            self.skip_message_keys(&previous_nonce);
            self.public_ratchet(&public_key);
        }
        self.skip_message_keys(&nonce);
        let (receive_chain_key, message_key) = Session::chain_kdf(self.receive_chain_key.unwrap());
        self.receive_chain_key = Some(receive_chain_key);
        self.receive_nonce.increment_le_inplace();
        match aead::open(
            &message.ciphertext.0,
            Some(&serialized_header),
            &nonce,
            &message_key,
        ) {
            Ok(plaintext) => Some(Plaintext(plaintext)),
            Err(_) => None,
        }
    }

    fn try_skipped_message_keys(
        &mut self,
        receive_public_key: &kx::PublicKey,
        receive_nonce: &aead::Nonce,
    ) -> Option<aead::Key> {
        self.skipped_message_keys
            .remove(&(*receive_public_key, *receive_nonce))
    }

    fn skip_message_keys(&mut self, receive_nonce: &aead::Nonce) {
        // TODO error handle MAX_SKIP to protect against denial of service
        while self.receive_nonce < *receive_nonce {
            let (receive_chain_key, message_key) =
                Session::chain_kdf(self.receive_chain_key.unwrap());
            self.receive_chain_key = Some(receive_chain_key);
            self.skipped_message_keys.insert(
                (self.receive_public_key.unwrap(), self.receive_nonce),
                message_key,
            );
            self.receive_nonce.increment_le_inplace();
        }
    }

    fn public_ratchet(&mut self, receive_public_key: &kx::PublicKey) {
        self.previous_send_nonce = self.send_nonce;
        self.send_nonce = aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap();
        self.receive_nonce = aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap();
        self.receive_public_key = Some(*receive_public_key);
        let (root_key, receive_chain_key) = Session::root_kdf(
            self.root_key,
            Session::key_exchange(&self.send_secret_key, receive_public_key),
        );
        self.root_key = root_key;
        self.receive_chain_key = Some(receive_chain_key);
        let (send_public_key, send_secret_key) = kx::gen_keypair();
        self.send_public_key = send_public_key;
        self.send_secret_key = send_secret_key;
        let (root_key, send_chain_key) = Session::root_kdf(
            self.root_key,
            Session::key_exchange(&self.send_secret_key, receive_public_key),
        );
        self.root_key = root_key;
        self.send_chain_key = Some(send_chain_key);
    }

    fn key_exchange(
        send_secret_key: &kx::SecretKey,
        receive_public_key: &kx::PublicKey,
    ) -> kx::SessionKey {
        let send_secret_key = scalarmult::Scalar::from_slice(&send_secret_key.0[..]).unwrap();
        let receive_public_key =
            scalarmult::GroupElement::from_slice(&receive_public_key.0[..]).unwrap();
        let shared_secret = scalarmult::scalarmult(&send_secret_key, &receive_public_key).unwrap();

        kx::SessionKey::from_slice(&shared_secret.0).unwrap()
    }

    fn root_kdf(root_key: kdf::Key, session_key: kx::SessionKey) -> (kdf::Key, kdf::Key) {
        let mut state = generichash::State::new(2 * kdf::KEYBYTES, Some(&root_key.0[..])).unwrap();
        state.update(&session_key.0[..]).unwrap();
        let digest = state.finalize().unwrap();

        let root_key = kdf::Key::from_slice(&digest.as_ref()[..kdf::KEYBYTES]).unwrap();
        let chain_key = kdf::Key::from_slice(&digest.as_ref()[kdf::KEYBYTES..]).unwrap();
        (root_key, chain_key)
    }

    fn chain_kdf(chain_key: kdf::Key) -> (kdf::Key, aead::Key) {
        const CONTEXT: [u8; 8] = *b"chainkdf";
        let mut next_chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut next_chain_key.0[..], 1, CONTEXT, &chain_key).unwrap();
        let mut message_key = aead::Key::from_slice(&[0; aead::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut message_key.0[..], 2, CONTEXT, &chain_key).unwrap();

        (next_chain_key, message_key)
    }
}

pub struct Plaintext(Vec<u8>);
pub struct Ciphertext(Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct Header(kx::PublicKey, aead::Nonce, aead::Nonce);

pub struct Message {
    pub header: Header,
    pub ciphertext: Ciphertext,
}

impl Message {
    pub fn new(header: Header, ciphertext: Ciphertext) -> Message {
        Message { header, ciphertext }
    }
}

#[cfg(test)]
mod tests {
    use super::{Plaintext, Session};
    use sodiumoxide::crypto::{kdf, kx};
    enum HamiltonBurr {
        Hamilton,
        Burr,
    }

    use HamiltonBurr::{Burr, Hamilton};
    const TRANSCRIPT: [(HamiltonBurr, &str); 40] = [
        (Hamilton, "Pardon me"),
        (Hamilton, "Are you Aaron Burr, sir?"),
        (Burr, "That depends"),
        (Hamilton, "Who's asking?"),
        (Hamilton, "Oh, well, sure, sir"),
        (Hamilton, "I'm Alexander Hamilton"),
        (Hamilton, "I'm at your service, sir"),
        (Hamilton, "I have been looking for you"),
        (Burr, "I'm getting nervous"),
        (Hamilton, "Sir, I heard your name at Princeton"),
        (Hamilton, "I was seeking an accelerated course of study"),
        (Hamilton, "When I got out of sorts with a buddy of yours"),
        (Hamilton, "I may have punched him"),
        (Hamilton, "It's a blur, sir"),
        (Hamilton, "He handles the financials?"),
        (Burr, "You punched the bursar?"),
        (Hamilton, "Yes!"),
        (Hamilton, "I wanted to do what you did"),
        (Hamilton, "Graduate in two, then join the revolution"),
        (
            Hamilton,
            "He looked at me like I was stupid, I’m not stupid",
        ),
        (Hamilton, "So how’d you do it?"),
        (Hamilton, "How’d you graduate so fast?"),
        (Burr, "It was my parents’ dying wish before they passed"),
        (Hamilton, "You’re an orphan"),
        (Hamilton, "Of course!"),
        (Hamilton, "I’m an orphan"),
        (Hamilton, "God, I wish there was a war!"),
        (
            Hamilton,
            "Then we could prove that we’re worth more than anyone bargained for",
        ),
        (Burr, "Can I buy you a drink?"),
        (Hamilton, "That would be nice"),
        (
            Burr,
            "While we’re talking, let me offer you some free advice",
        ),
        (Burr, "Talk less"),
        (Hamilton, "What?"),
        (Burr, "Smile more"),
        (Hamilton, "Ha"),
        (
            Burr,
            "Don’t let them know what you’re against or what you’re for",
        ),
        (Hamilton, "You can’t be serious"),
        (Burr, "You wanna get ahead?"),
        (Hamilton, "Yes"),
        (Burr, "Fools who run their mouths off wind up dead"),
    ];

    #[test]
    fn vanilla_session() {
        let shared_key = kdf::gen_key();
        let (burr_public_key, burr_secret_key) = kx::gen_keypair();
        let mut burr = Session::new_responder(shared_key, burr_public_key, burr_secret_key)
            .expect("Failed to create burr");
        let mut hamilton =
            Session::new_initiator(shared_key, burr_public_key).expect("Failed to create hamilton");
        for (hamilton_burr, line) in TRANSCRIPT.iter() {
            let (sender, receiver) = match hamilton_burr {
                Hamilton => (&mut hamilton, &mut burr),
                Burr => (&mut burr, &mut hamilton),
            };

            let message = sender.ratchet_encrypt(Plaintext(line.as_bytes().to_vec()));
            let decrypted_plaintext = receiver.ratchet_decrypt(message);
            assert!(
                decrypted_plaintext.is_some(),
                "Unable to decrypt message from line {}",
                line
            );
            let decrypted_line = String::from_utf8(decrypted_plaintext.unwrap().0)
                .expect("Failed to parse into utf8");
            assert_eq!(line, &decrypted_line);
        }
    }
}
