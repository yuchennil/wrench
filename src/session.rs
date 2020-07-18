use sodiumoxide::init;
use std::{collections, mem, slice};

use crate::crypto::{
    EncryptedHeader, Header, HeaderKey, Message, MessageKey, Nonce, Plaintext, PublicKey, RootKey,
    SecretKey,
};
use crate::ratchet::{ChainRatchet, PublicRatchet};

pub struct Session {
    state: SessionState,
}

impl Session {
    pub fn new_initiator(
        root_key: RootKey,
        receive_public_key: PublicKey,
        send_header_key: HeaderKey,
        receive_next_header_key: HeaderKey,
    ) -> Result<Session, ()> {
        let initiating_state = InitiatingState::new(
            root_key,
            receive_public_key,
            send_header_key,
            receive_next_header_key,
        )?;
        Ok(Session {
            state: SessionState::Initiating(initiating_state),
        })
    }

    pub fn new_responder(
        root_key: RootKey,
        send_public_key: PublicKey,
        send_secret_key: SecretKey,
        receive_next_header_key: HeaderKey,
        send_next_header_key: HeaderKey,
        message: Message,
    ) -> Result<(Session, Plaintext), ()> {
        let (normal_state, plaintext) = NormalState::new(
            root_key,
            send_public_key,
            send_secret_key,
            receive_next_header_key,
            send_next_header_key,
            message,
        )?;
        Ok((
            Session {
                state: SessionState::Normal(normal_state),
            },
            plaintext,
        ))
    }

    pub fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Result<Message, ()> {
        match &mut self.state {
            SessionState::Initiating(initiating_state) => {
                Ok(initiating_state.ratchet_encrypt(plaintext))
            }
            SessionState::Normal(normal_state) => Ok(normal_state.ratchet_encrypt(plaintext)),
            SessionState::Error => Err(()),
        }
    }

    pub fn ratchet_decrypt(&mut self, message: Message) -> Result<Plaintext, ()> {
        let mut next = SessionState::Error;
        mem::swap(&mut self.state, &mut next);
        let (mut next, result) = match next {
            SessionState::Initiating(initiating_state) => {
                match initiating_state.ratchet_decrypt(message) {
                    Ok((normal_state, plaintext)) => {
                        (SessionState::Normal(normal_state), Ok(plaintext))
                    }
                    Err(()) => (SessionState::Error, Err(())),
                }
            }
            SessionState::Normal(mut normal_state) => match normal_state.ratchet_decrypt(message) {
                Ok(plaintext) => (SessionState::Normal(normal_state), Ok(plaintext)),
                Err(()) => (SessionState::Error, Err(())),
            },
            SessionState::Error => (SessionState::Error, Err(())),
        };
        mem::swap(&mut self.state, &mut next);
        result
    }
}

enum SessionState {
    Initiating(InitiatingState),
    Normal(NormalState),
    Error,
}

struct InitiatingState {
    public_ratchet: PublicRatchet,
    send_ratchet: ChainRatchet,
    receive_next_header_key: HeaderKey,
}

impl InitiatingState {
    fn new(
        root_key: RootKey,
        receive_public_key: PublicKey,
        send_header_key: HeaderKey,
        receive_next_header_key: HeaderKey,
    ) -> Result<InitiatingState, ()> {
        init()?;

        let (send_public_key, send_secret_key) = SecretKey::generate_pair();
        let mut public_ratchet = PublicRatchet::new(send_public_key, send_secret_key, root_key);
        let send_ratchet = public_ratchet.advance(receive_public_key, send_header_key);

        Ok(InitiatingState {
            public_ratchet,
            send_ratchet,
            receive_next_header_key,
        })
    }

    fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (nonce, message_key) = self.send_ratchet.advance();
        let header = Header::new(
            self.public_ratchet.send_public_key.clone(),
            Nonce::new_zero(),
            nonce,
        );
        let encrypted_header = self.send_ratchet.header_key.encrypt(header);
        message_key.encrypt(plaintext, encrypted_header, nonce)
    }

    fn ratchet_decrypt(mut self, message: Message) -> Result<(NormalState, Plaintext), ()> {
        let header = self
            .receive_next_header_key
            .decrypt(&message.encrypted_header)?;
        if !header.previous_nonce.equals_zero() {
            // Previous nonce can only be nonzero after a full session handshake has occurred.
            return Err(());
        }

        let (mut receive_ratchet, previous_send_nonce) = self.ratchet(header.public_key.clone());

        let mut skipped_message_keys = SkippedMessageKeys::new();
        skipped_message_keys.skip(&mut receive_ratchet, header.nonce);

        let (nonce, message_key) = receive_ratchet.advance();
        let plaintext = message_key.decrypt(message, nonce)?;

        let normal_state = NormalState {
            public_ratchet: self.public_ratchet,
            send_ratchet: self.send_ratchet,
            receive_ratchet,
            previous_send_nonce,
            skipped_message_keys,
        };

        Ok((normal_state, plaintext))
    }

    fn ratchet(&mut self, receive_public_key: PublicKey) -> (ChainRatchet, Nonce) {
        let (receive_ratchet, previous_send_nonce) = self.public_ratchet.ratchet(
            &mut self.send_ratchet,
            self.receive_next_header_key.clone(),
            receive_public_key,
        );
        (receive_ratchet, previous_send_nonce)
    }
}

struct NormalState {
    public_ratchet: PublicRatchet,
    send_ratchet: ChainRatchet,
    receive_ratchet: ChainRatchet,
    previous_send_nonce: Nonce,
    skipped_message_keys: SkippedMessageKeys,
}

impl NormalState {
    fn new(
        root_key: RootKey,
        send_public_key: PublicKey,
        send_secret_key: SecretKey,
        receive_next_header_key: HeaderKey,
        send_next_header_key: HeaderKey,
        message: Message,
    ) -> Result<(NormalState, Plaintext), ()> {
        init()?;

        let mut public_ratchet = PublicRatchet::new(send_public_key, send_secret_key, root_key);

        let header = receive_next_header_key.decrypt(&message.encrypted_header)?;
        if !header.previous_nonce.equals_zero() {
            // Previous nonce can only be nonzero after a full session handshake has occurred.
            return Err(());
        }

        let mut send_ratchet = ChainRatchet::new_burner(send_next_header_key);

        let (mut receive_ratchet, previous_send_nonce) = public_ratchet.ratchet(
            &mut send_ratchet,
            receive_next_header_key,
            header.public_key.clone(),
        );

        let mut skipped_message_keys = SkippedMessageKeys::new();
        skipped_message_keys.skip(&mut receive_ratchet, header.nonce);

        let (nonce, message_key) = receive_ratchet.advance();
        let plaintext = message_key.decrypt(message, nonce)?;

        let normal_state = NormalState {
            public_ratchet,
            send_ratchet,
            receive_ratchet,
            previous_send_nonce,
            skipped_message_keys,
        };

        Ok((normal_state, plaintext))
    }

    fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (nonce, message_key) = self.send_ratchet.advance();
        let header = Header::new(
            self.public_ratchet.send_public_key.clone(),
            self.previous_send_nonce,
            nonce,
        );
        let encrypted_header = self.send_ratchet.header_key.encrypt(header);
        message_key.encrypt(plaintext, encrypted_header, nonce)
    }

    fn ratchet_decrypt(&mut self, message: Message) -> Result<Plaintext, ()> {
        let (nonce, message_key) = match self
            .skipped_message_keys
            .decrypt_header(&message.encrypted_header)
        {
            Some(nonce_message_key) => nonce_message_key,
            None => {
                let nonce = if let Ok(header) = self
                    .receive_ratchet
                    .header_key
                    .decrypt(&message.encrypted_header)
                {
                    header.nonce
                } else if let Ok(header) = self
                    .receive_ratchet
                    .next_header_key
                    .decrypt(&message.encrypted_header)
                {
                    self.skipped_message_keys
                        .skip(&mut self.receive_ratchet, header.previous_nonce);
                    self.ratchet(header.public_key.clone());
                    header.nonce
                } else {
                    return Err(());
                };

                self.skipped_message_keys
                    .skip(&mut self.receive_ratchet, nonce);
                self.receive_ratchet.advance()
            }
        };
        message_key.decrypt(message, nonce)
    }

    fn ratchet(&mut self, receive_public_key: PublicKey) {
        let (receive_ratchet, previous_send_nonce) = self.public_ratchet.ratchet(
            &mut self.send_ratchet,
            self.receive_ratchet.next_header_key.clone(),
            receive_public_key,
        );
        self.receive_ratchet = receive_ratchet;
        self.previous_send_nonce = previous_send_nonce;
    }
}

struct SkippedMessageKeys(Vec<(HeaderKey, collections::HashMap<Nonce, MessageKey>)>);

impl SkippedMessageKeys {
    // TODO const MAX_SKIP: usize = 256;

    fn new() -> SkippedMessageKeys {
        SkippedMessageKeys(Vec::new())
    }

    fn decrypt_header(
        &mut self,
        encrypted_header: &EncryptedHeader,
    ) -> Option<(Nonce, MessageKey)> {
        for (header_key, message_keys) in self.iter_mut() {
            if let Ok(header) = header_key.decrypt(encrypted_header) {
                let message_key = message_keys.remove(&header.nonce)?;
                return Some((header.nonce, message_key));
            }
        }
        None
    }

    fn skip(&mut self, receive_ratchet: &mut ChainRatchet, receive_nonce: Nonce) {
        // TODO error handle MAX_SKIP to protect against denial of service
        // TODO garbage collect empty (skipped_header_key, message_keys) elements
        let message_keys = match self
            .iter_mut()
            .find(|(skipped_header_key, _)| receive_ratchet.header_key == *skipped_header_key)
        {
            Some((_, message_keys)) => message_keys,
            None => {
                self.0.push((
                    receive_ratchet.header_key.clone(),
                    collections::HashMap::new(),
                ));
                &mut self.0.last_mut().unwrap().1
            }
        };
        while receive_ratchet.nonce < receive_nonce {
            let (nonce, message_key) = receive_ratchet.advance();
            message_keys.insert(nonce, message_key);
        }
    }

    fn iter_mut(&mut self) -> slice::IterMut<(HeaderKey, collections::HashMap<Nonce, MessageKey>)> {
        self.0.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::{Plaintext, Session};
    use crate::crypto::{HeaderKey, RootKey, SecretKey};
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
        let root_key = RootKey::generate();
        let (burr_public_key, burr_secret_key) = SecretKey::generate_pair();
        let hamilton_header_key = HeaderKey::generate();
        let burr_header_key = HeaderKey::generate();
        let mut hamilton = Session::new_initiator(
            root_key.clone(),
            burr_public_key.clone(),
            hamilton_header_key.clone(),
            burr_header_key.clone(),
        )
        .expect("Failed to create hamilton");
        let handshake_message = hamilton
            .ratchet_encrypt(Plaintext("handshake".as_bytes().to_vec()))
            .expect("Failed to encrypt handshake");
        let (mut burr, handshake_plaintext) = Session::new_responder(
            root_key,
            burr_public_key,
            burr_secret_key,
            hamilton_header_key,
            burr_header_key,
            handshake_message,
        )
        .expect("Failed to create burr");
        assert_eq!("handshake".as_bytes().to_vec(), handshake_plaintext.0);
        for (hamilton_burr, line) in TRANSCRIPT.iter() {
            let (sender, receiver) = match hamilton_burr {
                Hamilton => (&mut hamilton, &mut burr),
                Burr => (&mut burr, &mut hamilton),
            };

            let message = sender
                .ratchet_encrypt(Plaintext(line.as_bytes().to_vec()))
                .expect("Failed to encrypt plaintext");
            let decrypted_plaintext = receiver.ratchet_decrypt(message);
            assert!(
                decrypted_plaintext.is_ok(),
                "Unable to decrypt message from line {}",
                line
            );
            let decrypted_line = String::from_utf8(decrypted_plaintext.unwrap().0)
                .expect("Failed to parse into utf8");
            assert_eq!(line, &decrypted_line);
        }
    }

    #[test]
    fn hamilton_ignores_burr_session() {
        let root_key = RootKey::generate();
        let (burr_public_key, burr_secret_key) = SecretKey::generate_pair();
        let hamilton_header_key = HeaderKey::generate();
        let burr_header_key = HeaderKey::generate();
        let mut hamilton = Session::new_initiator(
            root_key.clone(),
            burr_public_key.clone(),
            hamilton_header_key.clone(),
            burr_header_key.clone(),
        )
        .expect("Failed to create hamilton");
        let handshake_message = hamilton
            .ratchet_encrypt(Plaintext("handshake".as_bytes().to_vec()))
            .expect("Failed to encrypt handshake");
        let (mut burr, handshake_plaintext) = Session::new_responder(
            root_key,
            burr_public_key,
            burr_secret_key,
            hamilton_header_key,
            burr_header_key,
            handshake_message,
        )
        .expect("Failed to create burr");
        assert_eq!("handshake".as_bytes().to_vec(), handshake_plaintext.0);
        let mut hamilton_inbox = Vec::new();
        for (hamilton_burr, line) in TRANSCRIPT.iter() {
            let (sender, receiver) = match hamilton_burr {
                Hamilton => (&mut hamilton, &mut burr),
                Burr => (&mut burr, &mut hamilton),
            };

            let message = sender
                .ratchet_encrypt(Plaintext(line.as_bytes().to_vec()))
                .expect("Failed to encrypt plaintext");
            if let Burr = hamilton_burr {
                // Ignore Burr!
                hamilton_inbox.push((message, line));
                continue;
            }
            let decrypted_plaintext = receiver.ratchet_decrypt(message);
            assert!(
                decrypted_plaintext.is_ok(),
                "Unable to decrypt message from line {}",
                line
            );
            let decrypted_line = String::from_utf8(decrypted_plaintext.unwrap().0)
                .expect("Failed to parse into utf8");
            assert_eq!(line, &decrypted_line);
        }

        // Okay, Hamilton's done ignoring. Check what Burr said...
        for (message, line) in hamilton_inbox {
            let decrypted_plaintext = hamilton.ratchet_decrypt(message);
            assert!(
                decrypted_plaintext.is_ok(),
                "Unable to decrypt message from line {}",
                line
            );
            let decrypted_line = String::from_utf8(decrypted_plaintext.unwrap().0)
                .expect("Failed to parse into utf8");
            assert_eq!(line, &decrypted_line);
        }
    }

    #[test]
    fn burr_ignores_hamilton_session() {
        let root_key = RootKey::generate();
        let (burr_public_key, burr_secret_key) = SecretKey::generate_pair();
        let hamilton_header_key = HeaderKey::generate();
        let burr_header_key = HeaderKey::generate();
        let mut hamilton = Session::new_initiator(
            root_key.clone(),
            burr_public_key.clone(),
            hamilton_header_key.clone(),
            burr_header_key.clone(),
        )
        .expect("Failed to create hamilton");
        let handshake_message = hamilton
            .ratchet_encrypt(Plaintext("handshake".as_bytes().to_vec()))
            .expect("Failed to encrypt handshake");
        let (mut burr, handshake_plaintext) = Session::new_responder(
            root_key,
            burr_public_key,
            burr_secret_key,
            hamilton_header_key,
            burr_header_key,
            handshake_message,
        )
        .expect("Failed to create burr");
        assert_eq!("handshake".as_bytes().to_vec(), handshake_plaintext.0);
        let mut burr_inbox = Vec::new();
        for (hamilton_burr, line) in TRANSCRIPT.iter() {
            let (sender, receiver) = match hamilton_burr {
                Hamilton => (&mut hamilton, &mut burr),
                Burr => (&mut burr, &mut hamilton),
            };

            let message = sender
                .ratchet_encrypt(Plaintext(line.as_bytes().to_vec()))
                .expect("Failed to encrypt plaintext");
            if let Hamilton = hamilton_burr {
                // Ignore Hamilton!
                burr_inbox.push((message, line));
                continue;
            }
            let decrypted_plaintext = receiver.ratchet_decrypt(message);
            assert!(
                decrypted_plaintext.is_ok(),
                "Unable to decrypt message from line {}",
                line
            );
            let decrypted_line = String::from_utf8(decrypted_plaintext.unwrap().0)
                .expect("Failed to parse into utf8");
            assert_eq!(line, &decrypted_line);
        }

        // Okay, Burr's done ignoring. Check what Hamilton said...
        for (message, line) in burr_inbox {
            let decrypted_plaintext = burr.ratchet_decrypt(message);
            assert!(
                decrypted_plaintext.is_ok(),
                "Unable to decrypt message from line {}",
                line
            );
            let decrypted_line = String::from_utf8(decrypted_plaintext.unwrap().0)
                .expect("Failed to parse into utf8");
            assert_eq!(line, &decrypted_line);
        }
    }
}
