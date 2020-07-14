use serde::{Deserialize, Serialize};
use sodiumoxide::{
    crypto::{aead, kdf, kx, secretbox},
    init,
    utils::memcmp,
};
use std::{collections, mem, slice};

use crate::ratchet::{ChainRatchet, PublicRatchet};

pub struct Session {
    state: SessionState,
}

impl Session {
    pub fn new_initiator(
        shared_key: kdf::Key,
        receive_public_key: kx::PublicKey,
        send_header_key: secretbox::Key,
        receive_next_header_key: secretbox::Key,
    ) -> Result<Session, ()> {
        let initiating_state = InitiatingState::new(
            shared_key,
            receive_public_key,
            send_header_key,
            receive_next_header_key,
        )?;
        Ok(Session {
            state: SessionState::Initiating(initiating_state),
        })
    }

    pub fn new_responder(
        shared_key: kdf::Key,
        send_keypair: (kx::PublicKey, kx::SecretKey),
        receive_next_header_key: secretbox::Key,
        send_next_header_key: secretbox::Key,
        message: Message,
    ) -> Result<(Session, Plaintext), ()> {
        let (normal_state, plaintext) = NormalState::new(
            shared_key,
            send_keypair,
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
    receive_next_header_key: secretbox::Key,
}

impl InitiatingState {
    fn new(
        shared_key: kdf::Key,
        receive_public_key: kx::PublicKey,
        send_header_key: secretbox::Key,
        receive_next_header_key: secretbox::Key,
    ) -> Result<InitiatingState, ()> {
        init()?;

        let send_keypair = kx::gen_keypair();
        let mut public_ratchet = PublicRatchet::new(send_keypair, shared_key);
        let send_ratchet = public_ratchet.advance(receive_public_key, send_header_key);

        Ok(InitiatingState {
            public_ratchet,
            send_ratchet,
            receive_next_header_key,
        })
    }

    fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (nonce, message_key) = self.send_ratchet.next().unwrap();
        let header = Header(
            self.public_ratchet.send_public_key(),
            aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap(),
            nonce,
        );
        let encrypted_header = EncryptedHeader::encrypt(&header, &self.send_ratchet.header_key());
        let ciphertext = Ciphertext(aead::seal(
            &plaintext.0,
            Some(&encrypted_header.ciphertext),
            &nonce,
            &message_key,
        ));
        Message::new(encrypted_header, ciphertext)
    }

    fn ratchet_decrypt(mut self, message: Message) -> Result<(NormalState, Plaintext), ()> {
        let Header(public_key, previous_nonce, nonce) = message
            .encrypted_header
            .decrypt(&self.receive_next_header_key)?;
        if !memcmp(&previous_nonce.0, &[0; aead::NONCEBYTES]) {
            // Previous nonce can only be nonzero after a full session handshake has occurred.
            return Err(());
        }
        let (mut receive_ratchet, previous_send_nonce) = self.ratchet(public_key);
        let skipped_message_keys = InitiatingState::skip_message_keys(&mut receive_ratchet, nonce);
        let (nonce, message_key) = receive_ratchet.next().unwrap();

        let state = NormalState {
            public_ratchet: self.public_ratchet,
            send_ratchet: self.send_ratchet,
            receive_ratchet,
            previous_send_nonce,
            skipped_message_keys,
        };

        let plaintext = Plaintext(aead::open(
            &message.ciphertext.0,
            Some(&message.encrypted_header.ciphertext),
            &nonce,
            &message_key,
        )?);

        Ok((state, plaintext))
    }

    fn skip_message_keys(
        receive_ratchet: &mut ChainRatchet,
        receive_nonce: aead::Nonce,
    ) -> SkippedMessageKeys {
        let mut skipped_message_keys = SkippedMessageKeys::new();
        skipped_message_keys.skip(receive_ratchet, receive_nonce);
        skipped_message_keys
    }

    fn ratchet(&mut self, receive_public_key: kx::PublicKey) -> (ChainRatchet, aead::Nonce) {
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
    previous_send_nonce: aead::Nonce,
    skipped_message_keys: SkippedMessageKeys,
}

impl NormalState {
    fn new(
        shared_key: kdf::Key,
        send_keypair: (kx::PublicKey, kx::SecretKey),
        receive_next_header_key: secretbox::Key,
        send_next_header_key: secretbox::Key,
        message: Message,
    ) -> Result<(NormalState, Plaintext), ()> {
        init()?;

        let mut public_ratchet = PublicRatchet::new(send_keypair, shared_key);

        let Header(receive_public_key, previous_receive_nonce, receive_nonce) =
            message.encrypted_header.decrypt(&receive_next_header_key)?;
        if !memcmp(&previous_receive_nonce.0, &[0; aead::NONCEBYTES]) {
            // Previous nonce can only be nonzero after a full session handshake has occurred.
            return Err(());
        }

        let mut send_ratchet = ChainRatchet::new(
            kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap(),
            secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap(),
            send_next_header_key,
        );
        let (mut receive_ratchet, previous_send_nonce) = public_ratchet.ratchet(
            &mut send_ratchet,
            receive_next_header_key,
            receive_public_key,
        );

        let mut skipped_message_keys = SkippedMessageKeys::new();
        skipped_message_keys.skip(&mut receive_ratchet, receive_nonce);

        let (nonce, message_key) = receive_ratchet.next().unwrap();
        let plaintext = Plaintext(aead::open(
            &message.ciphertext.0,
            Some(&message.encrypted_header.ciphertext),
            &nonce,
            &message_key,
        )?);

        let state = NormalState {
            public_ratchet,
            send_ratchet,
            receive_ratchet,
            previous_send_nonce,
            skipped_message_keys,
        };

        Ok((state, plaintext))
    }

    fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (nonce, message_key) = self.send_ratchet.next().unwrap();
        let header = Header(
            self.public_ratchet.send_public_key(),
            self.previous_send_nonce,
            nonce,
        );
        let encrypted_header = EncryptedHeader::encrypt(&header, &self.send_ratchet.header_key());
        let ciphertext = Ciphertext(aead::seal(
            &plaintext.0,
            Some(&encrypted_header.ciphertext),
            &nonce,
            &message_key,
        ));
        Message::new(encrypted_header, ciphertext)
    }

    fn ratchet_decrypt(&mut self, message: Message) -> Result<Plaintext, ()> {
        let (nonce, message_key) = match self.try_skipped_message_keys(&message.encrypted_header) {
            Some(nonce_message_key) => nonce_message_key,
            None => {
                let (Header(public_key, previous_nonce, nonce), should_ratchet) =
                    self.decrypt_header(&message.encrypted_header)?;
                if let ShouldRatchet::Yes = should_ratchet {
                    self.skip_message_keys(previous_nonce);
                    self.ratchet(public_key);
                }
                self.skip_message_keys(nonce);
                self.receive_ratchet.next().unwrap()
            }
        };
        Ok(Plaintext(aead::open(
            &message.ciphertext.0,
            Some(&message.encrypted_header.ciphertext),
            &nonce,
            &message_key,
        )?))
    }

    fn try_skipped_message_keys(
        &mut self,
        encrypted_header: &EncryptedHeader,
    ) -> Option<(aead::Nonce, aead::Key)> {
        for (header_key, message_keys) in self.skipped_message_keys.iter_mut() {
            if let Ok(Header(_, _, nonce)) = encrypted_header.decrypt(header_key) {
                let message_key = message_keys.remove(&nonce)?;
                return Some((nonce, message_key));
            }
        }
        None
    }

    fn decrypt_header(
        &mut self,
        encrypted_header: &EncryptedHeader,
    ) -> Result<(Header, ShouldRatchet), ()> {
        if let Ok(header) = encrypted_header.decrypt(&self.receive_ratchet.header_key()) {
            return Ok((header, ShouldRatchet::No));
        }
        if let Ok(header) = encrypted_header.decrypt(&self.receive_ratchet.next_header_key()) {
            return Ok((header, ShouldRatchet::Yes));
        }
        Err(())
    }

    fn skip_message_keys(&mut self, receive_nonce: aead::Nonce) {
        self.skipped_message_keys
            .skip(&mut self.receive_ratchet, receive_nonce);
    }

    fn ratchet(&mut self, receive_public_key: kx::PublicKey) {
        let (receive_ratchet, previous_send_nonce) = self.public_ratchet.ratchet(
            &mut self.send_ratchet,
            self.receive_ratchet.next_header_key(),
            receive_public_key,
        );
        self.receive_ratchet = receive_ratchet;
        self.previous_send_nonce = previous_send_nonce;
    }
}

struct SkippedMessageKeys(Vec<(secretbox::Key, collections::HashMap<aead::Nonce, aead::Key>)>);

impl SkippedMessageKeys {
    // TODO const MAX_SKIP: usize = 256;

    fn new() -> SkippedMessageKeys {
        SkippedMessageKeys(Vec::new())
    }

    fn skip(&mut self, receive_ratchet: &mut ChainRatchet, receive_nonce: aead::Nonce) {
        // TODO error handle MAX_SKIP to protect against denial of service
        // TODO garbage collect empty (skipped_header_key, message_keys) elements
        let header_key = receive_ratchet.header_key();
        let message_keys = match self
            .iter_mut()
            .find(|(skipped_header_key, _)| memcmp(&header_key.0, &skipped_header_key.0))
        {
            Some((_, message_keys)) => message_keys,
            None => {
                self.0.push((header_key, collections::HashMap::new()));
                &mut self.0.last_mut().unwrap().1
            }
        };
        while receive_ratchet.nonce() < &receive_nonce {
            let (nonce, message_key) = receive_ratchet.next().unwrap();
            message_keys.insert(nonce, message_key);
        }
    }

    fn iter_mut(
        &mut self,
    ) -> slice::IterMut<(secretbox::Key, collections::HashMap<aead::Nonce, aead::Key>)> {
        self.0.iter_mut()
    }
}

pub struct Plaintext(Vec<u8>);
struct Ciphertext(Vec<u8>);

#[derive(Serialize, Deserialize)]
struct Header(kx::PublicKey, aead::Nonce, aead::Nonce);

struct EncryptedHeader {
    ciphertext: Vec<u8>,
    nonce: secretbox::Nonce,
}

impl EncryptedHeader {
    fn encrypt(header: &Header, header_key: &secretbox::Key) -> EncryptedHeader {
        let serialized_header = serde_json::to_string(header).unwrap().into_bytes();
        let nonce = secretbox::gen_nonce();
        let ciphertext = secretbox::seal(&serialized_header, &nonce, &header_key);

        EncryptedHeader { ciphertext, nonce }
    }

    fn decrypt(&self, header_key: &secretbox::Key) -> Result<Header, ()> {
        let serialized_header = secretbox::open(&self.ciphertext, &self.nonce, header_key)?;
        match serde_json::from_slice(&serialized_header) {
            Ok(header) => Ok(header),
            Err(_) => Err(()),
        }
    }
}

pub struct Message {
    encrypted_header: EncryptedHeader,
    ciphertext: Ciphertext,
}

impl Message {
    fn new(encrypted_header: EncryptedHeader, ciphertext: Ciphertext) -> Message {
        Message {
            encrypted_header,
            ciphertext,
        }
    }
}

enum ShouldRatchet {
    Yes,
    No,
}

#[cfg(test)]
mod tests {
    use super::{Plaintext, Session};
    use sodiumoxide::crypto::{kdf, kx, secretbox};
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
        let burr_keypair = kx::gen_keypair();
        let burr_public_key = burr_keypair.0;
        let hamilton_header_key = secretbox::gen_key();
        let burr_header_key = secretbox::gen_key();
        let mut hamilton = Session::new_initiator(
            shared_key,
            burr_public_key,
            hamilton_header_key.clone(),
            burr_header_key.clone(),
        )
        .expect("Failed to create hamilton");
        let handshake_message = hamilton
            .ratchet_encrypt(Plaintext("handshake".as_bytes().to_vec()))
            .expect("Failed to encrypt handshake");
        let (mut burr, handshake_plaintext) = Session::new_responder(
            shared_key,
            burr_keypair,
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
        let shared_key = kdf::gen_key();
        let burr_keypair = kx::gen_keypair();
        let burr_public_key = burr_keypair.0;
        let hamilton_header_key = secretbox::gen_key();
        let burr_header_key = secretbox::gen_key();
        let mut hamilton = Session::new_initiator(
            shared_key,
            burr_public_key,
            hamilton_header_key.clone(),
            burr_header_key.clone(),
        )
        .expect("Failed to create hamilton");
        let handshake_message = hamilton
            .ratchet_encrypt(Plaintext("handshake".as_bytes().to_vec()))
            .expect("Failed to encrypt handshake");
        let (mut burr, handshake_plaintext) = Session::new_responder(
            shared_key,
            burr_keypair,
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
        let shared_key = kdf::gen_key();
        let burr_keypair = kx::gen_keypair();
        let burr_public_key = burr_keypair.0;
        let hamilton_header_key = secretbox::gen_key();
        let burr_header_key = secretbox::gen_key();
        let mut hamilton = Session::new_initiator(
            shared_key,
            burr_public_key,
            hamilton_header_key.clone(),
            burr_header_key.clone(),
        )
        .expect("Failed to create hamilton");
        let handshake_message = hamilton
            .ratchet_encrypt(Plaintext("handshake".as_bytes().to_vec()))
            .expect("Failed to encrypt handshake");
        let (mut burr, handshake_plaintext) = Session::new_responder(
            shared_key,
            burr_keypair,
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
