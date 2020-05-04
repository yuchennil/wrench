use serde::{Deserialize, Serialize};
use sodiumoxide::{
    crypto::{aead, generichash, kdf, kx, scalarmult},
    init,
    utils::memcmp,
};
use std::collections;

pub struct Session {
    public_ratchet: PublicRatchet,
    send_ratchet: Option<ChainRatchet>,
    receive_ratchet: Option<ChainRatchet>,
    receive_public_key: Option<kx::PublicKey>,
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

        let send_keypair = kx::gen_keypair();
        let mut public_ratchet = PublicRatchet::new(send_keypair, shared_key);
        let send_ratchet = public_ratchet.advance(receive_public_key);
        let previous_send_nonce = aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap();
        let skipped_message_keys = collections::HashMap::new();

        Ok(Session {
            public_ratchet,
            send_ratchet: Some(send_ratchet),
            receive_ratchet: None,
            receive_public_key: Some(receive_public_key),
            previous_send_nonce,
            skipped_message_keys,
        })
    }

    pub fn new_responder(
        shared_key: kdf::Key,
        send_keypair: (kx::PublicKey, kx::SecretKey),
    ) -> Result<Session, ()> {
        init()?;

        let public_ratchet = PublicRatchet::new(send_keypair, shared_key);
        let previous_send_nonce = aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap();
        let skipped_message_keys = collections::HashMap::new();

        Ok(Session {
            public_ratchet,
            send_ratchet: None,
            receive_ratchet: None,
            receive_public_key: None,
            previous_send_nonce,
            skipped_message_keys,
        })
    }

    pub fn ratchet_encrypt(&mut self, plaintext: Plaintext) -> Message {
        let (message_key, nonce) = self.send_ratchet.as_mut().unwrap().next().unwrap();
        let header = Header(
            self.public_ratchet.send_public_key(),
            self.previous_send_nonce,
            nonce,
        );
        let serialized_header = serde_json::to_string(&header).unwrap().into_bytes();
        let ciphertext = Ciphertext(aead::seal(
            &plaintext.0,
            Some(&serialized_header),
            &nonce,
            &message_key,
        ));
        Message::new(header, ciphertext)
    }

    pub fn ratchet_decrypt(&mut self, message: Message) -> Result<Plaintext, ()> {
        let Header(public_key, previous_nonce, nonce) = message.header;
        let message_key = match self.skipped_message_keys.remove(&(public_key, nonce)) {
            Some(message_key) => message_key,
            None => {
                if self.receive_public_key.is_none()
                    || !memcmp(&public_key.0, &self.receive_public_key.unwrap().0)
                {
                    self.skip_message_keys(previous_nonce);
                    self.public_ratchet(public_key);
                }
                self.skip_message_keys(nonce);
                let (message_key, _nonce) = self.receive_ratchet.as_mut().unwrap().next().unwrap();

                message_key
            }
        };
        let serialized_header = serde_json::to_string(&message.header).unwrap().into_bytes();
        Ok(Plaintext(aead::open(
            &message.ciphertext.0,
            Some(&serialized_header),
            &nonce,
            &message_key,
        )?))
    }

    fn skip_message_keys(&mut self, receive_nonce: aead::Nonce) {
        // TODO error handle MAX_SKIP to protect against denial of service
        while self.receive_ratchet.is_some()
            && self.receive_ratchet.as_ref().unwrap().nonce < receive_nonce
        {
            let (message_key, nonce) = self.receive_ratchet.as_mut().unwrap().next().unwrap();
            self.skipped_message_keys
                .insert((self.receive_public_key.unwrap(), nonce), message_key);
        }
    }

    fn public_ratchet(&mut self, receive_public_key: kx::PublicKey) {
        self.previous_send_nonce = match self.send_ratchet.as_ref() {
            Some(ratchet) => ratchet.nonce,
            None => aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap(),
        };
        self.receive_public_key = Some(receive_public_key);
        self.receive_ratchet = Some(self.public_ratchet.advance(receive_public_key));
        self.public_ratchet.update_send_keypair(kx::gen_keypair());
        self.send_ratchet = Some(self.public_ratchet.advance(receive_public_key));
    }
}

struct PublicRatchet {
    send_keypair: (kx::PublicKey, kx::SecretKey),
    root_ratchet: RootRatchet,
}

impl PublicRatchet {
    fn new(send_keypair: (kx::PublicKey, kx::SecretKey), root_key: kdf::Key) -> PublicRatchet {
        PublicRatchet {
            send_keypair,
            root_ratchet: RootRatchet::new(root_key),
        }
    }

    fn advance(&mut self, receive_public_key: kx::PublicKey) -> ChainRatchet {
        let session_key = self.key_exchange(receive_public_key);
        let chain_key = self.root_ratchet.advance(session_key);

        ChainRatchet::new(chain_key)
    }

    fn update_send_keypair(&mut self, send_keypair: (kx::PublicKey, kx::SecretKey)) {
        self.send_keypair = send_keypair;
    }

    fn send_public_key(&self) -> kx::PublicKey {
        self.send_keypair.0
    }

    fn key_exchange(&self, receive_public_key: kx::PublicKey) -> kx::SessionKey {
        let send_secret_scalar =
            scalarmult::Scalar::from_slice(&(self.send_keypair.1).0[..]).unwrap();
        let receive_public_group_element =
            scalarmult::GroupElement::from_slice(&receive_public_key.0[..]).unwrap();
        let shared_secret =
            scalarmult::scalarmult(&send_secret_scalar, &receive_public_group_element).unwrap();

        kx::SessionKey::from_slice(&shared_secret.0).unwrap()
    }
}

struct RootRatchet {
    root_key: kdf::Key,
}

impl RootRatchet {
    fn new(root_key: kdf::Key) -> RootRatchet {
        RootRatchet { root_key }
    }

    fn advance(&mut self, session_key: kx::SessionKey) -> kdf::Key {
        let (chain_key, root_key) = self.key_derivation(session_key);

        self.root_key = root_key;
        chain_key
    }

    fn key_derivation(&self, session_key: kx::SessionKey) -> (kdf::Key, kdf::Key) {
        let mut state =
            generichash::State::new(2 * kdf::KEYBYTES, Some(&self.root_key.0[..])).unwrap();
        state.update(&session_key.0[..]).unwrap();
        let digest = state.finalize().unwrap();

        let chain_key = kdf::Key::from_slice(&digest.as_ref()[kdf::KEYBYTES..]).unwrap();
        let root_key = kdf::Key::from_slice(&digest.as_ref()[..kdf::KEYBYTES]).unwrap();

        (chain_key, root_key)
    }
}

struct ChainRatchet {
    chain_key: kdf::Key,
    nonce: aead::Nonce,
}

impl Iterator for ChainRatchet {
    type Item = (aead::Key, aead::Nonce);

    fn next(&mut self) -> Option<Self::Item> {
        let (next_chain_key, message_key) = self.key_derivation();
        let nonce = self.nonce;

        self.chain_key = next_chain_key;
        self.nonce.increment_le_inplace();

        Some((message_key, nonce))
    }
}

impl ChainRatchet {
    fn new(chain_key: kdf::Key) -> ChainRatchet {
        ChainRatchet {
            chain_key,
            nonce: aead::Nonce::from_slice(&[0; aead::NONCEBYTES]).unwrap(),
        }
    }

    fn key_derivation(&self) -> (kdf::Key, aead::Key) {
        const CONTEXT: [u8; 8] = *b"chainkdf";

        let mut chain_key = kdf::Key::from_slice(&[0; kdf::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut chain_key.0[..], 1, CONTEXT, &self.chain_key).unwrap();

        let mut message_key = aead::Key::from_slice(&[0; aead::KEYBYTES]).unwrap();
        kdf::derive_from_key(&mut message_key.0[..], 2, CONTEXT, &self.chain_key).unwrap();

        (chain_key, message_key)
    }
}

pub struct Plaintext(Vec<u8>);
struct Ciphertext(Vec<u8>);

#[derive(Serialize, Deserialize)]
struct Header(kx::PublicKey, aead::Nonce, aead::Nonce);

pub struct Message {
    header: Header,
    ciphertext: Ciphertext,
}

impl Message {
    fn new(header: Header, ciphertext: Ciphertext) -> Message {
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
        let burr_keypair = kx::gen_keypair();
        let burr_public_key = burr_keypair.0;
        let mut burr =
            Session::new_responder(shared_key, burr_keypair).expect("Failed to create burr");
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
        let mut burr =
            Session::new_responder(shared_key, burr_keypair).expect("Failed to create burr");
        let mut hamilton =
            Session::new_initiator(shared_key, burr_public_key).expect("Failed to create hamilton");
        let mut hamilton_inbox = Vec::new();
        for (hamilton_burr, line) in TRANSCRIPT.iter() {
            let (sender, receiver) = match hamilton_burr {
                Hamilton => (&mut hamilton, &mut burr),
                Burr => (&mut burr, &mut hamilton),
            };

            let message = sender.ratchet_encrypt(Plaintext(line.as_bytes().to_vec()));
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
        let mut burr =
            Session::new_responder(shared_key, burr_keypair).expect("Failed to create burr");
        let mut hamilton =
            Session::new_initiator(shared_key, burr_public_key).expect("Failed to create hamilton");
        let mut burr_inbox = Vec::new();
        // Mandatory handshake initiated by hamilton. After this burr can ignore hamilton.
        // TODO move this to key exchange
        assert!(burr
            .ratchet_decrypt(hamilton.ratchet_encrypt(Plaintext(b"initiator handshake".to_vec())))
            .is_ok());
        for (hamilton_burr, line) in TRANSCRIPT.iter() {
            let (sender, receiver) = match hamilton_burr {
                Hamilton => (&mut hamilton, &mut burr),
                Burr => (&mut burr, &mut hamilton),
            };

            let message = sender.ratchet_encrypt(Plaintext(line.as_bytes().to_vec()));
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
