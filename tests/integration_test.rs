use wrench::{Plaintext, User};
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
    let mut hamilton_user = User::new().expect("Failed to create hamilton identity");
    let mut burr_user = User::new().expect("Failed to create burr identity");

    let burr_prekey = burr_user.publish_prekey();
    let (mut hamilton, hamilton_initial_message) = hamilton_user
        .initiate(burr_prekey)
        .expect("Failed to create hamilton");
    let mut burr = burr_user
        .respond(hamilton_initial_message)
        .expect("Failed to create burr");

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
        let decrypted_line =
            String::from_utf8(decrypted_plaintext.unwrap().0).expect("Failed to parse into utf8");
        assert_eq!(line, &decrypted_line);
    }
}

#[test]
fn hamilton_ignores_burr_session() {
    let mut hamilton_user = User::new().expect("Failed to create hamilton identity");
    let mut burr_user = User::new().expect("Failed to create burr identity");

    let burr_prekey = burr_user.publish_prekey();
    let (mut hamilton, hamilton_initial_message) = hamilton_user
        .initiate(burr_prekey)
        .expect("Failed to create hamilton");
    let mut burr = burr_user
        .respond(hamilton_initial_message)
        .expect("Failed to create burr");

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
        let decrypted_line =
            String::from_utf8(decrypted_plaintext.unwrap().0).expect("Failed to parse into utf8");
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
        let decrypted_line =
            String::from_utf8(decrypted_plaintext.unwrap().0).expect("Failed to parse into utf8");
        assert_eq!(line, &decrypted_line);
    }
}

#[test]
fn burr_ignores_hamilton_session() {
    let mut hamilton_user = User::new().expect("Failed to create hamilton identity");
    let mut burr_user = User::new().expect("Failed to create burr identity");

    let burr_prekey = burr_user.publish_prekey();
    let (mut hamilton, hamilton_initial_message) = hamilton_user
        .initiate(burr_prekey)
        .expect("Failed to create hamilton");
    let mut burr = burr_user
        .respond(hamilton_initial_message)
        .expect("Failed to create burr");

    let hamshake = "Hamilton must initiate conversation".as_bytes().to_vec();
    let message = hamilton
        .ratchet_encrypt(Plaintext(hamshake.clone()))
        .expect("Failed to encrypt initial plaintext");
    let decrypted_plaintext = burr
        .ratchet_decrypt(message)
        .expect("Failed to decrypt initial message");
    assert_eq!(hamshake, decrypted_plaintext.0);

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
        let decrypted_line =
            String::from_utf8(decrypted_plaintext.unwrap().0).expect("Failed to parse into utf8");
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
        let decrypted_line =
            String::from_utf8(decrypted_plaintext.unwrap().0).expect("Failed to parse into utf8");
        assert_eq!(line, &decrypted_line);
    }
}
