use wrench::{Client, Plaintext};
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
    let mut hamilton = Client::new().expect("Failed to create hamilton identity");
    let mut burr = Client::new().expect("Failed to create burr identity");

    let burr_prekey = burr.publish_prekeys().pop().unwrap();
    hamilton
        .initiate(burr_prekey)
        .expect("Failed to initiate hamilton session");

    for (hamilton_burr, line) in TRANSCRIPT.iter() {
        let (sender, receiver) = match hamilton_burr {
            Hamilton => (&mut hamilton, &mut burr),
            Burr => (&mut burr, &mut hamilton),
        };

        let envelope = sender
            .send(receiver.id(), Plaintext(line.as_bytes().to_vec()))
            .expect("Failed to encrypt plaintext");
        let decrypted_plaintext = receiver.receive(envelope);
        assert!(
            decrypted_plaintext.is_ok(),
            "Unable to decrypt message from line {}",
            line
        );
        let (user_id, plaintext) = decrypted_plaintext.unwrap();
        let decrypted_line = std::str::from_utf8(&plaintext.0).expect("Failed to parse into utf8");
        assert!(user_id == sender.id());
        assert_eq!(line, &decrypted_line);
    }
}

#[test]
fn hamilton_ignores_burr_session() {
    let mut hamilton = Client::new().expect("Failed to create hamilton identity");
    let mut burr = Client::new().expect("Failed to create burr identity");

    let burr_prekey = burr.publish_prekeys().pop().unwrap();
    hamilton
        .initiate(burr_prekey)
        .expect("Failed to initiate hamilton session");

    let mut hamilton_inbox = Vec::new();
    for (hamilton_burr, line) in TRANSCRIPT.iter() {
        let (sender, receiver) = match hamilton_burr {
            Hamilton => (&mut hamilton, &mut burr),
            Burr => (&mut burr, &mut hamilton),
        };

        let envelope = sender
            .send(receiver.id(), Plaintext(line.as_bytes().to_vec()))
            .expect("Failed to encrypt plaintext");
        if let Burr = hamilton_burr {
            // Ignore Burr!
            hamilton_inbox.push((envelope, line));
            continue;
        }
        let decrypted_plaintext = receiver.receive(envelope);
        assert!(
            decrypted_plaintext.is_ok(),
            "Unable to decrypt message from line {}",
            line
        );
        let (user_id, plaintext) = decrypted_plaintext.unwrap();
        let decrypted_line = std::str::from_utf8(&plaintext.0).expect("Failed to parse into utf8");
        assert!(user_id == sender.id());
        assert_eq!(line, &decrypted_line);
    }

    // Okay, Hamilton's done ignoring. Check what Burr said...
    for (envelope, line) in hamilton_inbox {
        let decrypted_plaintext = hamilton.receive(envelope);
        assert!(
            decrypted_plaintext.is_ok(),
            "Unable to decrypt message from line {}",
            line
        );
        let (user_id, plaintext) = decrypted_plaintext.unwrap();
        let decrypted_line = std::str::from_utf8(&plaintext.0).expect("Failed to parse into utf8");
        assert!(user_id == burr.id());
        assert_eq!(line, &decrypted_line);
    }
}

#[test]
fn burr_ignores_hamilton_session() {
    let mut hamilton = Client::new().expect("Failed to create hamilton identity");
    let mut burr = Client::new().expect("Failed to create burr identity");

    let burr_prekey = burr.publish_prekeys().pop().unwrap();
    hamilton
        .initiate(burr_prekey)
        .expect("Failed to initiate hamilton session");

    let hamshake = "Hamilton must initiate conversation".as_bytes().to_vec();
    let envelope = hamilton
        .send(burr.id(), Plaintext(hamshake.clone()))
        .expect("Failed to encrypt initial plaintext");
    let (user_id, plaintext) = burr
        .receive(envelope)
        .expect("Failed to decrypt initial message");
    assert!(user_id == hamilton.id());
    assert_eq!(hamshake, plaintext.0);

    let mut burr_inbox = Vec::new();
    for (hamilton_burr, line) in TRANSCRIPT.iter() {
        let (sender, receiver) = match hamilton_burr {
            Hamilton => (&mut hamilton, &mut burr),
            Burr => (&mut burr, &mut hamilton),
        };

        let envelope = sender
            .send(receiver.id(), Plaintext(line.as_bytes().to_vec()))
            .expect("Failed to encrypt plaintext");
        if let Hamilton = hamilton_burr {
            // Ignore Hamilton!
            burr_inbox.push((envelope, line));
            continue;
        }
        let decrypted_plaintext = receiver.receive(envelope);
        assert!(
            decrypted_plaintext.is_ok(),
            "Unable to decrypt message from line {}",
            line
        );
        let (user_id, plaintext) = decrypted_plaintext.unwrap();
        let decrypted_line = std::str::from_utf8(&plaintext.0).expect("Failed to parse into utf8");
        assert!(user_id == sender.id());
        assert_eq!(line, &decrypted_line);
    }

    // Okay, Burr's done ignoring. Check what Hamilton said...
    for (envelope, line) in burr_inbox {
        let decrypted_plaintext = burr.receive(envelope);
        assert!(
            decrypted_plaintext.is_ok(),
            "Unable to decrypt message from line {}",
            line
        );
        let (user_id, plaintext) = decrypted_plaintext.unwrap();
        let decrypted_line = std::str::from_utf8(&plaintext.0).expect("Failed to parse into utf8");
        assert!(user_id == hamilton.id());
        assert_eq!(line, &decrypted_line);
    }
}
