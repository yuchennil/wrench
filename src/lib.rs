#[cfg(test)]
mod tests {
    use sodiumoxide::crypto::box_;

    #[test]
    fn it_works() {
        let (ourpk, oursk) = box_::gen_keypair();
        // normally theirpk is sent by the other party
        let (theirpk, theirsk) = box_::gen_keypair();
        let nonce = box_::gen_nonce();
        let plaintext = b"some data";
        let ciphertext = box_::seal(plaintext, &nonce, &theirpk, &oursk);
        let their_plaintext = box_::open(&ciphertext, &nonce, &ourpk, &theirsk).unwrap();
        assert!(plaintext == &their_plaintext[..]);
    }
}
