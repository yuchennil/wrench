#[derive(Debug)]
pub enum Error {
    Deserialization,
    Initialization,
    InvalidKey,
    InvalidState,
    MissingEphemeralKey,
    MissingHeaderKey,
    MissingSession,
    MissingUser,
    NoMorePrekeys,
    NonceOutOfRange,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}
