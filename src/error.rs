use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum Error {
    Deserialization,
    Initialization,
    InvalidKey,
    InvalidState,
    InvalidServer,
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
