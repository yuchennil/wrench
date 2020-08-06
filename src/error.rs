#[derive(Debug)]
pub enum Error {
    Unknown,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}
