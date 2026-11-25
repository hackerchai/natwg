pub mod client;
pub mod config;
pub mod detect;
pub mod doctor;
pub mod export;
pub mod keys;
pub mod nat;
pub mod netcfg;
pub mod peer;
pub mod server;
pub mod service;
pub mod status;
pub mod tunnel;
pub mod update;
pub mod wire;

#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}

impl Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
