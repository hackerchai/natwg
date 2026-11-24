//! WireGuard keys and other secrets. Secrets never appear in `Debug` output, and
//! they serialize as `<redacted>` everywhere except the saved config file.

use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use gotatun::x25519;
use serde::{Deserialize, Serialize, Serializer};
use std::{cell::Cell, fmt, str::FromStr};

const REDACTED: &str = "<redacted>";

/// A 32-byte WireGuard secret in base64, either a private key or a preshared key.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Key([u8; 32]);

impl Key {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|e| Error::new("RANDOM_UNAVAILABLE", e.to_string()))?;
        Ok(Self(bytes))
    }

    pub fn public_key(&self) -> PublicKey {
        let secret = x25519::StaticSecret::from(self.0);
        PublicKey(x25519::PublicKey::from(&secret).to_bytes())
    }

    /// The secret itself, in base64.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }
}

impl FromStr for Key {
    type Err = &'static str;

    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        decode(text)
            .map(Self)
            .ok_or("expected a 32-byte key in base64")
    }
}

impl TryFrom<String> for Key {
    type Error = &'static str;

    fn try_from(text: String) -> std::result::Result<Self, Self::Error> {
        text.parse()
    }
}

impl Serialize for Key {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serialize_secret(&self.to_base64(), serializer)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// A WireGuard public key in base64.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublicKey([u8; 32]);

impl FromStr for PublicKey {
    type Err = &'static str;

    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        decode(text)
            .map(Self)
            .ok_or("expected a 32-byte public key in base64")
    }
}

impl TryFrom<String> for PublicKey {
    type Error = &'static str;

    fn try_from(text: String) -> std::result::Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<PublicKey> for String {
    fn from(key: PublicKey) -> Self {
        key.to_string()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A non-empty secret string, such as an API token.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl FromStr for Secret {
    type Err = &'static str;

    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        text.to_owned().try_into()
    }
}

impl TryFrom<String> for Secret {
    type Error = &'static str;

    fn try_from(text: String) -> std::result::Result<Self, Self::Error> {
        if text.is_empty() {
            return Err("expected a non-empty secret");
        }
        Ok(Self(text))
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serialize_secret(&self.0, serializer)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

thread_local! {
    static EXPOSING: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn exposing<T>(f: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            EXPOSING.set(self.0);
        }
    }
    let _restore = Restore(EXPOSING.replace(true));
    f()
}

fn serialize_secret<S: Serializer>(
    plain: &str,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(if EXPOSING.get() { plain } else { REDACTED })
}

fn decode(text: &str) -> Option<[u8; 32]> {
    STANDARD.decode(text).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_exposing_keeps_the_outer_scope_exposed() {
        let key = Key([7; 32]);
        let plain = serde_json::to_string(&key.to_base64()).unwrap();
        let outer = exposing(|| {
            exposing(|| ());
            serde_json::to_string(&key).unwrap()
        });
        assert_eq!(outer, plain);
        assert_eq!(serde_json::to_string(&key).unwrap(), "\"<redacted>\"");
    }
}
