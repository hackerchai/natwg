//! The UDP wire: STUN and DNS codecs, and the interface-bound socket that STUN
//! and WireGuard share.

pub mod dns;
pub mod stun;
pub mod transport;

use crate::{Error, Result};

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|e| Error::new("RANDOM_UNAVAILABLE", e.to_string()))?;
    Ok(bytes)
}
