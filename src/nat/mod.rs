//! Source NAT from the tunnel subnet onto the LAN, so LAN hosts answer tunnel
//! peers without a route back to the tunnel.

pub mod nft;
pub mod pf;

use crate::Result;
use crate::config::Instance;
use crate::netcfg::{Step, apply};
use ipnetwork::Ipv4Network;

/// The NAT rules of one instance, loaded until [`Nat::stop`].
pub struct Nat {
    down: Vec<Step>,
}

impl Nat {
    /// Load the rules. A start that fails removes what it loaded.
    pub fn start(
        instance: &Instance,
        iface: &str,
        tunnel: Ipv4Network,
        lan: Ipv4Network,
    ) -> Result<Self> {
        let mut nat = Self {
            down: down(instance),
        };
        match nat.up(instance, iface, tunnel, lan) {
            Ok(()) => Ok(nat),
            Err(error) => {
                let _ = nat.stop();
                Err(error)
            }
        }
    }

    /// Remove the rules. Every step runs, and the first failure is returned.
    pub fn stop(self) -> Result<()> {
        self.down
            .iter()
            .map(|step| apply(std::slice::from_ref(step)))
            .fold(Ok(()), Result::and)
    }

    #[cfg(target_os = "macos")]
    fn up(
        &mut self,
        instance: &Instance,
        iface: &str,
        tunnel: Ipv4Network,
        lan: Ipv4Network,
    ) -> Result<()> {
        self.down.extend(pf::enable()?);
        pf::require_anchor_point()?;
        apply(&pf::up(instance, iface, tunnel, lan))
    }

    #[cfg(not(target_os = "macos"))]
    fn up(
        &mut self,
        instance: &Instance,
        iface: &str,
        tunnel: Ipv4Network,
        lan: Ipv4Network,
    ) -> Result<()> {
        apply(&nft::up(instance, iface, tunnel, lan))
    }
}

#[cfg(target_os = "macos")]
fn down(instance: &Instance) -> Vec<Step> {
    pf::down(instance)
}

#[cfg(not(target_os = "macos"))]
fn down(instance: &Instance) -> Vec<Step> {
    nft::down(instance)
}
