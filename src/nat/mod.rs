//! Source NAT from the tunnel subnet onto the LAN, so LAN hosts answer tunnel
//! peers without a route back to the tunnel.

pub mod nft;
pub mod pf;

use crate::config::Instance;
use crate::netcfg::{Step, Teardown, apply, read};
use crate::{Error, Result};
use ipnetwork::Ipv4Network;

/// The one NAT rule of an instance. Traffic from `tunnel` to `lan` leaves
/// through `iface` with the address of `iface`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    instance: Instance,
    iface: String,
    tunnel: Ipv4Network,
    lan: Ipv4Network,
}

impl Rule {
    pub fn new(instance: &Instance, iface: &str, tunnel: Ipv4Network, lan: Ipv4Network) -> Self {
        Self {
            instance: instance.clone(),
            iface: iface.to_owned(),
            tunnel,
            lan,
        }
    }

    /// Refuse an anchor or a table that holds a rule of someone else. Loading
    /// replaces everything in it and stopping empties it, so natwg takes it
    /// only when it is empty or holds this rule already. A server that was
    /// killed leaves this rule behind, and so does the Python daemon that
    /// served the same subnets. The check only reads.
    pub fn check(self) -> Result<Checked> {
        let Some((place, line)) = self.foreign()? else {
            return Ok(Checked(self));
        };
        Err(Error::new(
            "INSTANCE_IN_USE",
            format!(
                "{place} holds {line:?}, which is not the NAT rule of this config; natwg replaces everything in it on start and empties it on stop, so set another role.server.instance or empty it first"
            ),
        ))
    }

    #[cfg(target_os = "macos")]
    fn foreign(&self) -> Result<Option<(String, String)>> {
        let anchor = pf::anchor(&self.instance);
        for rules in ["nat", "rules"] {
            let listing = read(&["pfctl", "-a", &anchor, "-s", rules])?;
            if let Some(line) = pf::foreign(&listing, self) {
                return Ok(Some((format!("the pf anchor {anchor}"), line.to_owned())));
            }
        }
        Ok(None)
    }

    #[cfg(not(target_os = "macos"))]
    fn foreign(&self) -> Result<Option<(String, String)>> {
        let name = self.instance.as_str();
        // `nft list table` fails for a table that does not exist, and a
        // failure must never count as a free table.
        if !nft::listed(&read(&["nft", "list", "tables"])?, &self.instance) {
            return Ok(None);
        }
        let listing = read(&["nft", "list", "table", "inet", name])?;
        let place = format!("the nftables table inet {name}");
        Ok(nft::foreign(&listing, self).map(|line| (place, line.to_owned())))
    }
}

/// A rule whose anchor or table held nothing of anyone else when
/// [`Rule::check`] read it.
#[derive(Debug)]
pub struct Checked(Rule);

impl Checked {
    /// Load the rule. A load that fails removes what it loaded.
    pub fn load(self) -> Result<Nat> {
        let mut nat = Nat {
            down: Teardown::new(down(&self.0.instance)),
        };
        nat.up(&self.0)?;
        Ok(nat)
    }
}

/// The NAT rules of one instance, loaded until [`Nat::stop`] or until the
/// value drops, so a panic in the server removes them too.
pub struct Nat {
    down: Teardown,
}

impl Nat {
    /// Remove the rules. Every step runs, and the first failure is returned.
    pub fn stop(self) -> Result<()> {
        self.down.run()
    }

    #[cfg(target_os = "macos")]
    fn up(&mut self, rule: &Rule) -> Result<()> {
        if let Some(disable) = pf::enable()? {
            self.down.push(disable);
        }
        pf::require_anchor_point()?;
        apply(&pf::up(rule))
    }

    #[cfg(not(target_os = "macos"))]
    fn up(&mut self, rule: &Rule) -> Result<()> {
        apply(&nft::up(rule))
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

/// A network as pfctl and nft print it. Both print the network address, and
/// both leave `/32` off a single host.
fn printed(net: Ipv4Network) -> String {
    match net.prefix() {
        32 => net.ip().to_string(),
        prefix => format!("{}/{prefix}", net.network()),
    }
}
