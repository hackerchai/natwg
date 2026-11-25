//! Source NAT from the tunnel subnet onto each LAN, so LAN hosts answer
//! tunnel peers without a route back to the tunnel.

pub mod nft;
pub mod pf;

use crate::config::Instance;
use crate::netcfg::{Step, Teardown, apply, read};
use crate::{Error, Result};
use ipnetwork::Ipv4Network;

/// The NAT rule of an instance. Traffic from `tunnel` to each of `lans`
/// leaves through `iface` with the address of `iface`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    instance: Instance,
    iface: String,
    tunnel: Ipv4Network,
    lans: Vec<Ipv4Network>,
}

impl Rule {
    /// The rule for `lans`, or none when there is no LAN, because a server
    /// without a LAN serves the tunnel only.
    pub fn new(
        instance: &Instance,
        iface: &str,
        tunnel: Ipv4Network,
        lans: &[Ipv4Network],
    ) -> Option<Self> {
        if lans.is_empty() {
            return None;
        }
        Some(Self {
            instance: instance.clone(),
            iface: iface.to_owned(),
            tunnel,
            lans: lans.to_vec(),
        })
    }

    /// Refuse an anchor or a table that holds a rule of someone else. Loading
    /// replaces everything in it and stopping empties it, so natwg takes it
    /// only when it is empty or holds this rule already. A server that was
    /// killed leaves this rule behind, and so does the Python daemon that
    /// served the same subnets. The check only reads.
    pub fn check(self) -> Result<Checked> {
        self.listing()?;
        Ok(Checked(self))
    }

    /// What the anchor or the table of the instance holds, which is nothing
    /// or this rule. Anything else is the error of [`Rule::check`].
    fn listing(&self) -> Result<String> {
        let (place, listing) = self.current()?;
        let Some(line) = foreign(&listing, self) else {
            return Ok(listing);
        };
        Err(Error::new(
            "INSTANCE_IN_USE",
            format!(
                "{place} holds {line:?}, which is not the NAT rule of this config; natwg replaces everything in it on start and empties it on stop, so set another role.server.instance or empty it first"
            ),
        ))
    }

    #[cfg(target_os = "macos")]
    fn current(&self) -> Result<(String, String)> {
        let anchor = pf::anchor(&self.instance);
        let mut listing = String::new();
        for rules in ["nat", "rules"] {
            listing += &read(&["pfctl", "-a", &anchor, "-s", rules])?;
        }
        Ok((format!("the pf anchor {anchor}"), listing))
    }

    #[cfg(not(target_os = "macos"))]
    fn current(&self) -> Result<(String, String)> {
        let name = self.instance.as_str();
        let place = format!("the nftables table inet {name}");
        // `nft list table` fails for a table that does not exist, and a
        // failure must never count as a free table.
        if !nft::listed(&read(&["nft", "list", "tables"])?, &self.instance) {
            return Ok((place, String::new()));
        }
        Ok((place, read(&["nft", "list", "table", "inet", name])?))
    }
}

/// Refuse the anchor or the table of `instance` when it holds any rule, for
/// a server that loads none. A server killed while it served a LAN leaves
/// its rule behind, and a server without a LAN would never remove it. The
/// check only reads.
pub fn require_empty(instance: &Instance) -> Result<()> {
    let none = Rule {
        instance: instance.clone(),
        iface: String::new(),
        tunnel: Ipv4Network::from(std::net::Ipv4Addr::UNSPECIFIED),
        lans: Vec::new(),
    };
    none.listing().map(drop)
}

/// Turn IP forwarding on, for a server that loads no NAT rule. Loading a
/// rule turns it on too.
pub fn forward() -> Result<()> {
    apply(&[forwarding()])
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

    /// Load `rule` again when it no longer takes effect, as after someone
    /// flushed its anchor or table, and keep IP forwarding on. A rule of
    /// someone else in its place is refused as [`Rule::check`] refuses it.
    /// Returns whether the rule had to be loaded again.
    pub fn ensure(&mut self, rule: &Rule) -> Result<bool> {
        let missing = !in_effect(&rule.listing()?, rule)?;
        if missing {
            self.up(rule)?;
        } else {
            apply(&[forwarding()])?;
        }
        Ok(missing)
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

#[cfg(target_os = "macos")]
fn foreign<'a>(listing: &'a str, rule: &Rule) -> Option<&'a str> {
    pf::foreign(listing, rule)
}

#[cfg(not(target_os = "macos"))]
fn foreign<'a>(listing: &'a str, rule: &Rule) -> Option<&'a str> {
    nft::foreign(listing, rule)
}

// pf applies no rule while it is disabled.
#[cfg(target_os = "macos")]
fn in_effect(listing: &str, rule: &Rule) -> Result<bool> {
    Ok(pf::holds(listing, rule) && pf::enabled()?)
}

#[cfg(not(target_os = "macos"))]
fn in_effect(listing: &str, rule: &Rule) -> Result<bool> {
    Ok(nft::holds(listing, rule))
}

#[cfg(target_os = "macos")]
fn forwarding() -> Step {
    pf::forwarding()
}

#[cfg(not(target_os = "macos"))]
fn forwarding() -> Step {
    nft::forwarding()
}

/// A network as pfctl and nft print it. Both print the network address, and
/// both leave `/32` off a single host.
fn printed(net: Ipv4Network) -> String {
    match net.prefix() {
        32 => net.ip().to_string(),
        prefix => format!("{}/{prefix}", net.network()),
    }
}
