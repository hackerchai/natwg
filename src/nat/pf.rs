//! On macOS, NAT is one `nat` rule in the pf anchor `com.apple/<instance>`.
//! The main ruleset that ships with macOS evaluates every `com.apple/*`
//! anchor, so natwg never changes the main ruleset.

use super::{Rule, printed};
use crate::config::Instance;
use crate::netcfg::Step;

#[cfg(target_os = "macos")]
use crate::{Error, Result, netcfg::run};

pub fn anchor(instance: &Instance) -> String {
    format!("com.apple/{instance}")
}

/// Load the rule into the anchor of its instance, then turn IP forwarding on.
pub fn up(rule: &Rule) -> Vec<Step> {
    vec![
        Step::new(&["pfctl", "-a", &anchor(&rule.instance), "-f", "-"]).stdin(text(rule)),
        forwarding(),
    ]
}

pub fn forwarding() -> Step {
    Step::new(&["sysctl", "-w", "net.inet.ip.forwarding=1"])
        .done_when(&["sysctl", "-n", "net.inet.ip.forwarding"], "1")
}

pub fn down(instance: &Instance) -> Vec<Step> {
    vec![Step::new(&["pfctl", "-a", &anchor(instance), "-F", "all"])]
}

fn text(rule: &Rule) -> String {
    let Rule {
        iface, tunnel, lan, ..
    } = rule;
    let (tunnel, lan) = (printed(*tunnel), printed(*lan));
    format!("nat on {iface} inet from {tunnel} to {lan} -> ({iface})\n")
}

/// The first rule in what `pfctl -s nat` or `pfctl -s rules` prints for an
/// anchor that is not the rule [`up`] loads.
pub fn foreign<'a>(listing: &'a str, rule: &Rule) -> Option<&'a str> {
    let own = text(rule);
    listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .find(|line| !words(line).eq(words(&own)))
}

/// Whether what `pfctl -s nat` prints for an anchor holds the rule [`up`]
/// loads.
pub fn holds(listing: &str, rule: &Rule) -> bool {
    let own = text(rule);
    listing.lines().any(|line| words(line).eq(words(&own)))
}

// pfctl prints `inet` whether or not the loaded rule had it, and it prints
// the `round-robin` that the rule left to the default.
fn words(rule: &str) -> impl Iterator<Item = &str> {
    rule.split_whitespace()
        .filter(|word| !matches!(*word, "inet" | "round-robin"))
}

/// The enable reference that `pfctl -E` prints as `Token : 123`.
pub fn token(output: &str) -> Option<&str> {
    output
        .lines()
        .filter_map(|line| line.strip_prefix("Token"))
        .filter_map(|rest| rest.trim_start().strip_prefix(':'))
        .map(str::trim)
        .find(|token| !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit()))
}

/// Turn pf on when it is off. The returned step gives the enable reference
/// back, so pf goes off again once nothing else holds a reference.
#[cfg(target_os = "macos")]
pub(super) fn enable() -> Result<Option<Step>> {
    if enabled()? {
        return Ok(None);
    }
    let output = run(&argv(["pfctl", "-E"]), None)?;
    Ok(token(&output.stderr).map(|token| Step::new(&["pfctl", "-X", token])))
}

#[cfg(target_os = "macos")]
pub(super) fn enabled() -> Result<bool> {
    let info = run(&argv(["pfctl", "-s", "info"]), None)?;
    Ok(info.stdout.contains("Status: Enabled"))
}

#[cfg(target_os = "macos")]
pub(super) fn require_anchor_point() -> Result<()> {
    const ANCHOR_POINT: &str = r#"nat-anchor "com.apple/*""#;
    if run(&argv(["pfctl", "-s", "nat"]), None)?
        .stdout
        .contains(ANCHOR_POINT)
    {
        return Ok(());
    }
    Err(Error::new(
        "NAT_UNAVAILABLE",
        format!(
            "the main pf ruleset has no {ANCHOR_POINT}; natwg loads its rule into an anchor below that point and never changes the main ruleset, which /etc/pf.conf defines"
        ),
    ))
}

#[cfg(target_os = "macos")]
fn argv<const N: usize>(argv: [&str; N]) -> Vec<String> {
    argv.map(str::to_owned).to_vec()
}
