//! On macOS, NAT is one `nat` rule in the pf anchor `com.apple/<instance>`.
//! The main ruleset that ships with macOS evaluates every `com.apple/*`
//! anchor, so natwg never changes the main ruleset.

use crate::config::Instance;
use crate::netcfg::Step;
use ipnetwork::Ipv4Network;

#[cfg(target_os = "macos")]
use crate::{Error, Result, netcfg::run};

pub fn anchor(instance: &Instance) -> String {
    format!("com.apple/{instance}")
}

/// Load the rule that sends tunnel traffic for `lan` out of `iface` with the
/// address of `iface`, then turn IP forwarding on.
pub fn up(instance: &Instance, iface: &str, tunnel: Ipv4Network, lan: Ipv4Network) -> Vec<Step> {
    let rule = format!("nat on {iface} inet from {tunnel} to {lan} -> ({iface})\n");
    vec![
        Step::new(&["pfctl", "-a", &anchor(instance), "-f", "-"]).stdin(rule),
        Step::new(&["sysctl", "-w", "net.inet.ip.forwarding=1"])
            .done_when(&["sysctl", "-n", "net.inet.ip.forwarding"], "1"),
    ]
}

pub fn down(instance: &Instance) -> Vec<Step> {
    vec![Step::new(&["pfctl", "-a", &anchor(instance), "-F", "all"])]
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
    if run(&argv(["pfctl", "-s", "info"]), None)?
        .stdout
        .contains("Status: Enabled")
    {
        return Ok(None);
    }
    let output = run(&argv(["pfctl", "-E"]), None)?;
    Ok(token(&output.stderr).map(|token| Step::new(&["pfctl", "-X", token])))
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
