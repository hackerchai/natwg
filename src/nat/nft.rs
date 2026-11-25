//! On Linux, NAT is the nftables table `inet <instance>` with one masquerade
//! rule per LAN.

use super::{Rule, printed};
use crate::config::Instance;
use crate::netcfg::Step;

/// Replace the table of the instance with one that holds the rules, then
/// turn IP forwarding on.
pub fn up(rule: &Rule) -> Vec<Step> {
    let load = format!("{}{}", delete(&rule.instance), table(rule));
    vec![Step::new(&["nft", "-f", "-"]).stdin(load), forwarding()]
}

pub fn forwarding() -> Step {
    // `sysctl -w` exits 0 when /proc/sys is read-only, as in a container.
    Step::new(&["sysctl", "-w", "net.ipv4.ip_forward=1"])
        .done_when(&["sysctl", "-n", "net.ipv4.ip_forward"], "1")
}

pub fn down(instance: &Instance) -> Vec<Step> {
    vec![Step::new(&["nft", "-f", "-"]).stdin(delete(instance))]
}

// `delete table` fails when the table does not exist, so declare it first.
fn delete(instance: &Instance) -> String {
    format!("table inet {instance}\ndelete table inet {instance}\n")
}

// Each line reads as `nft list table` prints it, so `foreign` compares lines.
pub(crate) fn table(rule: &Rule) -> String {
    let Rule {
        instance,
        iface,
        tunnel,
        lans,
    } = rule;
    let tunnel = printed(*tunnel);
    let masquerade: String = lans
        .iter()
        .map(|lan| {
            let lan = printed(*lan);
            format!("\t\toifname \"{iface}\" ip saddr {tunnel} ip daddr {lan} masquerade\n")
        })
        .collect();
    format!(
        "table inet {instance} {{
	chain postrouting {{
		type nat hook postrouting priority srcnat; policy accept;
{masquerade}	}}
}}
"
    )
}

/// Whether `nft list tables` lists the table of the instance.
pub fn listed(tables: &str, instance: &Instance) -> bool {
    tables.lines().any(|line| {
        line.split_whitespace()
            .eq(["table", "inet", instance.as_str()])
    })
}

/// Whether what `nft list table` prints holds every line of the table [`up`]
/// loads.
pub fn holds(listing: &str, rule: &Rule) -> bool {
    let printed: Vec<&str> = listing.lines().map(str::trim).collect();
    table(rule)
        .lines()
        .all(|line| printed.contains(&line.trim()))
}

/// The first line of what `nft list table` prints that is not a line of the
/// table [`up`] loads. An empty table has no such line.
pub fn foreign<'a>(listing: &'a str, rule: &Rule) -> Option<&'a str> {
    let own = table(rule);
    listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .find(|line| !own.lines().any(|loaded| loaded.trim() == *line))
}
