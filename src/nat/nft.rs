//! On Linux, NAT is the nftables table `inet <instance>` with one masquerade
//! rule.

use crate::config::Instance;
use crate::netcfg::Step;
use ipnetwork::Ipv4Network;

/// Replace the table with one that masquerades tunnel traffic for `lan` on
/// its way out of `iface`, then turn IP forwarding on.
pub fn up(instance: &Instance, iface: &str, tunnel: Ipv4Network, lan: Ipv4Network) -> Vec<Step> {
    let delete = delete(instance);
    let table = format!(
        "{delete}table inet {instance} {{
	chain postrouting {{
		type nat hook postrouting priority srcnat; policy accept;
		oifname \"{iface}\" ip saddr {tunnel} ip daddr {lan} masquerade
	}}
}}
"
    );
    vec![
        Step::new(&["nft", "-f", "-"]).stdin(table),
        Step::new(&["sysctl", "-w", "net.ipv4.ip_forward=1"]),
    ]
}

pub fn down(instance: &Instance) -> Vec<Step> {
    vec![Step::new(&["nft", "-f", "-"]).stdin(delete(instance))]
}

// `delete table` fails when the table does not exist, so declare it first.
fn delete(instance: &Instance) -> String {
    format!("table inet {instance}\ndelete table inet {instance}\n")
}
