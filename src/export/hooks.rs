//! Standalone wg-quick hooks for the platform that exports the server.
use crate::{config::ServerConfig, nat::Rule};
use ipnetwork::Ipv4Network;
use std::fmt::Write as _;

pub(super) fn firewall(server: &ServerConfig, subnet: Ipv4Network) -> String {
    let mut hooks = String::new();
    #[cfg(target_os = "macos")]
    let forwarding = "net.inet.ip.forwarding";
    #[cfg(not(target_os = "macos"))]
    let forwarding = "net.ipv4.ip_forward";
    let enable = format!(r#"sysctl -w {forwarding}=1 && test "$(sysctl -n {forwarding})" = 1"#);
    if let Some(rule) = Rule::new(&server.instance, &server.iface, subnet, &server.lan) {
        nat_hooks(&mut hooks, server, &rule, &enable);
    } else {
        hook(&mut hooks, "PostUp", &enable);
    }
    hooks
}

// Each wg-quick hook must fit on one line. Rules only interpolate validated
// interface and instance names and IPv4 prefixes, none of which contain '.
fn hook(text: &mut String, phase: &str, script: &str) {
    let lines: Vec<_> = script.trim().lines().map(str::trim).collect();
    writeln!(text, "{phase} = {}", lines.join(" ")).unwrap();
}

fn rule_input(rules: &str) -> String {
    let lines: Vec<_> = rules.lines().map(|line| format!("'{line}'")).collect();
    format!("printf '%s\\n' {}", lines.join(" "))
}

#[cfg(not(target_os = "macos"))]
fn nat_hooks(text: &mut String, server: &ServerConfig, rule: &Rule, enable: &str) {
    let table = format!("natwg_wgquick_{}", server.instance);
    let rules = crate::nat::nft::table(rule, &table);
    // Exclusive create and installation of all rules are one nft transaction.
    let create = rule_input(&format!("create table inet {table}\n{rules}"));
    let expected = rule_input(&rules);
    let remove = format!(
        r#"current=$(nft list table inet {table}) && [[ "$current" = "$({expected})" ]] && nft delete table inet {table} || {{ echo 'Refusing to remove changed nftables table inet {table}' >&2; exit 1; }}"#
    );
    hook(text, "PostUp", &format!("{create} | nft -f -"));
    hook(
        text,
        "PostUp",
        &format!("{enable} || {{ {remove}; exit 1; }}"),
    );
    hook(text, "PostDown", &remove);
}

#[cfg(target_os = "macos")]
fn nat_hooks(text: &mut String, server: &ServerConfig, rule: &Rule, enable: &str) {
    let anchor = crate::nat::pf::anchor(&server.instance);
    let input = rule_input(&crate::nat::pf::text(rule));
    let state = format!("/var/run/natwg-wg-quick-{}", server.instance);
    hook(
        text,
        "PostUp",
        r#"pfctl -s nat | grep -E '^nat-anchor "com\.apple/\*"( all)?$' >/dev/null || { echo 'Missing com.apple/* NAT anchor point in the main PF ruleset' >&2; exit 1; }"#,
    );
    // Reserve the anchor between wg-quick instances. Take a PF enable
    // reference, return it on error, and load only the NAT rules (-N).
    hook(
        text,
        "PostUp",
        &format!(
            r#"
        (set -e -o pipefail; umask 077; mkdir {state};
        trap 'rm -f {state}/token; rmdir {state}' EXIT;
        current=$(pfctl -a {anchor} -s nat);
        [[ -z "$current" ]] || {{ echo 'PF anchor {anchor} already holds NAT rules' >&2; exit 1; }};
        pfctl -E 2>&1 | awk '/^Token[[:space:]]*:/ {{print $NF}}' > {state}/token;
        read -r token < {state}/token; [[ $token =~ ^[0-9]+$ ]];
        trap 'pfctl -X "$token"; rm -f {state}/token; rmdir {state}' EXIT;
        {input} | pfctl -a {anchor} -N -f -;
        trap 'pfctl -a {anchor} -F nat; pfctl -X "$token"; rm -f {state}/token; rmdir {state}' EXIT;
        {enable} || exit 1;
        trap - EXIT)
    "#
        ),
    );
    // pfctl may print the implicit inet and round-robin defaults.
    let normalize = "sed -E 's/ inet / /; s/ round-robin$//'";
    hook(
        text,
        "PostDown",
        &format!(
            r#"
        read -r token < {state}/token && [[ $token =~ ^[0-9]+$ ]] &&
        current=$(pfctl -a {anchor} -s nat | {normalize}) &&
        [[ "$current" = "$({input} | {normalize})" ]] &&
        pfctl -a {anchor} -F nat &&
        pfctl -X "$token" && rm {state}/token && rmdir {state} ||
        {{ echo 'Check PF anchor {anchor} and its enable reference in {state}' >&2; exit 1; }}
    "#
        ),
    );
}
