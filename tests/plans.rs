use ipnetwork::Ipv4Network;
use natwg::config::Instance;
use natwg::nat::{Rule, nft, pf};
use natwg::netcfg::{self, Step, Teardown};
use std::fs;

fn argv(line: &str) -> Vec<String> {
    line.split(' ').map(str::to_owned).collect()
}

fn net(text: &str) -> Ipv4Network {
    text.parse().unwrap()
}

fn instance(name: &str) -> Instance {
    name.parse().unwrap()
}

fn commands(plan: &[Step]) -> Vec<String> {
    plan.iter().map(|step| step.argv.join(" ")).collect()
}

fn rule(instance_name: &str, iface: &str, tunnel: &str, lan: &str) -> Rule {
    lans_rule(instance_name, iface, tunnel, &[lan]).expect("a rule for one LAN")
}

fn lans_rule(instance_name: &str, iface: &str, tunnel: &str, lans: &[&str]) -> Option<Rule> {
    let lans: Vec<Ipv4Network> = lans.iter().map(|lan| net(lan)).collect();
    Rule::new(&instance(instance_name), iface, net(tunnel), &lans)
}

fn mac_lans_rule() -> Rule {
    let lans = ["10.73.0.0/24", "192.168.50.0/24", "172.20.0.0/16"];
    lans_rule("natwg_next", "en6", "10.66.67.0/24", &lans).unwrap()
}

fn linux_lans_rule() -> Rule {
    let lans = ["192.168.139.0/24", "10.30.0.0/16"];
    lans_rule("natwg_next", "eth0", "10.66.67.0/24", &lans).unwrap()
}

fn mac_rule() -> Rule {
    rule("natwg_next", "en6", "10.66.67.0/24", "10.73.0.0/24")
}

fn linux_rule() -> Rule {
    rule("natwg_next", "eth0", "10.66.67.0/24", "192.168.139.0/24")
}

#[test]
fn macos_sets_the_address_then_routes_the_subnet_through_the_utun() {
    let plan = netcfg::macos::plan(
        "utun12",
        net("10.66.67.1/24"),
        1380,
        &[net("10.66.67.0/24")],
    );
    assert_eq!(plan.len(), 2);
    assert_eq!(
        plan[0],
        Step::new(&[
            "ifconfig",
            "utun12",
            "inet",
            "10.66.67.1",
            "10.66.67.1",
            "netmask",
            "255.255.255.0",
            "mtu",
            "1380",
            "up"
        ])
    );
    assert_eq!(
        plan[1].argv,
        argv("route -q -n add -inet 10.66.67.0/24 -interface utun12")
    );
    assert_eq!(plan[1].stdin, None);
    let check = plan[1].done_when.as_ref().expect("the route has a check");
    assert_eq!(check.argv, argv("route -n get -inet 10.66.67.0/24"));
    assert_eq!(check.expect, "interface: utun12\n");
}

#[test]
fn a_route_written_with_host_bits_is_routed_as_its_network() {
    let routes = [net("10.73.0.7/24"), net("192.168.50.9/32")];
    assert_eq!(
        commands(&netcfg::macos::plan(
            "utun3",
            net("10.66.66.2/32"),
            1420,
            &routes
        )),
        [
            "ifconfig utun3 inet 10.66.66.2 10.66.66.2 netmask 255.255.255.255 mtu 1420 up",
            "route -q -n add -inet 10.73.0.0/24 -interface utun3",
            "route -q -n add -inet 192.168.50.9/32 -interface utun3",
        ]
    );
    assert_eq!(
        commands(&netcfg::linux::plan(
            "natwg",
            net("10.66.66.2/32"),
            1420,
            &routes
        )),
        [
            "ip addr replace 10.66.66.2/32 dev natwg",
            "ip link set dev natwg mtu 1420 up",
            "ip route replace 10.73.0.0/24 dev natwg",
            "ip route replace 192.168.50.9/32 dev natwg",
        ]
    );
}

#[test]
fn linux_leaves_the_route_for_the_address_subnet_to_the_kernel() {
    let plan = netcfg::linux::plan(
        "natwg_next",
        net("10.66.67.1/24"),
        1380,
        &[net("10.66.67.0/24")],
    );
    assert_eq!(
        plan,
        [
            Step::new(&[
                "ip",
                "addr",
                "replace",
                "10.66.67.1/24",
                "dev",
                "natwg_next"
            ]),
            Step::new(&[
                "ip",
                "link",
                "set",
                "dev",
                "natwg_next",
                "mtu",
                "1380",
                "up"
            ]),
        ]
    );
}

#[test]
fn a_route_for_the_tunnel_subnet_that_leaves_through_another_device_is_found() {
    fn foreign(listing: &str) -> Option<&str> {
        netcfg::linux::foreign_route(listing, "natwg_fix")
    }
    let own = "10.66.70.0/24 dev natwg_fix proto kernel scope link src 10.66.70.1 \n";
    assert_eq!(foreign(""), None);
    assert_eq!(foreign(own), None);
    for other in [
        "10.66.70.0/24 dev dmy70 scope link",
        "10.66.70.0/24 dev natwg_fix2 scope link",
        "10.66.70.0/24 via 192.168.139.1 dev eth0",
        "blackhole 10.66.70.0/24",
    ] {
        assert_eq!(foreign(&format!("{other} \n")), Some(other));
        assert_eq!(foreign(&format!("{own}{other} \n")), Some(other));
    }
}

// `netstat -rn -f inet` on a Mac where Surge owns the default route
// through utun8, the live tunnel is utun11, and `wg-quick down` left utun12
// behind.
const MAC_ROUTES: &str = "Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            link#39            UCSg                utun8
default            10.73.0.1          UGScIg                en6
10.24/24           link#32            UCS                   en6      !
10.66.66.1         10.66.66.1         UH                 utun11
10.66.66.2/32      utun11             USc                utun11
10.66.75.1         10.66.75.1         UH                 utun12
10.66.75.2/32      utun12             USc                utun12
10.66.76.2         link#39            UHWIig              utun8
10.66.78/24        utun13             USc                utun13
127                127.0.0.1          UCS                   lo0
198.18.0.1         198.18.0.1         UH                  utun8
";

#[test]
fn a_route_through_a_utun_within_the_allowed_ips_of_a_peer_is_found() {
    let found = |allowed: &[&str]| {
        let allowed: Vec<_> = allowed.iter().map(|text| net(text)).collect();
        netcfg::macos::utun_route_within(MAC_ROUTES, &allowed)
            .map(|(route, utun, within)| format!("{route} through {utun} within {within}"))
    };
    let found_as = |route: &str, utun: &str, within: &str| {
        Some(format!("{route} through {utun} within {within}"))
    };
    assert_eq!(
        found(&["10.66.75.2/32"]),
        found_as("10.66.75.2/32", "utun12", "10.66.75.2/32")
    );
    assert_eq!(
        found(&["10.66.77.0/24", "10.66.75.0/24"]),
        found_as("10.66.75.1/32", "utun12", "10.66.75.0/24"),
        "a host route counts"
    );
    assert_eq!(
        found(&["10.66.78.0/23"]),
        found_as("10.66.78.0/24", "utun13", "10.66.78.0/23"),
        "netstat leaves the zero octets off a network"
    );
    for free in [
        "10.66.76.2/32",
        "10.66.78.5/32",
        "10.73.0.0/24",
        "127.0.0.1/32",
    ] {
        assert_eq!(
            found(&[free]),
            None,
            "{free}: a cloned route, a wider route and a route through another interface do not count"
        );
    }
}

#[test]
fn apply_runs_the_steps_in_order_and_stops_at_the_first_failure() {
    let dir = tempfile::tempdir().unwrap();
    let file = |name: &str| dir.path().join(name).display().to_string();
    let (first, second, third) = (file("first"), file("second"), file("third"));
    let error = netcfg::apply(&[
        Step::new(&["tee", &first]).stdin("one\n"),
        Step::new(&["cp", &first, &second]),
        Step::new(&["false"]),
        Step::new(&["touch", &third]),
    ])
    .unwrap_err();
    assert_eq!(error.code, "COMMAND_FAILED");
    assert!(error.message.contains("`false`"), "{}", error.message);
    assert_eq!(fs::read_to_string(&second).unwrap(), "one\n");
    assert!(!dir.path().join("third").exists());
}

#[test]
fn apply_skips_a_step_whose_check_already_holds() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker").display().to_string();
    let listing = dir.path().display().to_string();
    let append = Step::new(&["tee", "-a", &marker])
        .stdin("ran\n")
        .done_when(&["ls", &listing], "marker");
    netcfg::apply(std::slice::from_ref(&append)).unwrap();
    netcfg::apply(std::slice::from_ref(&append)).unwrap();
    assert_eq!(fs::read_to_string(&marker).unwrap(), "ran\n");
}

#[test]
fn apply_fails_when_a_command_exits_0_without_its_effect_and_quotes_its_output() {
    let no_effect = Step::new(&["echo", "File exists"]).done_when(&["echo", "absent"], "present");
    let error = netcfg::apply(&[no_effect]).unwrap_err();
    assert_eq!(error.code, "COMMAND_NO_EFFECT");
    assert!(error.message.contains("File exists"), "{}", error.message);
}

#[test]
fn a_check_that_fails_counts_as_missing_state() {
    let dir = tempfile::tempdir().unwrap();
    let made = dir.path().join("made");
    let path = made.display().to_string();
    netcfg::apply(&[Step::new(&["mkdir", &path]).done_when(&["ls", "-d", &path], "made")]).unwrap();
    assert!(made.is_dir());
}

#[test]
fn a_command_that_cannot_start_names_itself() {
    let error = netcfg::apply(&[Step::new(&["natwg-no-such-command", "--flag"])]).unwrap_err();
    assert_eq!(error.code, "COMMAND_FAILED");
    assert!(
        error.message.contains("natwg-no-such-command --flag"),
        "{}",
        error.message
    );
}

#[test]
fn commands_run_with_the_system_path_and_without_the_callers_environment() {
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    let output = netcfg::run(&argv("env"), None).unwrap();
    let variables: Vec<&str> = output.stdout.lines().collect();
    assert!(
        variables.contains(&"PATH=/usr/sbin:/usr/bin:/sbin:/bin"),
        "{variables:?}"
    );
    assert!(
        !variables
            .iter()
            .any(|variable| variable.starts_with("CARGO_")),
        "{variables:?}"
    );
}

#[test]
fn a_teardown_runs_every_step_and_returns_the_first_failure() {
    let dir = tempfile::tempdir().unwrap();
    let after = dir.path().join("after").display().to_string();
    let teardown = Teardown::new(vec![
        Step::new(&["false"]),
        Step::new(&["touch", &after]),
        Step::new(&["natwg-no-such-command"]),
    ]);
    let error = teardown.run().unwrap_err();
    assert!(error.message.contains("`false`"), "{}", error.message);
    assert!(dir.path().join("after").exists());
}

#[test]
fn a_teardown_runs_its_steps_when_a_panic_unwinds_past_it() {
    let dir = tempfile::tempdir().unwrap();
    let undone = dir.path().join("undone");
    let path = undone.display().to_string();
    let panicked = std::panic::catch_unwind(|| {
        let mut teardown = Teardown::new(vec![]);
        teardown.push(Step::new(&["touch", &path]));
        panic!("the server panics with its plan applied");
    });
    assert!(panicked.is_err());
    assert!(undone.exists());
}

#[test]
fn a_teardown_that_ran_does_not_run_again_when_it_drops() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log");
    let path = log.display().to_string();
    let teardown = Teardown::new(vec![Step::new(&["tee", "-a", &path]).stdin("ran\n")]);
    teardown.run().unwrap();
    assert_eq!(fs::read_to_string(&log).unwrap(), "ran\n");
}

#[test]
fn pf_loads_one_nat_rule_into_the_instance_anchor_and_turns_forwarding_on() {
    assert_eq!(
        pf::up(&mac_rule()),
        [
            Step::new(&["pfctl", "-a", "com.apple/natwg_next", "-f", "-"])
                .stdin("nat on en6 inet from 10.66.67.0/24 to 10.73.0.0/24 -> (en6)\n"),
            Step::new(&["sysctl", "-w", "net.inet.ip.forwarding=1"])
                .done_when(&["sysctl", "-n", "net.inet.ip.forwarding"], "1"),
        ]
    );
}

#[test]
fn the_default_instance_loads_the_rule_and_anchor_of_the_python_daemon() {
    let plan = pf::up(&rule("natwg", "en6", "10.66.66.0/24", "10.73.0.0/24"));
    assert_eq!(instance("natwg"), Instance::default());
    assert_eq!(plan[0].argv, argv("pfctl -a com.apple/natwg -f -"));
    assert_eq!(
        plan[0].stdin.as_deref(),
        Some("nat on en6 inet from 10.66.66.0/24 to 10.73.0.0/24 -> (en6)\n")
    );
}

#[test]
fn pf_stop_flushes_only_the_instance_anchor() {
    assert_eq!(
        pf::down(&instance("natwg_next")),
        [Step::new(&[
            "pfctl",
            "-a",
            "com.apple/natwg_next",
            "-F",
            "all"
        ])]
    );
}

#[test]
fn the_pf_enable_token_is_read_from_the_output_of_pfctl() {
    let enabled = "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 18446743524195463560\n";
    assert_eq!(pf::token(enabled), Some("18446743524195463560"));
    assert_eq!(pf::token("Token: 7\n"), Some("7"));
    for output in ["", "pf enabled\n", "Token : \n", "Token : pf enabled\n"] {
        assert_eq!(pf::token(output), None, "{output:?}");
    }
}

#[test]
fn nft_replaces_the_instance_table_with_one_masquerade_rule_and_checks_forwarding() {
    let table = "table inet natwg_next
delete table inet natwg_next
table inet natwg_next {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname \"eth0\" ip saddr 10.66.67.0/24 ip daddr 192.168.139.0/24 masquerade
	}
}
";
    assert_eq!(
        nft::up(&linux_rule()),
        [
            Step::new(&["nft", "-f", "-"]).stdin(table),
            Step::new(&["sysctl", "-w", "net.ipv4.ip_forward=1"])
                .done_when(&["sysctl", "-n", "net.ipv4.ip_forward"], "1"),
        ]
    );
}

#[test]
fn nft_stop_deletes_the_instance_table_even_when_it_is_already_gone() {
    assert_eq!(
        nft::down(&instance("natwg_next")),
        [Step::new(&["nft", "-f", "-"])
            .stdin("table inet natwg_next\ndelete table inet natwg_next\n")]
    );
}

// What `pfctl -a com.apple/natwg -s nat` printed on the home server while the
// Python daemon ran.
const PYTHON_RULE: &str =
    "nat on en6 inet from 10.66.66.0/24 to 10.73.0.0/24 -> (en6) round-robin\n";

#[test]
fn an_anchor_that_is_empty_or_holds_only_the_rule_of_this_config_is_free() {
    let own = mac_rule();
    let printed = "nat on en6 inet from 10.66.67.0/24 to 10.73.0.0/24 -> (en6) round-robin\n";
    for listing in [
        "",
        "\n",
        printed,
        "nat on en6 from 10.66.67.0/24 to 10.73.0.0/24 -> (en6)\n",
        &printed.repeat(2),
    ] {
        assert_eq!(pf::foreign(listing, &own), None, "{listing:?}");
    }
    let python = rule("natwg", "en6", "10.66.66.0/24", "10.73.0.0/24");
    assert_eq!(pf::foreign(PYTHON_RULE, &python), None);
}

#[test]
fn an_anchor_holds_the_rule_only_when_pfctl_prints_it() {
    let own = mac_rule();
    let printed = "nat on en6 inet from 10.66.67.0/24 to 10.73.0.0/24 -> (en6) round-robin\n";
    assert!(pf::holds(printed, &own));
    assert!(pf::holds(&format!("\n{printed}"), &own));
    for listing in ["", "\n", PYTHON_RULE] {
        assert!(!pf::holds(listing, &own), "{listing:?}");
    }
}

#[test]
fn an_anchor_with_any_other_rule_is_in_use_and_the_rule_is_named() {
    let own = mac_rule();
    for other in [
        PYTHON_RULE.trim(),
        "nat on en0 inet from 10.66.67.0/24 to 10.73.0.0/24 -> (en0) round-robin",
        "nat on en6 inet from 10.66.67.0/24 to 10.73.1.0/24 -> (en6) round-robin",
        "nat on en6 inet from 10.66.67.0/24 to any -> (en6) round-robin",
        "nat on en6 inet6 from 10.66.67.0/24 to 10.73.0.0/24 -> (en6) round-robin",
        "rdr on en6 inet proto tcp from 10.66.67.0/24 to any port = 8080 -> 127.0.0.1 port 80",
        "pass in quick on en6 inet from 10.66.67.0/24 to any flags S/SA keep state",
    ] {
        assert_eq!(pf::foreign(other, &own), Some(other), "{other}");
        let after_the_own_rule = format!(
            "nat on en6 inet from 10.66.67.0/24 to 10.73.0.0/24 -> (en6) round-robin\n{other}\n"
        );
        assert_eq!(pf::foreign(&after_the_own_rule, &own), Some(other));
    }
}

#[test]
fn rules_are_written_the_way_pfctl_and_nft_print_a_host_and_a_network() {
    let host_bits = rule("natwg_next", "en6", "10.66.67.1/24", "10.73.0.7/24");
    assert_eq!(pf::up(&host_bits), pf::up(&mac_rule()));

    let hosts = rule("natwg_next", "en6", "10.66.67.1/32", "10.73.0.7/32");
    let printed = "nat on en6 inet from 10.66.67.1 to 10.73.0.7 -> (en6) round-robin\n";
    assert_eq!(pf::foreign(printed, &hosts), None);
    let printed = "table inet natwg_next {
\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\toifname \"en6\" ip saddr 10.66.67.1 ip daddr 10.73.0.7 masquerade
\t}
}
";
    assert_eq!(nft::foreign(printed, &hosts), None);
}

// What `nft list table inet natwg_next` printed in the VM while natwg ran.
const OWN_TABLE: &str = "table inet natwg_next {
\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\toifname \"eth0\" ip saddr 10.66.67.0/24 ip daddr 192.168.139.0/24 masquerade
\t}
}
";

#[test]
fn a_table_that_is_empty_or_holds_only_the_rule_of_this_config_is_free() {
    for listing in ["", "table inet natwg_next {\n}\n", OWN_TABLE] {
        assert_eq!(nft::foreign(listing, &linux_rule()), None, "{listing:?}");
    }
}

#[test]
fn a_table_holds_the_rule_only_when_nft_prints_all_of_it() {
    assert!(nft::holds(OWN_TABLE, &linux_rule()));
    let other_subnet = rule("natwg_next", "eth0", "10.66.68.0/24", "192.168.139.0/24");
    let without_rule = OWN_TABLE.replace(
        "\t\toifname \"eth0\" ip saddr 10.66.67.0/24 ip daddr 192.168.139.0/24 masquerade\n",
        "",
    );
    for (listing, rule) in [
        ("", linux_rule()),
        ("table inet natwg_next {\n}\n", linux_rule()),
        (without_rule.as_str(), linux_rule()),
        (OWN_TABLE, other_subnet),
    ] {
        assert!(!nft::holds(listing, &rule), "{listing:?}");
    }
}

#[test]
fn a_table_with_any_other_line_is_in_use_and_the_line_is_named() {
    let marker = "counter comment \"someone else\"";
    let with_marker = OWN_TABLE.replace("\t\toifname", &format!("\t\t{marker}\n\t\toifname"));
    assert_eq!(nft::foreign(&with_marker, &linux_rule()), Some(marker));

    let other_subnet = rule("natwg_next", "eth0", "10.66.68.0/24", "192.168.139.0/24");
    assert_eq!(
        nft::foreign(OWN_TABLE, &other_subnet),
        Some("oifname \"eth0\" ip saddr 10.66.67.0/24 ip daddr 192.168.139.0/24 masquerade")
    );

    let firewall = "table inet natwg_next {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t}
}
";
    assert_eq!(nft::foreign(firewall, &linux_rule()), Some("chain input {"));
}

#[test]
fn only_an_inet_table_with_the_exact_instance_name_is_listed() {
    let next = instance("natwg_next");
    assert!(nft::listed(
        "table ip filter\ntable inet natwg_next\n",
        &next
    ));
    for tables in [
        "",
        "table ip natwg_next\n",
        "table inet natwg_next2\n",
        "table inet natwg\n",
    ] {
        assert!(!nft::listed(tables, &next), "{tables:?}");
    }
}

#[test]
fn a_client_leaves_out_the_lan_it_sits_on() {
    let routes: Vec<ipnetwork::Ipv4Network> = ["10.66.66.0/24", "10.73.0.0/24"]
        .iter()
        .map(|net| net.parse().unwrap())
        .collect();
    let at = |name: &str, address: &str| (name.to_owned(), address.parse().unwrap());
    let away = [at("lo0", "127.0.0.1"), at("en0", "192.168.1.20")];
    assert!(netcfg::local_networks(&routes, &away).is_empty());
    let home = [at("en0", "10.73.0.37"), at("utun4", "10.66.66.2")];
    assert_eq!(netcfg::local_networks(&routes, &home), vec![routes[1]]);
    let old_tunnels = [
        at("utun9", "10.73.0.9"),
        at("wg-home", "10.66.66.2"),
        at("natwg-client", "10.66.66.2"),
    ];
    assert!(netcfg::local_networks(&routes, &old_tunnels).is_empty());
}

#[test]
fn a_server_without_a_lan_has_no_nat_rule() {
    assert_eq!(lans_rule("natwg_next", "en6", "10.66.67.0/24", &[]), None);
}

// One rule per LAN, in the order of role.server.lan, as pfctl lists them.
const MAC_LANS: &str = "nat on en6 inet from 10.66.67.0/24 to 10.73.0.0/24 -> (en6)
nat on en6 inet from 10.66.67.0/24 to 192.168.50.0/24 -> (en6)
nat on en6 inet from 10.66.67.0/24 to 172.20.0.0/16 -> (en6)
";

#[test]
fn pf_loads_one_nat_rule_per_lan_into_the_instance_anchor() {
    assert_eq!(
        pf::up(&mac_lans_rule()),
        [
            Step::new(&["pfctl", "-a", "com.apple/natwg_next", "-f", "-"]).stdin(MAC_LANS),
            Step::new(&["sysctl", "-w", "net.inet.ip.forwarding=1"])
                .done_when(&["sysctl", "-n", "net.inet.ip.forwarding"], "1"),
        ]
    );
    assert_eq!(
        pf::down(&instance("natwg_next")),
        [Step::new(&[
            "pfctl",
            "-a",
            "com.apple/natwg_next",
            "-F",
            "all"
        ])],
        "stop still flushes the whole anchor"
    );
}

#[test]
fn an_anchor_holds_the_rules_of_several_lans_only_when_pfctl_prints_each() {
    let own = mac_lans_rule();
    let printed = MAC_LANS.replace(" -> (en6)\n", " -> (en6) round-robin\n");
    assert!(pf::holds(&printed, &own));
    let reordered: String = printed
        .lines()
        .rev()
        .map(|line| format!("{line}\n"))
        .collect();
    assert!(pf::holds(&reordered, &own), "the order does not matter");
    assert_eq!(pf::foreign(&printed, &own), None);
    assert_eq!(pf::foreign("", &own), None);

    let partial: String = printed
        .lines()
        .take(2)
        .map(|line| format!("{line}\n"))
        .collect();
    assert!(
        !pf::holds(&partial, &own),
        "a missing LAN rule is not in effect"
    );
    assert_eq!(
        pf::foreign(&partial, &own),
        None,
        "a partial load is still natwg's own"
    );

    let dropped = "nat on en6 inet from 10.66.67.0/24 to 10.99.0.0/24 -> (en6) round-robin";
    let stale = format!("{printed}{dropped}\n");
    assert_eq!(
        pf::foreign(&stale, &own),
        Some(dropped),
        "a rule for a LAN the config no longer lists is someone else's"
    );
}

const LINUX_LANS: &str = "table inet natwg_next {
\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\toifname \"eth0\" ip saddr 10.66.67.0/24 ip daddr 192.168.139.0/24 masquerade
\t\toifname \"eth0\" ip saddr 10.66.67.0/24 ip daddr 10.30.0.0/16 masquerade
\t}
}
";

#[test]
fn nft_loads_one_masquerade_rule_per_lan_into_the_instance_table() {
    let load = format!("table inet natwg_next\ndelete table inet natwg_next\n{LINUX_LANS}");
    assert_eq!(
        nft::up(&linux_lans_rule()),
        [
            Step::new(&["nft", "-f", "-"]).stdin(load),
            Step::new(&["sysctl", "-w", "net.ipv4.ip_forward=1"])
                .done_when(&["sysctl", "-n", "net.ipv4.ip_forward"], "1"),
        ]
    );
}

#[test]
fn a_table_holds_the_rules_of_several_lans_only_when_nft_prints_each() {
    let own = linux_lans_rule();
    assert!(nft::holds(LINUX_LANS, &own));
    assert_eq!(nft::foreign(LINUX_LANS, &own), None);
    let second = "\t\toifname \"eth0\" ip saddr 10.66.67.0/24 ip daddr 10.30.0.0/16 masquerade\n";
    let partial = LINUX_LANS.replace(second, "");
    assert!(!nft::holds(&partial, &own));
    assert_eq!(nft::foreign(&partial, &own), None);
    assert_eq!(
        nft::foreign(LINUX_LANS, &linux_rule()),
        Some("oifname \"eth0\" ip saddr 10.66.67.0/24 ip daddr 10.30.0.0/16 masquerade"),
        "the rule of a LAN the config dropped is someone else's"
    );
}
