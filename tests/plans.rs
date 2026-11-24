use ipnetwork::Ipv4Network;
use natwg::config::Instance;
use natwg::nat::{nft, pf};
use natwg::netcfg::{self, Step};
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
    let routes = [net("10.24.0.7/24"), net("192.168.50.9/32")];
    assert_eq!(
        commands(&netcfg::macos::plan(
            "utun3",
            net("10.66.66.2/32"),
            1420,
            &routes
        )),
        [
            "ifconfig utun3 inet 10.66.66.2 10.66.66.2 netmask 255.255.255.255 mtu 1420 up",
            "route -q -n add -inet 10.24.0.0/24 -interface utun3",
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
            "ip route replace 10.24.0.0/24 dev natwg",
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
fn pf_loads_one_nat_rule_into_the_instance_anchor_and_turns_forwarding_on() {
    let plan = pf::up(
        &instance("natwg_next"),
        "en6",
        net("10.66.67.0/24"),
        net("10.24.0.0/24"),
    );
    assert_eq!(
        plan,
        [
            Step::new(&["pfctl", "-a", "com.apple/natwg_next", "-f", "-"])
                .stdin("nat on en6 inet from 10.66.67.0/24 to 10.24.0.0/24 -> (en6)\n"),
            Step::new(&["sysctl", "-w", "net.inet.ip.forwarding=1"])
                .done_when(&["sysctl", "-n", "net.inet.ip.forwarding"], "1"),
        ]
    );
}

#[test]
fn the_default_instance_loads_the_rule_and_anchor_of_the_python_daemon() {
    let plan = pf::up(
        &Instance::default(),
        "en6",
        net("10.66.66.0/24"),
        net("10.24.0.0/24"),
    );
    assert_eq!(plan[0].argv, argv("pfctl -a com.apple/natwg -f -"));
    assert_eq!(
        plan[0].stdin.as_deref(),
        Some("nat on en6 inet from 10.66.66.0/24 to 10.24.0.0/24 -> (en6)\n")
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
fn nft_replaces_the_instance_table_with_one_masquerade_rule() {
    let plan = nft::up(
        &instance("natwg_next"),
        "eth0",
        net("10.66.67.0/24"),
        net("192.168.139.0/24"),
    );
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
        plan,
        [
            Step::new(&["nft", "-f", "-"]).stdin(table),
            Step::new(&["sysctl", "-w", "net.ipv4.ip_forward=1"]),
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
