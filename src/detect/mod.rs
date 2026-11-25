//! `natwg detect`: can this network host a natwg server? natwg needs a UDP
//! endpoint that a client whose address is unknown in advance can reach:
//! a public address that keeps the listen port, or a full-cone NAT (NAT1).
//!
//! One socket on the uplink runs every test, the way the server's one socket
//! carries STUN and WireGuard:
//! 1. On a private uplink with `--upnp auto`, the UPnP gateway forwards the
//!    test port for the test, as it would for the server, and the lease goes
//!    afterwards.
//! 2. Filtering (RFC 5780): an RFC 5780 STUN server answers a CHANGE-REQUEST
//!    from its other IP and port, then from its other port. These run before
//!    the socket sends anywhere else, since sending to an address opens a
//!    filtering NAT to it.
//! 3. Mapping: that server's other IP and more servers report the public
//!    address and port of the socket. Two answers that differ mean an
//!    endpoint-dependent mapping.
//! 4. Self test: a second socket sends to the mapping, and the first waits.

pub mod classify;

pub use classify::{
    Answer, Assessment, ChangeTest, Filtering, Kind, Mapping, Observations, Probe, PublicBy,
    SelfTest, Verdict, classify, is_public,
};

use crate::client::uplink;
use crate::server::upnp::{self, Gateway, Igd};
use crate::wire::dns::{self, Record, RecordKind};
use crate::wire::stun::{self, BindingResponse, Change, TransactionId};
use crate::wire::transport::{BoundInterface, bound_udp_socket};
use crate::{Error, Result};
use serde::Serialize;
use std::{
    fmt::Write as _,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    signal::unix::{Signal, SignalKind, signal},
    task::JoinSet,
    time::Instant,
};

/// The version of the JSON that `natwg detect --json` prints. It changes
/// only when a field changes meaning or goes away.
pub const SCHEMA: u32 = 1;
/// The exit status of `natwg detect` when it fails before a verdict.
pub const ERROR_EXIT: i32 = 3;
/// The port natwg tests when neither `--port` nor a config names one.
pub const DEFAULT_PORT: u16 = 51830;
/// The DNS server asked for STUN hosts when neither `--dns` nor a config
/// names one.
pub const DEFAULT_DNS: Ipv4Addr = Ipv4Addr::new(223, 5, 5, 5);
/// How long each STUN request waits before it is sent again.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);
/// How long the UPnP lease of the test port lasts, should natwg die before it
/// deletes the lease.
pub const LEASE_SECS: u32 = 120;
/// The description of the test lease on the gateway.
pub const LEASE_DESCRIPTION: &str = "natwg detect";
/// How long the cleanup of a lease during a panic waits for the gateway.
const PANIC_CLEANUP: Duration = Duration::from_secs(2);

const SSDP_WAIT: Duration = Duration::from_secs(2);
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_PORT: u16 = 53;
const BINDING_ATTEMPTS: u32 = 2;
const CHANGE_ATTEMPTS: u32 = 3;
/// Change tests against this many servers at most, when none proves
/// endpoint-independent filtering. A second server guards against one that
/// does not answer change requests.
const CHANGE_SERVERS: usize = 2;
/// The mapping test stops once answers come from this many server IPs.
const MAPPING_IPS: usize = 3;
/// With no answer from this many servers, UDP counts as blocked.
const SILENT_SERVERS: usize = 4;
const SELF_TEST_SENDS: u32 = 4;
const SELF_TEST_GAP: Duration = Duration::from_millis(500);
const SELF_TEST_MAGIC: &[u8; 16] = b"natwg-self-test.";

/// Whether `natwg detect` may lease the test port on the UPnP gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpnpMode {
    /// Lease the port when the uplink's address is private.
    Auto,
    Off,
}

/// What to test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The uplink (default: the physical interface of the default route,
    /// as `natwg client` picks it).
    pub iface: Option<String>,
    /// The UDP port to test (default: [`DEFAULT_PORT`]). A port that a
    /// socket holds already, such as a running natwg's, gives way to a free
    /// one.
    pub port: Option<u16>,
    /// STUN servers as `host:port`, asked in order (default:
    /// [`stun::RFC5780_SERVERS`], then [`stun::DEFAULT_SERVERS`] and
    /// [`stun::DEFAULT_FALLBACKS`]). An IPv4 address needs no DNS.
    pub servers: Vec<(String, u16)>,
    pub upnp: UpnpMode,
    /// The DNS server for STUN host names, asked through the uplink.
    pub dns: Ipv4Addr,
    /// How long each STUN request waits before it is sent again.
    pub timeout: Duration,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            iface: None,
            port: None,
            servers: Vec::new(),
            upnp: UpnpMode::Auto,
            dns: DEFAULT_DNS,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// Everything `natwg detect` found, as `--json` prints it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Detection {
    /// [`SCHEMA`].
    pub schema: u32,
    /// `supported`, `likely`, `inconclusive` or `unsupported`.
    pub verdict: Verdict,
    /// For a supported network: `public` or `nat1`.
    pub kind: Option<Kind>,
    /// For a supported public network, how natwg knows: `address` (the
    /// uplink holds it), `upnp` (the gateway forwards the port and owns the
    /// address) or `port_kept` (only STUN says so; a full-cone NAT that
    /// keeps the port looks the same). `natwg init` offers WireGuard mode
    /// only for `address` and `upnp`.
    pub public_by: Option<PublicBy>,
    /// The verdict in words, such as `supported (NAT1)`.
    pub summary: String,
    /// Why the network is not supported, or only likely.
    pub reason: Option<String>,
    /// What would fix an unsupported network, or settle a likely one.
    pub fix: Option<String>,
    pub uplink: UplinkReport,
    pub port: PortReport,
    pub upnp: UpnpReport,
    pub mapping: MappingReport,
    pub filtering: FilteringReport,
    pub self_test: SelfTest,
    /// Servers that could not be asked, and other remarks.
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UplinkReport {
    pub iface: String,
    pub address: Ipv4Addr,
    /// Whether the uplink's own address is public.
    pub public: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PortReport {
    /// The port the request named, or the default.
    pub wanted: u16,
    /// The port the tests ran on.
    pub tested: u16,
    /// Whether another socket held `wanted`, as a running natwg does.
    pub held: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UpnpReport {
    pub mode: UpnpMode,
    pub state: UpnpState,
    /// The gateway that answered SSDP. `natwg init` offers its control URL.
    pub gateway: Option<Gateway>,
    /// The gateway's WAN address.
    pub external_ip: Option<Ipv4Addr>,
    /// The mapping of the tested port that the gateway held already.
    pub existing: Option<upnp::PortMapping>,
    /// Why the gateway could not forward the tested port.
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpnpState {
    /// `--upnp off`.
    Off,
    /// The uplink's address is public.
    NotNeeded,
    /// natwg leased the tested port for the test and deleted the lease.
    Leased,
    /// natwg leased the tested port for [`LEASE_SECS`], but deleting the
    /// lease failed; a gateway that honours lease durations drops it then.
    LeaseLeft,
    /// The gateway forwards the tested port to this host already, and the
    /// mapping stays.
    Existing,
    /// The gateway forwards the tested port to another host, so natwg left
    /// it alone.
    Conflict,
    /// The gateway takes only permanent leases, which natwg does not take
    /// for a test.
    PermanentOnly,
    /// No gateway, or the gateway refused.
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MappingReport {
    pub behaviour: Mapping,
    /// The public address and port of the tested socket, when every answer
    /// agrees.
    pub endpoint: Option<SocketAddrV4>,
    /// Whether the endpoint keeps the tested port.
    pub port_kept: bool,
    pub answers: Vec<Answer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FilteringReport {
    pub behaviour: Filtering,
    pub tests: Vec<ChangeTest>,
}

impl Detection {
    pub fn exit_code(&self) -> i32 {
        self.verdict.exit_code()
    }

    /// The report for a terminal.
    pub fn render(&self) -> String {
        let mut text = String::new();
        let mut line = |label: &str, value: &str| {
            let _ = writeln!(text, "{label:<10}: {value}");
        };
        let uplink = &self.uplink;
        let kind = if uplink.public { "public" } else { "private" };
        line(
            "uplink",
            &format!("{} {} ({kind})", uplink.iface, uplink.address),
        );
        let port = self.port;
        line(
            "port",
            &if port.held {
                format!(
                    "udp/{} is in use, perhaps by a running natwg; tested udp/{} instead, so the result leaves out any router lease of udp/{}",
                    port.wanted, port.tested, port.wanted
                )
            } else {
                format!("udp/{}", port.tested)
            },
        );
        line("upnp", &self.upnp.describe(port.tested));
        line("mapping", &self.mapping.describe());
        line("filtering", &self.filtering.describe());
        line(
            "self test",
            match self.self_test {
                SelfTest::Received => "a second socket got in through the mapping",
                SelfTest::NotReceived => {
                    "a second socket did not get in through the mapping (inconclusive: the carrier may not hairpin)"
                }
                SelfTest::Skipped => "skipped",
            },
        );
        let by = match self.public_by {
            Some(PublicBy::Address) => ", by the uplink's own address",
            Some(PublicBy::Upnp) => ", by the UPnP gateway's forward",
            Some(PublicBy::PortKept) => {
                ", by STUN alone: a full-cone NAT that keeps the port looks the same, so publish txt; publish a needs address or upnp"
            }
            None => "",
        };
        line("verdict", &format!("{}{by}", self.summary));
        for remark in [&self.reason, &self.fix].into_iter().flatten() {
            let _ = writeln!(text, "{remark}");
        }
        for note in &self.notes {
            let _ = writeln!(text, "note: {note}");
        }
        text
    }
}

impl UpnpReport {
    fn new(mode: UpnpMode, state: UpnpState) -> Self {
        Self {
            mode,
            state,
            gateway: None,
            external_ip: None,
            existing: None,
            error: None,
        }
    }

    fn describe(&self, port: u16) -> String {
        let at = match (&self.gateway, self.external_ip) {
            (Some(gateway), Some(ip)) => format!(" on {} (WAN {ip})", gateway.control_url),
            (Some(gateway), None) => format!(" on {}", gateway.control_url),
            _ => String::new(),
        };
        let error = self.error.as_deref().unwrap_or("unknown error");
        match self.state {
            UpnpState::Off => "off".to_owned(),
            UpnpState::NotNeeded => "not needed: the uplink's address is public".to_owned(),
            UpnpState::Leased => format!("leased udp/{port}{at} for the test, deleted after it"),
            UpnpState::LeaseLeft => {
                format!("leased udp/{port}{at} for the test, but could not delete it: {error}")
            }
            UpnpState::Existing => format!("udp/{port} is forwarded to this host already{at}"),
            UpnpState::Conflict => format!("udp/{port}{at} is forwarded elsewhere: {error}"),
            UpnpState::PermanentOnly => {
                format!("the gateway{at} only takes permanent leases; not used for the test")
            }
            UpnpState::Failed => format!("failed: {error}"),
        }
    }
}

impl MappingReport {
    fn describe(&self) -> String {
        let servers = self.answers.len();
        let what = match self.behaviour {
            Mapping::NoNat => "no NAT",
            Mapping::EndpointIndependent => "endpoint-independent",
            Mapping::EndpointDependent => "endpoint-dependent (NAT4)",
            Mapping::Unknown if servers == 0 => return "no STUN server answered".to_owned(),
            Mapping::Unknown => "unknown",
        };
        match self.endpoint {
            Some(endpoint) => format!(
                "{what}, {endpoint}{} ({servers} answers)",
                if self.port_kept { ", port kept" } else { "" }
            ),
            None => {
                let seen: Vec<String> = self
                    .answers
                    .iter()
                    .map(|answer| format!("{} via {}", answer.mapped, answer.server))
                    .collect();
                format!("{what}: {}", seen.join(", "))
            }
        }
    }
}

impl FilteringReport {
    fn describe(&self) -> String {
        let what = match self.behaviour {
            Filtering::EndpointIndependent => "endpoint-independent",
            Filtering::AddressDependent => "address-dependent (NAT2)",
            Filtering::AddressAndPortDependent => "address-and-port-dependent (NAT3)",
            Filtering::Unknown => "unknown",
        };
        let tests: Vec<String> = self
            .tests
            .iter()
            .map(|test| {
                let probe = |probe: Probe| match probe {
                    Probe::Answered(from) => format!("answered from {from}"),
                    Probe::Silent => "silent".to_owned(),
                    Probe::NotRun => "not run".to_owned(),
                };
                format!(
                    "{} (other {}): change IP and port {}, change port {}",
                    test.server,
                    test.other,
                    probe(test.ip_and_port),
                    probe(test.port)
                )
            })
            .collect();
        match tests.is_empty() {
            true => format!("{what}: no RFC 5780 STUN server answered"),
            false => format!("{what}: {}", tests.join("; ")),
        }
    }
}

/// Run every test and judge the network. Errors are only for a missing
/// uplink, a socket natwg cannot bind, or a signal: a network that blocks
/// everything is an unsupported verdict.
///
/// SIGINT, SIGTERM and SIGHUP stop the tests, from before natwg asks the
/// gateway for a lease on: the lease goes before the error returns. A panic
/// deletes it too, with a blocking request of at most two seconds a step.
///
/// tokio keeps a signal handler for the life of the process, so these
/// signals lose their default action from here on. A caller that goes on
/// afterwards, such as an interactive `natwg init`, can pass its own stop
/// to [`run_until`] instead.
pub async fn run(request: &Request) -> Result<Detection> {
    let mut stop = Stop::listen()?;
    run_until(request, async move { stop.requested().await.to_owned() }).await
}

/// [`run`] that stops when `stop` resolves, with the error `INTERRUPTED`
/// and the reason `stop` gives, instead of on a signal.
pub async fn run_until(request: &Request, stop: impl Future<Output = String>) -> Result<Detection> {
    let uplink = uplink::find(request.iface.as_deref())?;
    let address = uplink.address.ok_or_else(|| {
        Error::new(
            "UPLINK_NO_ADDRESS",
            format!("{} has no IPv4 address", uplink.iface),
        )
    })?;
    let iface = uplink.iface;
    let public = is_public(address);
    let wanted = request.port.unwrap_or(DEFAULT_PORT);
    let (socket, port, held) = bind(&iface, wanted)?;
    let mut notes = Vec::new();
    let mut upnp = UpnpReport::new(request.upnp, UpnpState::Off);
    let mut lease: Option<LeaseGuard> = None;
    let local = SocketAddrV4::new(address, port);
    let tested = {
        let work = async {
            if request.upnp == UpnpMode::Auto {
                if public {
                    upnp.state = UpnpState::NotNeeded;
                } else {
                    take_lease(&iface, address, port, &mut upnp, &mut lease).await;
                }
            }
            test(&iface, socket, local, request, &mut notes).await
        };
        tokio::select! {
            tested = work => tested,
            reason = stop => Err(Error::new(
                "INTERRUPTED",
                format!("natwg detect stopped on {reason}"),
            )),
        }
    };
    if let Some(guard) = lease.take()
        && let Err(error) = guard.release().await
    {
        upnp.state = UpnpState::LeaseLeft;
        upnp.error = Some(error.to_string());
    }
    let (answers, change_tests, self_test) = tested?;
    if upnp.state == UpnpState::Failed && upnp.error.as_deref().is_some_and(local_network_denied) {
        notes.push(
            "macOS Local Network privacy may block natwg from the gateway: run natwg detect from Terminal, over SSH or with sudo, or give the app that runs it Local Network access in System Settings > Privacy & Security > Local Network".to_owned(),
        );
    }
    let seen = Observations {
        local,
        answers,
        change_tests,
        self_test,
        gateway_ip: upnp.external_ip,
        upnp_forwarded: matches!(
            upnp.state,
            UpnpState::Leased | UpnpState::LeaseLeft | UpnpState::Existing
        ),
    };
    Ok(report(
        &seen,
        UplinkReport {
            iface: iface.to_string(),
            address,
            public,
        },
        PortReport {
            wanted,
            tested: port,
            held,
        },
        upnp,
        notes,
    ))
}

/// The signals that stop `natwg detect`. Listening replaces their default
/// action, which would end the process with the lease still held.
struct Stop {
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
}

impl Stop {
    fn listen() -> Result<Self> {
        let listen =
            |kind| signal(kind).map_err(|e| Error::new("SIGNAL_UNAVAILABLE", e.to_string()));
        Ok(Self {
            interrupt: listen(SignalKind::interrupt())?,
            terminate: listen(SignalKind::terminate())?,
            hangup: listen(SignalKind::hangup())?,
        })
    }

    async fn requested(&mut self) -> &'static str {
        tokio::select! {
            _ = self.interrupt.recv() => "SIGINT",
            _ = self.terminate.recv() => "SIGTERM",
            _ = self.hangup.recv() => "SIGHUP",
        }
    }
}

/// A lease natwg asked the gateway for. It exists from just before the
/// request goes out, since a signal may cut the answer off. Dropped without
/// [`LeaseGuard::release`], as when a panic unwinds, it deletes the lease
/// with a blocking request.
struct LeaseGuard {
    igd: Option<Igd>,
    port: u16,
}

impl LeaseGuard {
    async fn release(mut self) -> Result<()> {
        match self.igd.take() {
            Some(igd) => igd.delete(self.port).await,
            None => Ok(()),
        }
    }

    /// Forget a lease that the gateway refused: there is nothing to delete.
    fn disarm(mut self) {
        self.igd = None;
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if let Some(igd) = self.igd.take() {
            let _ = igd.delete_blocking(self.port, PANIC_CLEANUP);
        }
    }
}

/// The [`Detection`] for what the tests saw.
pub fn report(
    seen: &Observations,
    uplink: UplinkReport,
    port: PortReport,
    upnp: UpnpReport,
    mut notes: Vec<String>,
) -> Detection {
    let assessment = classify(seen);
    let summary = match (assessment.verdict, assessment.kind) {
        (Verdict::Supported, Some(Kind::Public)) => "supported (public)",
        (Verdict::Supported, _) => "supported (NAT1)",
        (Verdict::Likely, _) => "likely",
        (Verdict::Inconclusive, _) => "inconclusive",
        (Verdict::Unsupported, _) => "unsupported",
    };
    let filtered = matches!(
        assessment.filtering,
        Filtering::AddressDependent | Filtering::AddressAndPortDependent
    );
    let lease_missing = matches!(
        upnp.state,
        UpnpState::Failed | UpnpState::Conflict | UpnpState::PermanentOnly
    );
    if filtered && lease_missing {
        notes.push(format!(
            "the UPnP gateway did not forward udp/{} for the test, so a filtering home router may be what dropped the answers; check UPnP, or forward the port by hand and run natwg detect --upnp off",
            port.tested
        ));
    }
    if port.held && assessment.verdict != Verdict::Supported {
        notes.push(format!(
            "if a running natwg holds udp/{}, natwg status shows whether its own port and lease work",
            port.wanted
        ));
    }
    let mut mapped: Vec<SocketAddrV4> = seen.answers.iter().map(|answer| answer.mapped).collect();
    mapped.sort();
    mapped.dedup();
    let endpoint = match mapped[..] {
        [only] => Some(only),
        _ => None,
    };
    let (mapping, filtering) = (assessment.mapping, assessment.filtering);
    Detection {
        schema: SCHEMA,
        verdict: assessment.verdict,
        kind: assessment.kind,
        public_by: assessment.public_by,
        summary: summary.to_owned(),
        reason: assessment.reason,
        fix: assessment.fix,
        uplink,
        port,
        upnp,
        mapping: MappingReport {
            behaviour: mapping,
            endpoint,
            port_kept: endpoint.is_some_and(|endpoint| endpoint.port() == port.tested),
            answers: seen.answers.clone(),
        },
        filtering: FilteringReport {
            behaviour: filtering,
            tests: seen.change_tests.clone(),
        },
        self_test: seen.self_test,
        notes,
    }
}

/// A socket on `port` of `iface`, its port, and whether another socket held
/// `port`, which then gives way to a free port.
fn bind(iface: &BoundInterface, port: u16) -> Result<(UdpSocket, u16, bool)> {
    let failed = |port, e: io::Error| Error::new("UDP_BIND", format!("{iface} udp/{port}: {e}"));
    let (socket, held) = match bound_udp_socket(iface, port) {
        Err(e) if e.kind() == io::ErrorKind::AddrInUse && port != 0 => {
            (bound_udp_socket(iface, 0).map_err(|e| failed(0, e))?, true)
        }
        socket => (socket.map_err(|e| failed(port, e))?, false),
    };
    let socket = UdpSocket::from_std(socket).map_err(|e| failed(port, e))?;
    let port = socket.local_addr().map_err(|e| failed(port, e))?.port();
    Ok((socket, port, held))
}

/// Ask the gateway of the LAN to forward `port` to this host for the test.
/// `lease` holds the lease from just before the request goes out until the
/// gateway refuses it; none when natwg leased nothing.
async fn take_lease(
    iface: &BoundInterface,
    address: Ipv4Addr,
    port: u16,
    report: &mut UpnpReport,
    lease: &mut Option<LeaseGuard>,
) {
    report.state = UpnpState::Failed;
    let failed = |report: &mut UpnpReport, error: Error| {
        report.error = Some(error.to_string());
    };
    let gateway = match upnp::discover(iface, address, SSDP_WAIT).await {
        Ok(gateway) => gateway,
        Err(error) => return failed(report, error),
    };
    report.gateway = Some(gateway.clone());
    let igd = match Igd::new(iface, gateway) {
        Ok(igd) => igd,
        Err(error) => return failed(report, error),
    };
    report.external_ip = igd.external_ip().await.ok();
    match igd.mapping(port).await {
        // natwg cannot tell what the gateway holds, so it changes nothing.
        Err(error) => failed(report, error),
        Ok(Some(existing)) if existing.client == address && existing.internal_port == port => {
            report.state = UpnpState::Existing;
            report.existing = Some(existing);
        }
        Ok(Some(existing)) => {
            report.error = Some(format!(
                "the gateway forwards it to {}:{} ({:?})",
                existing.client, existing.internal_port, existing.description
            ));
            report.state = UpnpState::Conflict;
            report.existing = Some(existing);
        }
        Ok(None) => {
            let guard = lease.insert(LeaseGuard {
                igd: Some(igd),
                port,
            });
            let igd = guard.igd.as_ref().expect("the guard holds the client");
            match igd.add(port, address, LEASE_DESCRIPTION, LEASE_SECS).await {
                Ok(()) => report.state = UpnpState::Leased,
                Err(error) => {
                    if error.code == "UPNP_PERMANENT_ONLY" {
                        report.state = UpnpState::PermanentOnly;
                    }
                    failed(report, error);
                    if let Some(guard) = lease.take() {
                        guard.disarm();
                    }
                }
            }
        }
    }
}

/// Whether an error is what macOS returns to a program that Local Network
/// privacy keeps off the LAN.
fn local_network_denied(error: &str) -> bool {
    cfg!(target_os = "macos")
        && ["No route to host", "Broken pipe", "Network is unreachable"]
            .iter()
            .any(|text| error.contains(text))
}

type Tested = (Vec<Answer>, Vec<ChangeTest>, SelfTest);

async fn test(
    iface: &BoundInterface,
    socket: UdpSocket,
    local: SocketAddrV4,
    request: &Request,
    notes: &mut Vec<String>,
) -> Result<Tested> {
    let servers = resolve(iface, request, notes).await;
    let mut prober = Prober {
        socket,
        timeout: request.timeout,
        contacted: Vec::new(),
    };
    let mut answers = Vec::new();
    let mut change_tests: Vec<ChangeTest> = Vec::new();
    let mut asked = 0;
    let mut silent = 0;
    // Filtering first, while the socket has sent nowhere else.
    for &server in &servers {
        let proven = classify::filtering(&change_tests) == Filtering::EndpointIndependent;
        if proven || change_tests.len() >= CHANGE_SERVERS || silent >= SILENT_SERVERS {
            break;
        }
        asked += 1;
        let Some((response, _)) = prober.ask(server, None, BINDING_ATTEMPTS).await else {
            if answers.is_empty() {
                silent += 1;
            }
            continue;
        };
        answers.push(Answer {
            server,
            mapped: response.mapped,
        });
        let Some(other) = response.other.filter(|other| other.port() != server.port()) else {
            continue;
        };
        if let Some(test) = prober.change_test(server, other, notes).await {
            change_tests.push(test);
        }
    }
    // Then the mapping: each change-tested server's other IP at its first
    // port (test II of RFC 5780), then the servers not asked yet. The other
    // IP and port sent the change answer, so a NAT may have tracked it, and a
    // Linux NAT then gives the host a new port for it.
    let others = change_tests
        .iter()
        .filter(|test| test.other.ip() != test.server.ip() && !hidden(test.server, test.other))
        .map(|test| SocketAddrV4::new(*test.other.ip(), test.server.port()));
    let rest = servers.iter().copied().skip(asked);
    for server in others.chain(rest) {
        let mut ips: Vec<Ipv4Addr> = answers.iter().map(|answer| *answer.server.ip()).collect();
        ips.sort();
        ips.dedup();
        if ips.len() >= MAPPING_IPS || (answers.is_empty() && silent >= SILENT_SERVERS) {
            break;
        }
        if prober.contacted.contains(&server) {
            continue;
        }
        match prober.ask(server, None, BINDING_ATTEMPTS).await {
            Some((response, _)) => answers.push(Answer {
                server,
                mapped: response.mapped,
            }),
            None if answers.is_empty() => silent += 1,
            None => {}
        }
    }
    // A mapping only a server inside the NAT saw is this host's own
    // address, which tells nothing.
    let outside = answers.iter().find(|answer| is_public(*answer.mapped.ip()));
    let self_test = match (classify::mapping(local, &answers), outside) {
        (Mapping::EndpointIndependent | Mapping::Unknown, Some(answer)) => {
            prober.self_test(iface, answer.mapped).await
        }
        _ => SelfTest::Skipped,
    };
    Ok((answers, change_tests, self_test))
}

/// Whether a public server reports a private other address, as one behind
/// NAT does. Its answers from the other IP come from somewhere else, if at
/// all.
fn hidden(server: SocketAddrV4, other: SocketAddrV4) -> bool {
    is_public(*server.ip()) && !is_public(*other.ip())
}

/// The addresses of the STUN servers, in order and each once. Host names
/// are resolved together through the uplink.
async fn resolve(
    iface: &BoundInterface,
    request: &Request,
    notes: &mut Vec<String>,
) -> Vec<SocketAddrV4> {
    let builtin = request.servers.is_empty();
    let servers: Vec<(String, u16)> = if builtin {
        stun::RFC5780_SERVERS
            .iter()
            .chain(&stun::DEFAULT_SERVERS)
            .map(|(host, port)| ((*host).to_owned(), *port))
            .collect()
    } else {
        request.servers.clone()
    };
    let dns = SocketAddrV4::new(request.dns, DNS_PORT);
    let mut lookups = JoinSet::new();
    for (index, (host, port)) in servers.iter().cloned().enumerate() {
        let iface = iface.clone();
        lookups.spawn(async move {
            let found = match host.parse::<Ipv4Addr>() {
                Ok(ip) => Ok(vec![ip]),
                Err(_) => dns::resolve(&iface, dns, &host, RecordKind::A, DNS_TIMEOUT)
                    .await
                    .map(|records| {
                        records
                            .into_iter()
                            .filter_map(|record| match record {
                                Record::A(ip) => Some(ip),
                                Record::Txt(_) => None,
                            })
                            .collect()
                    }),
            };
            (index, host, port, found)
        });
    }
    let mut found = vec![None; servers.len()];
    while let Some(Ok((index, host, port, ips))) = lookups.join_next().await {
        match ips {
            // The first address of a host is enough: the others are often
            // the same server, which would only repeat its answer.
            Ok(ips) => found[index] = ips.first().map(|ip| SocketAddrV4::new(*ip, port)),
            Err(error) => notes.push(format!("skipped {host}:{port}: {error}")),
        }
    }
    let fallbacks = builtin
        .then_some(stun::DEFAULT_FALLBACKS)
        .into_iter()
        .flatten();
    let mut addresses: Vec<SocketAddrV4> = Vec::new();
    for address in found.into_iter().flatten().chain(fallbacks) {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
}

/// The tested socket, and every address it has sent to.
struct Prober {
    socket: UdpSocket,
    timeout: Duration,
    contacted: Vec<SocketAddrV4>,
}

impl Prober {
    /// Send a Binding request, with `change` if given, up to `attempts`
    /// times, and return the answer and its source. A send error counts as
    /// no answer.
    async fn ask(
        &mut self,
        server: SocketAddrV4,
        change: Option<Change>,
        attempts: u32,
    ) -> Option<(BindingResponse, SocketAddrV4)> {
        let id = TransactionId(crate::wire::random().ok()?);
        let request = match change {
            Some(change) => stun::change_request(id, change).to_vec(),
            None => stun::binding_request(id).to_vec(),
        };
        if !self.contacted.contains(&server) {
            self.contacted.push(server);
        }
        let mut buffer = [0; 1500];
        for _ in 0..attempts {
            // RFC 5389 resends a request with the same transaction id, so a
            // late answer to the first send still counts.
            self.socket.send_to(&request, server).await.ok()?;
            let deadline = Instant::now() + self.timeout;
            while let Ok(received) =
                tokio::time::timeout_at(deadline, self.socket.recv_from(&mut buffer)).await
            {
                let Ok((len, SocketAddr::V4(source))) = received else {
                    continue;
                };
                match stun::parse_binding_response(&buffer[..len]) {
                    Some(response) if response.id == id => return Some((response, source)),
                    _ => {}
                }
            }
        }
        None
    }

    /// The change tests of RFC 5780 against `server`, whose other address is
    /// `other`. None when the server ignores CHANGE-REQUEST and answers from
    /// where it was asked.
    async fn change_test(
        &mut self,
        server: SocketAddrV4,
        other: SocketAddrV4,
        notes: &mut Vec<String>,
    ) -> Option<ChangeTest> {
        let ignored =
            || format!("{server} ignores CHANGE-REQUEST; not used for the filtering test");
        // An address this socket has sent to is open in any filtering NAT,
        // so an answer from it would prove nothing.
        let contacted = |prober: &Self, ip: Ipv4Addr, port: Option<u16>| {
            prober
                .contacted
                .iter()
                .any(|to| *to.ip() == ip && port.is_none_or(|port| to.port() == port))
        };
        let ip_and_port = if other.ip() == server.ip() || hidden(server, other) {
            Probe::NotRun
        } else if contacted(self, *other.ip(), None) {
            notes.push(format!(
                "{server}: this socket has sent to {} already, so its change of IP was not tested",
                other.ip()
            ));
            Probe::NotRun
        } else {
            match self
                .ask(server, Some(Change::IpAndPort), CHANGE_ATTEMPTS)
                .await
            {
                None => Probe::Silent,
                Some((_, from)) if from == server => {
                    notes.push(ignored());
                    return None;
                }
                Some((_, from)) if from.ip() != server.ip() => Probe::Answered(from),
                // Only the port changed: this server cannot change its IP.
                Some(_) => Probe::NotRun,
            }
        };
        let port = if contacted(self, *server.ip(), Some(other.port())) {
            Probe::NotRun
        } else {
            match self.ask(server, Some(Change::Port), CHANGE_ATTEMPTS).await {
                None => Probe::Silent,
                Some((_, from)) if from == server => {
                    if ip_and_port == Probe::NotRun {
                        notes.push(ignored());
                        return None;
                    }
                    Probe::NotRun
                }
                Some((_, from)) if from.ip() == server.ip() => Probe::Answered(from),
                Some(_) => Probe::NotRun,
            }
        };
        Some(ChangeTest {
            server,
            other,
            ip_and_port,
            port,
        })
    }

    /// Send to `mapped` from a second socket on `iface` and wait for the
    /// datagram on the tested socket.
    async fn self_test(&mut self, iface: &BoundInterface, mapped: SocketAddrV4) -> SelfTest {
        let Ok(token) = crate::wire::random::<16>() else {
            return SelfTest::Skipped;
        };
        let mut datagram = SELF_TEST_MAGIC.to_vec();
        datagram.extend(token);
        let Ok(second) = bound_udp_socket(iface, 0).and_then(UdpSocket::from_std) else {
            return SelfTest::Skipped;
        };
        let mut buffer = [0; 64];
        for _ in 0..SELF_TEST_SENDS {
            if second.send_to(&datagram, mapped).await.is_err() {
                return SelfTest::NotReceived;
            }
            let deadline = Instant::now() + SELF_TEST_GAP;
            while let Ok(received) =
                tokio::time::timeout_at(deadline, self.socket.recv_from(&mut buffer)).await
            {
                if matches!(received, Ok((len, _)) if buffer[..len] == datagram[..]) {
                    return SelfTest::Received;
                }
            }
        }
        SelfTest::NotReceived
    }
}
