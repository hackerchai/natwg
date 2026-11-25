//! UPnP discovery and the one-off port mappings of `natwg detect`: the SSDP
//! and description parsers against what a TP-Link TL-7DR7290 sends, and the
//! SOAP client against a fake gateway on loopback.

use natwg::server::upnp::{
    self, Gateway, Igd, PortMapping, search_request, soap_body, ssdp_location, upnp_error,
    wan_service,
};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[cfg(target_os = "macos")]
const LOOPBACK: &str = "lo0";
#[cfg(target_os = "linux")]
const LOOPBACK: &str = "lo";

const WAN_IP_1: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
const TP_LINK_DESCRIPTION: &str = include_str!("fixtures/tp-link-igd.xml");
// What the TL-7DR7290 answers GetSpecificPortMappingEntry for a port it does
// not forward, captured 2026-11-25.
const TP_LINK_NO_ENTRY: &str = r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>501</errorCode><errorDescription>Entry not found !</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"#;

#[test]
fn the_search_request_asks_for_one_target() {
    let request = search_request("urn:schemas-upnp-org:device:InternetGatewayDevice:1");
    assert!(request.starts_with("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"));
    assert!(request.contains("MAN: \"ssdp:discover\"\r\n"));
    assert!(request.contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"));
    assert!(request.ends_with("\r\n\r\n"));
}

#[test]
fn ssdp_answers_yield_their_location() {
    let answer = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=100\r\nlocation: http://10.24.0.1:1900/igd.xml \r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
    assert_eq!(ssdp_location(answer), Some("http://10.24.0.1:1900/igd.xml"));
    for answer in [
        "NOTIFY * HTTP/1.1\r\nLOCATION: http://10.24.0.1:1900/igd.xml\r\n\r\n",
        "HTTP/1.1 404 Not Found\r\nLOCATION: http://10.24.0.1:1900/igd.xml\r\n\r\n",
        "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n",
        "HTTP/1.1 200 OK\r\nLOCATION:\r\n\r\n",
    ] {
        assert_eq!(ssdp_location(answer), None, "{answer:?}");
    }
}

#[test]
fn the_tp_link_description_yields_its_control_url() {
    assert_eq!(
        wan_service(TP_LINK_DESCRIPTION, "http://10.24.0.1:1900/igd.xml"),
        Some(("http://10.24.0.1:1900/ipc".to_owned(), WAN_IP_1))
    );
}

fn description(services: &[(&str, &str)], base: Option<&str>) -> String {
    let services: String = services
        .iter()
        .map(|(kind, control)| {
            format!(
                "<service><serviceType>{kind}</serviceType><controlURL>{control}</controlURL></service>"
            )
        })
        .collect();
    let base = base.map_or(String::new(), |base| format!("<URLBase>{base}</URLBase>"));
    format!("<root>{base}<device><serviceList>{services}</serviceList></device></root>")
}

#[test]
fn the_best_wan_service_wins_and_its_url_is_made_absolute() {
    let both = description(
        &[
            (
                "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1",
                "/ifc",
            ),
            (WAN_IP_1, "/ip1"),
            ("urn:schemas-upnp-org:service:WANIPConnection:2", "ctl/ip2"),
        ],
        None,
    );
    assert_eq!(
        wan_service(&both, "http://192.168.1.1:5000/rootDesc.xml"),
        Some((
            "http://192.168.1.1:5000/ctl/ip2".to_owned(),
            "urn:schemas-upnp-org:service:WANIPConnection:2"
        ))
    );
    let ppp = description(
        &[("urn:schemas-upnp-org:service:WANPPPConnection:1", "/ppp")],
        Some("http://192.168.1.1:49000/"),
    );
    assert_eq!(
        wan_service(&ppp, "http://192.168.1.1:5000/desc.xml"),
        Some((
            "http://192.168.1.1:49000/ppp".to_owned(),
            "urn:schemas-upnp-org:service:WANPPPConnection:1"
        ))
    );
    let absolute = description(&[(WAN_IP_1, "http://192.168.1.1:2869/upnp/ip")], None);
    assert_eq!(
        wan_service(&absolute, "http://192.168.1.1:5000/desc.xml").map(|(url, _)| url),
        Some("http://192.168.1.1:2869/upnp/ip".to_owned())
    );
    let none = description(
        &[("urn:schemas-upnp-org:service:Layer3Forwarding:1", "/l3f")],
        None,
    );
    assert_eq!(wan_service(&none, "http://192.168.1.1/desc.xml"), None);
}

#[test]
fn the_generic_soap_body_is_the_daemons_add_port_mapping() {
    let arguments = [
        ("NewRemoteHost", String::new()),
        ("NewExternalPort", "51831".to_owned()),
        ("NewProtocol", "UDP".to_owned()),
        ("NewInternalPort", "51831".to_owned()),
        ("NewInternalClient", "10.24.0.2".to_owned()),
        ("NewEnabled", "1".to_owned()),
        ("NewPortMappingDescription", "natwg".to_owned()),
        ("NewLeaseDuration", "3600".to_owned()),
    ];
    assert_eq!(
        soap_body(WAN_IP_1, "AddPortMapping", &arguments),
        upnp::add_port_mapping(
            51831,
            "10.24.0.2".parse().unwrap(),
            &"natwg".parse().unwrap(),
            3600
        )
    );
}

#[test]
fn a_upnp_fault_yields_its_code_and_description() {
    assert_eq!(
        upnp_error(TP_LINK_NO_ENTRY),
        Some((501, "Entry not found !".to_owned()))
    );
    assert_eq!(upnp_error("<s:Envelope></s:Envelope>"), None);
}

/// What the fake gateway saw: each SOAPAction and body.
type Calls = Arc<Mutex<Vec<(String, String)>>>;

/// A gateway on loopback that answers each call with `reply(action, body)`.
async fn fake_gateway(reply: fn(&str, &str) -> String) -> (Igd, Calls) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls: Calls = Arc::default();
    let seen = calls.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            let (head, body) = loop {
                let len = stream.read(&mut buffer).await.unwrap();
                request.extend(&buffer[..len]);
                let text = String::from_utf8_lossy(&request).into_owned();
                let Some((head, body)) = text.split_once("\r\n\r\n") else {
                    continue;
                };
                let length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if body.len() >= length {
                    break (head.to_owned(), body.to_owned());
                }
            };
            let action = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("soapaction").then_some(value)
                })
                .unwrap_or_default()
                .trim()
                .trim_matches('"')
                .rsplit('#')
                .next()
                .unwrap_or_default()
                .to_owned();
            let answer = reply(&action, &body);
            seen.lock().unwrap().push((action, body));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let gateway = Gateway {
        location: format!("http://{address}/igd.xml"),
        control_url: format!("http://{address}/ipc"),
        service: WAN_IP_1.to_owned(),
    };
    (Igd::new(LOOPBACK, gateway).unwrap(), calls)
}

fn ok(action: &str, fields: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:{action}Response xmlns:u="{WAN_IP_1}">{fields}</u:{action}Response></s:Body></s:Envelope>"#
    )
}

fn fault(code: u16, description: &str) -> String {
    TP_LINK_NO_ENTRY
        .replace("501", &code.to_string())
        .replace("Entry not found !", description)
}

#[tokio::test]
async fn a_missing_mapping_is_none_and_another_fault_an_error() {
    let (igd, calls) = fake_gateway(|_, body| match body.contains(">51899<") {
        true => TP_LINK_NO_ENTRY.to_owned(),
        false if body.contains(">51898<") => fault(714, "NoSuchEntryInArray"),
        false => fault(606, "Action not authorized"),
    })
    .await;
    assert_eq!(igd.mapping(51899).await.unwrap(), None);
    assert_eq!(igd.mapping(51898).await.unwrap(), None);
    let error = igd.mapping(51897).await.unwrap_err();
    assert_eq!(error.code, "UPNP_REFUSED");
    assert!(error.message.contains("606"), "{error}");
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "GetSpecificPortMappingEntry");
    assert!(
        calls[0]
            .1
            .contains("<NewExternalPort>51899</NewExternalPort><NewProtocol>UDP</NewProtocol>")
    );
}

#[tokio::test]
async fn an_existing_mapping_is_read() {
    let (igd, _) = fake_gateway(|action, _| {
        ok(
            action,
            "<NewInternalPort>51830</NewInternalPort><NewInternalClient>10.24.0.4</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>natwg</NewPortMappingDescription><NewLeaseDuration>3412</NewLeaseDuration>",
        )
    })
    .await;
    assert_eq!(
        igd.mapping(51830).await.unwrap(),
        Some(PortMapping {
            client: "10.24.0.4".parse().unwrap(),
            internal_port: 51830,
            description: "natwg".to_owned(),
            lease_secs: 3412,
        })
    );
}

#[tokio::test]
async fn a_gateway_that_takes_only_permanent_leases_gets_one() {
    let (igd, calls) = fake_gateway(|action, body| match body.contains("<NewLeaseDuration>0<") {
        true => ok(action, ""),
        false => fault(725, "OnlyPermanentLeasesSupported"),
    })
    .await;
    let lease = igd
        .add(51899, "10.24.0.4".parse().unwrap(), "natwg detect", 120)
        .await
        .unwrap();
    assert_eq!(lease, 0);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(
        calls[0]
            .1
            .contains("<NewLeaseDuration>120</NewLeaseDuration>")
    );
    assert!(
        calls[0]
            .1
            .contains("<NewInternalClient>10.24.0.4</NewInternalClient>")
    );
    assert!(
        calls[0]
            .1
            .contains("<NewPortMappingDescription>natwg detect</NewPortMappingDescription>")
    );
}

#[tokio::test]
async fn add_delete_and_the_external_address_round_trip() {
    let (igd, calls) = fake_gateway(|action, _| match action {
        "GetExternalIPAddress" => ok(
            action,
            "<NewExternalIPAddress>100.87.135.127</NewExternalIPAddress>",
        ),
        "AddPortMapping" | "DeletePortMapping" => ok(action, ""),
        _ => fault(401, "Invalid Action"),
    })
    .await;
    assert_eq!(
        igd.external_ip().await.unwrap(),
        "100.87.135.127".parse::<std::net::Ipv4Addr>().unwrap()
    );
    let lease = igd
        .add(51899, "10.24.0.4".parse().unwrap(), "natwg detect", 120)
        .await
        .unwrap();
    assert_eq!(lease, 120);
    igd.delete(51899).await.unwrap();
    let actions: Vec<String> = calls
        .lock()
        .unwrap()
        .iter()
        .map(|(a, _)| a.clone())
        .collect();
    assert_eq!(
        actions,
        [
            "GetExternalIPAddress",
            "AddPortMapping",
            "DeletePortMapping"
        ]
    );
}

#[tokio::test]
async fn a_refused_delete_is_an_error() {
    let (igd, _) = fake_gateway(|_, _| fault(714, "NoSuchEntryInArray")).await;
    let error = igd.delete(51899).await.unwrap_err();
    assert_eq!(error.code, "UPNP_REFUSED");
    assert!(error.message.contains("DeletePortMapping"), "{error}");
}
