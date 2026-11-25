//! Keep the Cloudflare record that clients read: a TXT record with the
//! mapping as `"ip:port"`, the record natwg.py writes, or an A record with the
//! public IP.

use crate::config::{CloudflareConfig, PublishMode};
use crate::keys::Secret;
use crate::server::error_chain;
use crate::{Error, Result};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, SystemTime},
};
use tokio::{sync::watch, time::Instant};

pub const API: &str = "https://api.cloudflare.com/client/v4";

/// How long the publisher waits after a failure before it tries the same
/// value again. A new value does not wait.
pub const RETRY: Duration = Duration::from_secs(60);

/// How often publish `a` reads the name again, to see a record that someone
/// changed or added.
pub const AUDIT_EVERY: Duration = Duration::from_secs(300);

/// The TTL natwg gives its records.
pub const TTL: u32 = 60;

const TXT_COMMENT: &str = "natwg: WireGuard public endpoint, auto-updated";
const A_COMMENT: &str = "natwg: WireGuard public IP, auto-updated";
const TIMEOUT: Duration = Duration::from_secs(15);
const REDACTED: &str = "<redacted>";

/// What the record holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content {
    /// A TXT record with the endpoint as `"ip:port"`.
    Txt(SocketAddrV4),
    /// An A record with the public IP.
    A(Ipv4Addr),
}

impl Content {
    /// The DNS record type: `TXT` or `A`.
    pub fn record_type(self) -> &'static str {
        match self {
            Self::Txt(_) => "TXT",
            Self::A(_) => "A",
        }
    }

    /// The `content` of the record in the Cloudflare API.
    fn api_content(self) -> String {
        match self {
            Self::Txt(endpoint) => format!("\"{endpoint}\""),
            Self::A(ip) => ip.to_string(),
        }
    }

    /// The body that creates or replaces the record. The TXT body is the one
    /// natwg.py sends. An A record is never proxied, since Cloudflare's proxy
    /// carries no WireGuard.
    fn body(self, name: &str) -> Value {
        match self {
            Self::Txt(_) => json!({
                "type": "TXT",
                "name": name,
                "content": self.api_content(),
                "ttl": TTL,
                "comment": TXT_COMMENT,
            }),
            Self::A(_) => json!({
                "type": "A",
                "name": name,
                "content": self.api_content(),
                "ttl": TTL,
                "proxied": false,
                "comment": A_COMMENT,
            }),
        }
    }
}

impl fmt::Display for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Txt(endpoint) => endpoint.fmt(f),
            Self::A(ip) => ip.fmt(f),
        }
    }
}

/// A value the record holds, and when natwg wrote it or found it there.
/// With publish `a`, this is also an address that natwg cannot confirm now
/// and so keeps as it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub value: Content,
    pub at: SystemTime,
}

/// What the publisher is doing. `previous` is the value the record holds
/// from an earlier success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Publish {
    /// No value to publish yet.
    Idle,
    Publishing {
        previous: Option<Record>,
        /// Why the attempt before this one failed.
        error: Option<String>,
    },
    Published(Record),
    Failed {
        error: String,
        retry_at: Instant,
        previous: Option<Record>,
    },
}

impl Publish {
    /// The value the record holds since natwg last wrote it.
    pub fn record(&self) -> Option<Record> {
        match self {
            Self::Idle => None,
            Self::Published(record) => Some(*record),
            Self::Publishing { previous, .. } | Self::Failed { previous, .. } => *previous,
        }
    }

    /// Why the last attempt failed, until an attempt succeeds.
    pub fn error(&self) -> Option<&str> {
        match self {
            Self::Publishing { error, .. } => error.as_deref(),
            Self::Failed { error, .. } => Some(error),
            Self::Idle | Self::Published(_) => None,
        }
    }
}

pub struct Publisher {
    http: reqwest::Client,
    api: String,
    zone: String,
    record: String,
    token: Secret,
    mode: PublishMode,
    zone_id: Option<String>,
    record_id: Option<String>,
    strays: watch::Sender<Option<String>>,
}

/// The A record that publish `a` keeps, as a look at the name found it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Kept {
    id: String,
    /// What it holds, when that is an IPv4 address.
    ip: Option<Ipv4Addr>,
    /// Whether it is what natwg writes: not proxied, with natwg's TTL.
    exact: bool,
}

/// What a look at the name found.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Found {
    kept: Option<Kept>,
    at: SystemTime,
}

impl Found {
    /// The address the kept record holds exactly as natwg writes it.
    fn exact(&self) -> Option<Ipv4Addr> {
        self.kept.as_ref().filter(|kept| kept.exact)?.ip
    }

    /// The record as the status shows it: what the kept record holds.
    fn record(&self) -> Option<Record> {
        let ip = self.kept.as_ref()?.ip?;
        Some(Record {
            value: Content::A(ip),
            at: self.at,
        })
    }
}

impl Publisher {
    /// A publisher of `mode` that sends API requests to `api`, which is
    /// [`API`] outside of tests. The requests may take the default route.
    pub fn new(config: &CloudflareConfig, mode: PublishMode, api: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .no_proxy()
            .build()
            .map_err(|e| Error::new("HTTP_UNAVAILABLE", error_chain(&e)))?;
        Ok(Self {
            http,
            api: api.trim_end_matches('/').to_owned(),
            zone: config.zone.clone(),
            record: config.record.clone(),
            token: config.token.clone(),
            mode,
            zone_id: None,
            record_id: None,
            strays: watch::Sender::new(None),
        })
    }

    /// With publish `a`, what else the name holds that clients may dial:
    /// more A records than the one natwg keeps, and AAAA records. natwg never
    /// deletes them; the operator must.
    pub fn strays(&self) -> watch::Receiver<Option<String>> {
        self.strays.subscribe()
    }

    /// Publish every new value, one request at a time. A value already in
    /// the record is skipped, and a failed value is tried again after
    /// [`RETRY`], or at once when the wanted value moves on. With publish
    /// `a`, the publisher also reads the name at start and every
    /// [`AUDIT_EVERY`], and writes nothing while no value is wanted.
    pub async fn run(
        self,
        wanted: watch::Receiver<Option<Content>>,
        state: watch::Sender<Publish>,
    ) -> Infallible {
        match self.mode {
            PublishMode::Txt => self.run_txt(wanted, state).await,
            PublishMode::A => self.run_a(wanted, state).await,
        }
    }

    async fn run_txt(
        mut self,
        mut wanted: watch::Receiver<Option<Content>>,
        state: watch::Sender<Publish>,
    ) -> Infallible {
        loop {
            let value = *wanted.borrow_and_update();
            let previous = state.borrow().record();
            match (value, previous) {
                (Some(value), Some(record)) if record.value == value => {
                    state.send_if_modified(|state| {
                        let stale = !matches!(state, Publish::Published(_));
                        if stale {
                            *state = Publish::Published(record);
                        }
                        stale
                    });
                }
                (Some(Content::Txt(endpoint)), _) => {
                    let value = Content::Txt(endpoint);
                    let error = state.borrow().error().map(str::to_owned);
                    state.send_replace(Publish::Publishing { previous, error });
                    match self.publish_txt(endpoint).await {
                        Ok(wrote) => {
                            let record = &self.record;
                            if wrote {
                                tracing::info!("published TXT {record} = \"{value}\"");
                            } else {
                                tracing::info!("TXT {record} holds \"{value}\" already");
                            }
                            let at = SystemTime::now();
                            state.send_replace(Publish::Published(Record { value, at }));
                        }
                        Err(error) => {
                            let error = self.redacted(&error);
                            tracing::warn!("publish {value} failed: {error} (retry in 60s)");
                            let retry_at = Instant::now() + RETRY;
                            state.send_replace(Publish::Failed {
                                error,
                                retry_at,
                                previous,
                            });
                            tokio::select! {
                                () = tokio::time::sleep_until(retry_at) => {}
                                () = changed(&mut wanted) => {}
                            }
                            continue;
                        }
                    }
                }
                (Some(Content::A(_)) | None, _) => {}
            }
            changed(&mut wanted).await;
        }
    }

    /// Publish `a`. The publisher writes only the address that is wanted
    /// now: when none is, it writes nothing, and the status shows what the
    /// record holds. A record that holds the address but is proxied or has
    /// another TTL is written again, since Cloudflare's proxy carries no
    /// WireGuard.
    async fn run_a(
        mut self,
        mut wanted: watch::Receiver<Option<Content>>,
        state: watch::Sender<Publish>,
    ) -> Infallible {
        let mut found: Option<Found> = None;
        let mut audit_at = Instant::now();
        loop {
            if found.is_none() || Instant::now() >= audit_at {
                match self.look().await {
                    Ok(look) => {
                        found = Some(look);
                        audit_at = Instant::now() + AUDIT_EVERY;
                    }
                    Err(error) => {
                        let error = self.redacted(&error);
                        tracing::warn!("reading {} failed: {error} (retry in 60s)", self.record);
                        let retry_at = Instant::now() + RETRY;
                        let previous = state.borrow().record();
                        state.send_replace(Publish::Failed {
                            error,
                            retry_at,
                            previous,
                        });
                        tokio::select! {
                            () = tokio::time::sleep_until(retry_at) => {}
                            () = changed(&mut wanted) => {}
                        }
                        continue;
                    }
                }
            }
            let seen = found.clone().expect("a look just ran");
            let value = *wanted.borrow_and_update();
            match value {
                Some(Content::A(ip)) if seen.exact() == Some(ip) => {
                    let record = seen.record().expect("an exact record has an address");
                    state.send_if_modified(|state| {
                        let stale = !matches!(state, Publish::Published(_))
                            || state.record().map(|r| r.value) != Some(record.value);
                        if stale {
                            tracing::info!("A {} holds \"{ip}\" already", self.record);
                            *state = Publish::Published(record);
                        }
                        stale
                    });
                }
                Some(Content::A(ip)) => {
                    let previous = seen.record();
                    let error = state.borrow().error().map(str::to_owned);
                    state.send_replace(Publish::Publishing { previous, error });
                    let id = seen.kept.as_ref().map(|kept| kept.id.clone());
                    match self.write_a(ip, id).await {
                        Ok(id) => {
                            tracing::info!("published A {} = \"{ip}\"", self.record);
                            let at = SystemTime::now();
                            let kept = Kept {
                                id,
                                ip: Some(ip),
                                exact: true,
                            };
                            found = Some(Found {
                                kept: Some(kept),
                                at,
                            });
                            let value = Content::A(ip);
                            state.send_replace(Publish::Published(Record { value, at }));
                        }
                        Err(error) => {
                            let error = self.redacted(&error);
                            tracing::warn!("publish {ip} failed: {error} (retry in 60s)");
                            // The record may be gone, so the next try reads the name again.
                            found = None;
                            let retry_at = Instant::now() + RETRY;
                            state.send_replace(Publish::Failed {
                                error,
                                retry_at,
                                previous,
                            });
                            tokio::select! {
                                () = tokio::time::sleep_until(retry_at) => {}
                                () = changed(&mut wanted) => {}
                            }
                            continue;
                        }
                    }
                }
                Some(Content::Txt(_)) | None => {
                    // Nothing is confirmed now, so nothing is written, and no
                    // write is pending: the record keeps what it holds.
                    let now = match seen.record() {
                        Some(record) => Publish::Published(record),
                        None => Publish::Idle,
                    };
                    state.send_if_modified(|state| {
                        let stale = *state != now;
                        if stale {
                            *state = now;
                        }
                        stale
                    });
                }
            }
            tokio::select! {
                () = changed(&mut wanted) => {}
                () = tokio::time::sleep_until(audit_at) => {}
            }
        }
    }

    /// The token never reaches a log or the status.
    fn redacted(&self, error: &Error) -> String {
        error.to_string().replace(self.token.expose(), REDACTED)
    }

    async fn zone_id(&mut self) -> Result<String> {
        if let Some(id) = &self.zone_id {
            return Ok(id.clone());
        }
        let query = [("name", self.zone.as_str())];
        let zones = self.call(Method::GET, "/zones", &query, None).await?;
        let id = first_id(&zones).ok_or_else(|| {
            Error::new(
                "CLOUDFLARE_ZONE",
                format!("the zone {} is not visible to the token", self.zone),
            )
        })?;
        Ok(self.zone_id.insert(id).clone())
    }

    /// Make the TXT record hold `value`, and return whether that took a
    /// write. The lookup of the record ID, after a start or a failed write,
    /// reads what the record holds too, so a server that restarts on the
    /// same mapping finds it published.
    async fn publish_txt(&mut self, value: SocketAddrV4) -> Result<bool> {
        let zone_id = self.zone_id().await?;
        let records = format!("/zones/{zone_id}/dns_records");
        if self.record_id.is_none() {
            let query = [("type", "TXT"), ("name", &self.record)];
            let found = self.call(Method::GET, &records, &query, None).await?;
            self.record_id = first_id(&found);
            let content = found[0]["content"].as_str().unwrap_or_default();
            if content.trim_matches('"') == value.to_string() {
                return Ok(false);
            }
        }
        let body = Content::Txt(value).body(&self.record);
        match &self.record_id {
            Some(id) => {
                let path = format!("{records}/{id}");
                let put = self.call(Method::PUT, &path, &[], Some(&body)).await;
                // The record may be gone, so the next try looks it up again.
                if put.is_err() {
                    self.record_id = None;
                }
                put.map(|_| true)
            }
            None => {
                let created = self.call(Method::POST, &records, &[], Some(&body)).await?;
                let id = created["id"]
                    .as_str()
                    .ok_or_else(|| Error::new("CLOUDFLARE_API", "the created record has no id"))?;
                self.record_id = Some(id.to_owned());
                Ok(true)
            }
        }
    }

    /// Read every record of the name: the A record natwg keeps (the one it
    /// kept before, else the first), and the strays beside it, which go to
    /// [`Publisher::strays`].
    async fn look(&mut self) -> Result<Found> {
        let zone_id = self.zone_id().await?;
        let records = format!("/zones/{zone_id}/dns_records");
        let query = [("name", self.record.as_str())];
        let found = self.call(Method::GET, &records, &query, None).await?;
        let at = SystemTime::now();
        let all = found.as_array().map(Vec::as_slice).unwrap_or_default();
        let of = |kind: &str| -> Vec<&Value> {
            all.iter()
                .filter(|record| record["type"].as_str() == Some(kind))
                .collect()
        };
        let a = of("A");
        let held = self.record_id.as_deref();
        let kept = a
            .iter()
            .position(|record| held.is_some() && record["id"].as_str() == held)
            .unwrap_or(0);
        let kept = a.get(kept).map(|record| Kept {
            id: record["id"].as_str().unwrap_or_default().to_owned(),
            ip: record["content"].as_str().and_then(|ip| ip.parse().ok()),
            exact: record["proxied"].as_bool() == Some(false)
                && record["ttl"].as_u64() == Some(u64::from(TTL)),
        });
        self.record_id = kept.as_ref().map(|kept| kept.id.clone());
        let strays: Vec<String> = a
            .iter()
            .filter(|record| record["id"].as_str() != self.record_id.as_deref())
            .chain(of("AAAA").iter())
            .map(|record| {
                format!(
                    "{} {}",
                    record["type"].as_str().unwrap_or_default(),
                    record["content"].as_str().unwrap_or_default()
                )
            })
            .collect();
        let stray = (!strays.is_empty()).then(|| {
            format!(
                "{} also has {}; delete them in Cloudflare: natwg keeps one A record and is IPv4-only, and clients may dial the others",
                self.record,
                strays.join(", ")
            )
        });
        self.strays.send_if_modified(|now| {
            let changed = *now != stray;
            if changed && let Some(stray) = &stray {
                tracing::warn!("{stray}");
            }
            *now = stray.clone();
            changed
        });
        Ok(Found { kept, at })
    }

    /// Make the A record hold `ip`, not proxied and with natwg's TTL:
    /// replace the record `id`, or create one. Returns the record's ID.
    async fn write_a(&mut self, ip: Ipv4Addr, id: Option<String>) -> Result<String> {
        let zone_id = self.zone_id().await?;
        let records = format!("/zones/{zone_id}/dns_records");
        let body = Content::A(ip).body(&self.record);
        let id = match id {
            Some(id) => {
                let path = format!("{records}/{id}");
                self.call(Method::PUT, &path, &[], Some(&body)).await?;
                id
            }
            None => {
                let created = self.call(Method::POST, &records, &[], Some(&body)).await?;
                created["id"]
                    .as_str()
                    .ok_or_else(|| Error::new("CLOUDFLARE_API", "the created record has no id"))?
                    .to_owned()
            }
        };
        self.record_id = Some(id.clone());
        Ok(id)
    }

    /// The `result` of one API call that reports success.
    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.api))
            .query(query)
            .bearer_auth(self.token.expose());
        if let Some(body) = body {
            request = request.json(body);
        }
        let http = |e: reqwest::Error| Error::new("CLOUDFLARE_HTTP", error_chain(&e));
        let response = request.send().await.map_err(http)?;
        let status = response.status();
        let mut reply: Value = response.json().await.map_err(http)?;
        if reply["success"] != Value::Bool(true) {
            return Err(Error::new(
                "CLOUDFLARE_API",
                format!("HTTP {status}: {}", reply["errors"]),
            ));
        }
        Ok(reply["result"].take())
    }
}

fn first_id(result: &Value) -> Option<String> {
    Some(result.get(0)?["id"].as_str()?.to_owned())
}

/// Resolve when the wanted value changes. The server owns the sender for as
/// long as the publisher runs, so a closed channel never resolves.
async fn changed(wanted: &mut watch::Receiver<Option<Content>>) {
    if wanted.changed().await.is_err() {
        std::future::pending().await
    }
}
