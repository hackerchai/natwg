//! Keep the Cloudflare record that clients read: a TXT record with the
//! mapping as `"ip:port"`, the record natwg.py writes, or an A record with the
//! public IP.

use crate::config::CloudflareConfig;
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

const TTL: u32 = 60;
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

    /// Whether the `content` the API reports is this value.
    fn held_by(self, content: &str) -> bool {
        content.trim_matches('"') == self.to_string()
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
    zone_id: Option<String>,
    /// The ID of the record, and its type.
    record_id: Option<(&'static str, String)>,
}

impl Publisher {
    /// A publisher that sends API requests to `api`, which is [`API`] outside
    /// of tests. The requests may take the default route.
    pub fn new(config: &CloudflareConfig, api: &str) -> Result<Self> {
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
            zone_id: None,
            record_id: None,
        })
    }

    /// Publish every new value, one request at a time. A value already in
    /// the record is skipped, and a failed value is tried again after
    /// [`RETRY`], or at once when the wanted value moves on.
    pub async fn run(
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
                (Some(value), _) => {
                    let error = state.borrow().error().map(str::to_owned);
                    state.send_replace(Publish::Publishing { previous, error });
                    match self.publish(value).await {
                        Ok(wrote) => {
                            let (kind, record) = (value.record_type(), &self.record);
                            if wrote {
                                tracing::info!("published {kind} {record} = \"{value}\"");
                            } else {
                                tracing::info!("{kind} {record} holds \"{value}\" already");
                            }
                            let at = SystemTime::now();
                            state.send_replace(Publish::Published(Record { value, at }));
                        }
                        Err(error) => {
                            let error = error.to_string().replace(self.token.expose(), REDACTED);
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
                (None, _) => {}
            }
            changed(&mut wanted).await;
        }
    }

    /// Make the record hold `value`, and return whether that took a write.
    /// The lookup of the record ID, after a start or a failed write, reads
    /// what the record holds too, so a server that restarts on the same
    /// value finds it published.
    async fn publish(&mut self, value: Content) -> Result<bool> {
        let zone_id = match &self.zone_id {
            Some(id) => id.clone(),
            None => {
                let query = [("name", self.zone.as_str())];
                let zones = self.call(Method::GET, "/zones", &query, None).await?;
                let id = first_id(&zones).ok_or_else(|| {
                    Error::new(
                        "CLOUDFLARE_ZONE",
                        format!("the zone {} is not visible to the token", self.zone),
                    )
                })?;
                self.zone_id.insert(id).clone()
            }
        };
        let records = format!("/zones/{zone_id}/dns_records");
        let kind = value.record_type();
        if self
            .record_id
            .as_ref()
            .is_none_or(|(held, _)| *held != kind)
        {
            let query = [("type", kind), ("name", &self.record)];
            let found = self.call(Method::GET, &records, &query, None).await?;
            self.record_id = first_id(&found).map(|id| (kind, id));
            if let Some(count) = found.as_array().map(Vec::len).filter(|count| *count > 1) {
                tracing::warn!(
                    "{} has {count} {kind} records, and natwg keeps only the first; delete the others",
                    self.record
                );
            }
            let content = found[0]["content"].as_str().unwrap_or_default();
            if value.held_by(content) {
                return Ok(false);
            }
        }
        let body = value.body(&self.record);
        match &self.record_id {
            Some((_, id)) => {
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
                self.record_id = Some((kind, id.to_owned()));
                Ok(true)
            }
        }
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
