//! Publish the mapping as the TXT record that clients read, through the
//! Cloudflare API, with the record natwg.py writes.

use crate::config::CloudflareConfig;
use crate::keys::Secret;
use crate::server::{error_chain, keepalive::Mapping};
use crate::{Error, Result};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    net::SocketAddrV4,
    time::{Duration, SystemTime},
};
use tokio::{sync::watch, time::Instant};

pub const API: &str = "https://api.cloudflare.com/client/v4";

/// How long the publisher waits after a failure before it tries the same
/// value again. A new mapping does not wait.
pub const RETRY: Duration = Duration::from_secs(60);

const TTL: u32 = 60;
const COMMENT: &str = "natwg: WireGuard public endpoint, auto-updated";
const TIMEOUT: Duration = Duration::from_secs(15);
const REDACTED: &str = "<redacted>";

/// A value natwg wrote to the TXT record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub value: SocketAddrV4,
    pub at: SystemTime,
}

/// What the publisher is doing. `previous` is the value the record holds
/// from an earlier success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Publish {
    /// No mapping to publish yet.
    Idle,
    Publishing {
        previous: Option<Record>,
    },
    Published(Record),
    Failed {
        error: String,
        retry_at: Instant,
        previous: Option<Record>,
    },
}

impl Publish {
    /// The value the TXT record holds since natwg last wrote it.
    pub fn record(&self) -> Option<Record> {
        match self {
            Self::Idle => None,
            Self::Published(record) => Some(*record),
            Self::Publishing { previous } | Self::Failed { previous, .. } => *previous,
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
    record_id: Option<String>,
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

    /// Publish every new mapping, one request at a time. A value already in
    /// the record is skipped, and a failed value is tried again after
    /// [`RETRY`], or at once when the mapping moves on.
    pub async fn run(
        mut self,
        mut mapping: watch::Receiver<Option<Mapping>>,
        state: watch::Sender<Publish>,
    ) -> Infallible {
        loop {
            let wanted = mapping.borrow_and_update().map(|mapping| mapping.addr);
            let previous = state.borrow().record();
            match (wanted, previous) {
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
                    state.send_replace(Publish::Publishing { previous });
                    match self.publish(value).await {
                        Ok(()) => {
                            tracing::info!("published TXT {} = \"{value}\"", self.record);
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
                                () = changed(&mut mapping) => {}
                            }
                            continue;
                        }
                    }
                }
                (None, _) => {}
            }
            changed(&mut mapping).await;
        }
    }

    async fn publish(&mut self, value: SocketAddrV4) -> Result<()> {
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
        if self.record_id.is_none() {
            let query = [("type", "TXT"), ("name", &self.record)];
            self.record_id = first_id(&self.call(Method::GET, &records, &query, None).await?);
        }
        let body = json!({
            "type": "TXT",
            "name": self.record,
            "content": format!("\"{value}\""),
            "ttl": TTL,
            "comment": COMMENT,
        });
        match &self.record_id {
            Some(id) => {
                let path = format!("{records}/{id}");
                let put = self.call(Method::PUT, &path, &[], Some(&body)).await;
                // The record may be gone, so the next try looks it up again.
                if put.is_err() {
                    self.record_id = None;
                }
                put.map(drop)
            }
            None => {
                let created = self.call(Method::POST, &records, &[], Some(&body)).await?;
                let id = created["id"]
                    .as_str()
                    .ok_or_else(|| Error::new("CLOUDFLARE_API", "the created record has no id"))?;
                self.record_id = Some(id.to_owned());
                Ok(())
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

/// Resolve when the mapping changes. The supervisor owns the sender for as
/// long as the publisher runs, so a closed channel never resolves.
async fn changed(mapping: &mut watch::Receiver<Option<Mapping>>) {
    if mapping.changed().await.is_err() {
        std::future::pending().await
    }
}
