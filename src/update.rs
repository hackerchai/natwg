//! Self-update. `natwg update` installs the newest release from the download
//! site, or from GitHub Releases when the site fails, and restarts the natwg
//! services that run. A running server or client looks for a newer release
//! in the background and names it in its status file. It never installs one
//! by itself.
//!
//! CI uploads the archives of a release before the manifest that names them,
//! so neither source offers a version whose archives are missing.

use crate::config::UpdateConfig;
use crate::{Error, Result, service};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// The largest archive, and the largest binary in it, that natwg accepts.
const LIMIT: usize = 64 * 1024 * 1024;
const MANIFEST_LIMIT: usize = 64 * 1024;
const RELEASES_LIMIT: usize = 4 * 1024 * 1024;

/// The update manifest: the version of a release and its archives.
pub const MANIFEST: &str = "natwg-update.json";
/// The repository whose GitHub Releases carry the archives and the manifest.
/// It is private, so natwg sends a GitHub token to it.
pub const REPOSITORY: &str = "hackerchai/natwg";
/// The release download site (Cloudflare R2), tried before GitHub Releases.
pub const SITE: &str = "https://natwg-dl.hackerchai.com";
/// The platforms that every release has an archive for.
pub const TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
];

/// The answer of the last automatic check, which every natwg daemon on the
/// host shares, so the host checks once per interval.
#[cfg(target_os = "macos")]
pub const CHECK_CACHE: &str = "/usr/local/var/natwg/update-check.json";
#[cfg(not(target_os = "macos"))]
pub const CHECK_CACHE: &str = "/var/lib/natwg/update-check.json";

/// The lock that keeps two updates from running at once.
#[cfg(target_os = "macos")]
const LOCK: &str = "/var/run/natwg-update.lock";
#[cfg(not(target_os = "macos"))]
const LOCK: &str = "/run/natwg-update.lock";

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A daemon checks this long after it starts, then this often whether its
/// interval has passed, and gives one check this long.
const FIRST_CHECK: Duration = Duration::from_secs(60);
const CHECK_EVERY: Duration = Duration::from_secs(3600);
const CHECK_TIMEOUT: Duration = Duration::from_secs(20);

fn say(line: impl std::fmt::Display) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

#[derive(Deserialize, Debug)]
struct Asset {
    name: String,
    url: String,
}

#[derive(Deserialize, Debug)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u8,
    version: String,
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Artifact {
    target: String,
    asset: String,
    sha256: String,
}

/// The release platform of the running executable, including x86_64 under
/// Rosetta, so an update never switches an installation to another
/// architecture.
fn target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-musl"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        _ => Err(Error::new(
            "UPDATE_PLATFORM",
            "no release binary exists for this OS and architecture",
        )),
    }
}

/// The newest stable release that carries a manifest. A draft, a
/// prerelease and a release whose upload has not finished do not count.
fn select(releases: &[Release]) -> Result<&Release> {
    releases
        .iter()
        .filter(|r| !r.draft && !r.prerelease && r.assets.iter().any(|a| a.name == MANIFEST))
        .filter_map(|r| {
            let version = semver::Version::parse(r.tag_name.strip_prefix('v')?).ok()?;
            version.pre.is_empty().then_some((version, r))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, r)| r)
        .ok_or_else(|| {
            Error::new(
                "UPDATE_UNAVAILABLE",
                "no complete stable release has an update manifest yet; retry once the release is published",
            )
        })
}

/// Where to look for releases, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Source {
    /// A download site that serves `latest/` and `v{version}/` paths.
    Site(String),
    /// The GitHub Releases of an owner/repository.
    GitHub(String),
}

/// The download site, then the GitHub Releases of [`REPOSITORY`]. An explicit
/// repository is used alone.
fn sources(site: Option<&str>, repository: Option<&str>) -> Result<Vec<Source>> {
    if let Some(repository) = repository {
        validate_repository(repository).map_err(|e| Error::new("UPDATE_REPOSITORY", e))?;
        return Ok(vec![Source::GitHub(repository.to_owned())]);
    }
    let site = site.unwrap_or(SITE);
    validate_site(site).map_err(|e| Error::new("UPDATE_SOURCE", e))?;
    Ok(vec![
        Source::Site(site.to_owned()),
        Source::GitHub(REPOSITORY.to_owned()),
    ])
}

/// A download site is an exact `https://` origin. `http://127.0.0.1:<port>`
/// passes too, for a site on this host.
fn validate_site(base: &str) -> std::result::Result<(), String> {
    let invalid = || format!("the update download site {base:?} is not an exact https:// origin");
    let url = url::Url::parse(base).map_err(|_| invalid())?;
    let loopback = url.scheme() == "http" && url.host_str() == Some("127.0.0.1");
    if !(url.scheme() == "https" || loopback)
        || url.origin().ascii_serialization() != base
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_repository(repository: &str) -> std::result::Result<(), String> {
    let parts: Vec<&str> = repository.split('/').collect();
    let part = |p: &&str| {
        !p.is_empty()
            && *p != "."
            && *p != ".."
            && p.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
    };
    if parts.len() != 2 || !parts.iter().all(part) {
        return Err(format!(
            "the update repository {repository:?} is not a GitHub owner/repository"
        ));
    }
    Ok(())
}

/// Check the `update` object of a config, naming the field at fault.
pub fn validate(update: &UpdateConfig) -> std::result::Result<(), String> {
    if let Some(url) = &update.url {
        validate_site(url).map_err(|e| format!("update.url: {e}"))?;
    }
    if let Some(repository) = &update.repository {
        validate_repository(repository).map_err(|e| format!("update.repository: {e}"))?;
    }
    if let Some(check) = &update.check {
        check_interval(Some(check)).map_err(|e| format!("update.check: {}", e.message))?;
    }
    Ok(())
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("natwg-updater/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(network)
}

/// The body of `response`, refused once it grows past `limit`.
async fn body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network)? {
        if bytes.len() + chunk.len() > limit {
            return Err(invalid());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// The release download site.
struct Site {
    base: String,
    client: reqwest::Client,
}

impl Site {
    fn new(base: &str) -> Result<Self> {
        validate_site(base).map_err(|e| Error::new("UPDATE_SOURCE", e))?;
        Ok(Self {
            base: base.to_owned(),
            client: client()?,
        })
    }

    async fn get(&self, path: &str, limit: usize) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(format!("{}/{path}", self.base))
            .send()
            .await
            .map_err(network)?;
        if !response.status().is_success() {
            return Err(Error::new(
                "UPDATE_DOWNLOAD",
                format!(
                    "the download site answered HTTP {} for {path}",
                    response.status().as_u16()
                ),
            ));
        }
        body(response, limit).await
    }

    async fn manifest(&self) -> Result<Manifest> {
        let bytes = self
            .get(&format!("latest/{MANIFEST}"), MANIFEST_LIMIT)
            .await?;
        serde_json::from_slice(&bytes).map_err(|_| invalid())
    }

    async fn archive(&self, version: &str, asset: &str) -> Result<Vec<u8>> {
        self.get(&format!("v{version}/{asset}"), LIMIT).await
    }
}

/// The GitHub API of a private repository, with a token.
struct GitHub {
    client: reqwest::Client,
    token: String,
    repository: String,
}

impl GitHub {
    async fn new(repository: &str) -> Result<Self> {
        let token = token().await.ok_or_else(|| {
            Error::new(
                "UPDATE_AUTH",
                format!(
                    "the GitHub Releases of {repository} need a GitHub token, because the repository is private: set GH_TOKEN (sudo GH_TOKEN=\"$(gh auth token)\" natwg update) or log in with gh auth login"
                ),
            )
        })?;
        Ok(Self {
            client: client()?,
            token,
            repository: repository.to_owned(),
        })
    }

    async fn get(&self, url: &str, binary: bool, limit: usize) -> Result<Vec<u8>> {
        let parsed = url::Url::parse(url).map_err(|_| invalid())?;
        if parsed.scheme() != "https"
            || parsed.host_str() != Some("api.github.com")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(invalid());
        }
        let accept = if binary {
            "application/octet-stream"
        } else {
            "application/vnd.github+json"
        };
        let mut response = self
            .client
            .get(url)
            .header("Accept", accept)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(network)?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get("location")
                .and_then(|h| h.to_str().ok())
                .ok_or_else(invalid)?;
            let location = url::Url::parse(location).map_err(|_| invalid())?;
            if location.scheme() != "https"
                || !location
                    .host_str()
                    .is_some_and(|h| h.ends_with(".githubusercontent.com"))
            {
                return Err(invalid());
            }
            // The signed asset URL gets no repository token.
            response = self.client.get(location).send().await.map_err(network)?;
        }
        let status = response.status().as_u16();
        if !response.status().is_success() {
            let repository = &self.repository;
            return Err(Error::new(
                "UPDATE_DOWNLOAD",
                match status {
                    401 | 404 => format!(
                        "GitHub refused the token for {repository} (HTTP {status}); it needs Contents: read on the repository. Set GH_TOKEN or log in again with gh auth login"
                    ),
                    403 | 429 => format!(
                        "GitHub denied or rate-limited the request (HTTP {status}); retry later"
                    ),
                    _ => format!("GitHub answered HTTP {status}"),
                },
            ));
        }
        body(response, limit).await
    }

    async fn releases(&self) -> Result<Vec<Release>> {
        let url = format!(
            "https://api.github.com/repos/{}/releases?per_page=100",
            self.repository
        );
        let bytes = self.get(&url, false, RELEASES_LIMIT).await?;
        serde_json::from_slice(&bytes).map_err(|_| invalid())
    }
}

/// GH_TOKEN or GITHUB_TOKEN, else what `gh auth token` prints within 5 s.
async fn token() -> Option<String> {
    let set = ["GH_TOKEN", "GITHUB_TOKEN"].into_iter().find_map(|name| {
        let value = std::env::var(name).ok()?;
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    });
    if set.is_some() {
        return set;
    }
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("gh")
            .args(["auth", "token", "--hostname", "github.com"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    let token = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (output.status.success() && !token.is_empty()).then_some(token)
}

/// A stable version, as the manifest or a release tag names it.
fn stable(version: &str) -> Result<semver::Version> {
    semver::Version::parse(version)
        .ok()
        .filter(|v| v.pre.is_empty() && v.build.is_empty())
        .ok_or_else(invalid)
}

/// The artifact of this platform in the manifest of `version`.
fn artifact<'a>(manifest: &'a Manifest, version: &str) -> Result<&'a Artifact> {
    if manifest.schema != 1
        || manifest.version != version
        || manifest.artifacts.len() != TARGETS.len()
    {
        return Err(invalid());
    }
    let platform = target()?;
    let artifact = manifest
        .artifacts
        .iter()
        .find(|a| a.target == platform)
        .ok_or_else(|| {
            Error::new(
                "UPDATE_PLATFORM",
                format!("natwg {version} has no archive for {platform}"),
            )
        })?;
    if artifact.asset != format!("natwg-{version}-{platform}.tar.gz")
        || artifact.sha256.len() != 64
        || !artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    Ok(artifact)
}

/// The natwg binary in `archive`, once the archive matches the checksum of
/// the manifest and its TARGET file names the artifact's platform. Only
/// `natwg-{version}-{target}/bin/natwg` and `.../TARGET` are read.
fn verified_binary(archive: &[u8], artifact: &Artifact, version: &str) -> Result<Vec<u8>> {
    if hex::encode(Sha256::digest(archive)) != artifact.sha256.to_ascii_lowercase() {
        return Err(Error::new(
            "UPDATE_CHECKSUM",
            format!(
                "{} does not match the checksum of the manifest; nothing was installed",
                artifact.asset
            ),
        ));
    }
    let prefix = format!("natwg-{version}-{}", artifact.target);
    let (binary_path, target_path) = (format!("{prefix}/bin/natwg"), format!("{prefix}/TARGET"));
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    let mut binary = None;
    let mut platform = None;
    for entry in archive.entries().map_err(|_| invalid())? {
        let entry = entry.map_err(|_| invalid())?;
        let path = entry.path().map_err(|_| invalid())?.into_owned();
        let slot = if path == Path::new(&binary_path) {
            &mut binary
        } else if path == Path::new(&target_path) {
            &mut platform
        } else {
            continue;
        };
        if !entry.header().entry_type().is_file() {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        entry
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() > LIMIT || slot.replace(bytes).is_some() {
            return Err(invalid());
        }
    }
    let platform = platform
        .as_deref()
        .and_then(|b| std::str::from_utf8(b).ok());
    if platform.map(str::trim) != Some(artifact.target.as_str()) {
        return Err(invalid());
    }
    binary.filter(|b| !b.is_empty()).ok_or_else(invalid)
}

/// The cached answer of the last automatic check.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checked {
    checked_at: u64,
    latest: String,
}

/// `NATWG_UPDATE_CHECK` / `update.check`: `off`, or `<n>m`, `<n>h` or `<n>d`
/// of at least one hour. None means one day.
pub fn check_interval(value: Option<&str>) -> Result<Option<Duration>> {
    let Some(value) = value else {
        return Ok(Some(Duration::from_secs(86400)));
    };
    if value == "off" {
        return Ok(None);
    }
    let invalid = || {
        Error::new(
            "UPDATE_CHECK",
            format!("{value:?} is neither off nor an interval of at least 1h such as 6h or 1d"),
        )
    };
    let (number, unit) = value.split_at(value.len().saturating_sub(1));
    let seconds = match unit {
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(invalid()),
    };
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let total = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(seconds))
        .ok_or_else(invalid)?;
    if total < 3600 {
        return Err(invalid());
    }
    Ok(Some(Duration::from_secs(total)))
}

fn read_checked(cache: &Path) -> Option<Checked> {
    let bytes = fs::read(cache).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The prompt that `natwg status` prints when `latest` is newer than
/// `running`, the natwg that wrote the status (this natwg when unknown).
pub fn notice(running: Option<&str>, latest: &str) -> Option<String> {
    let latest = stable(latest).ok()?;
    let running = running
        .and_then(|v| semver::Version::parse(v).ok())
        .or_else(|| semver::Version::parse(VERSION).ok())?;
    (latest > running)
        .then(|| format!("Update available: {running} → {latest}. Run sudo natwg update."))
}

/// The settings of the automatic check.
#[derive(Debug, PartialEq, Eq)]
pub struct Schedule {
    /// None turns the check off.
    pub interval: Option<Duration>,
    pub site: Option<String>,
    pub repository: Option<String>,
}

/// The automatic check's settings: NATWG_UPDATE_CHECK, NATWG_UPDATE_URL and
/// NATWG_UPDATE_REPOSITORY, else the `update` object of the config.
pub fn schedule(config: Option<&UpdateConfig>) -> Result<Schedule> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let config = config.cloned().unwrap_or_default();
    Ok(Schedule {
        interval: check_interval(var("NATWG_UPDATE_CHECK").or(config.check).as_deref())?,
        site: var("NATWG_UPDATE_URL").or(config.url),
        repository: var("NATWG_UPDATE_REPOSITORY").or(config.repository),
    })
}

/// The newest release that the automatic check of this process knows of.
static LATEST: Mutex<Option<String>> = Mutex::new(None);

/// The newest release that the automatic check of this process knows of,
/// for the status file. None when the check is off or has no answer yet.
pub fn latest() -> Option<String> {
    LATEST.lock().ok()?.clone()
}

fn remember(cache: &Path) {
    let latest = read_checked(cache).and_then(|c| stable(&c.latest).ok());
    if let (Some(latest), Ok(mut known)) = (latest, LATEST.lock()) {
        *known = Some(latest.to_string());
    }
}

/// Look for a newer release in the background, as [`schedule`] says: a
/// minute after the start, then every hour whether the interval has passed
/// since the last check of any natwg daemon on the host. The answer goes to
/// [`latest`], and from there into the status file. It never blocks or
/// fails the tunnel, and it never installs anything. Call it inside the
/// runtime of the daemon.
pub fn spawn_checks(config: Option<&UpdateConfig>) {
    let schedule = match schedule(config) {
        Ok(schedule) => schedule,
        Err(error) => {
            tracing::warn!("no update checks: {error}");
            return;
        }
    };
    let Some(interval) = schedule.interval else {
        return;
    };
    let sources = match sources(schedule.site.as_deref(), schedule.repository.as_deref()) {
        Ok(sources) => sources,
        Err(error) => {
            tracing::warn!("no update checks: {error}");
            return;
        }
    };
    let cache = PathBuf::from(CHECK_CACHE);
    remember(&cache);
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_CHECK).await;
        loop {
            let checked = tokio::time::timeout(
                CHECK_TIMEOUT,
                refresh_at(&cache, interval, &sources, SystemTime::now()),
            )
            .await;
            remember(&cache);
            if let Ok(Ok(true)) = checked
                && let Some(notice) = latest().and_then(|latest| notice(None, &latest))
            {
                tracing::info!("{notice}");
            }
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

/// Ask the sources for the newest release if `interval` has passed since the
/// last check, and cache the answer. Returns whether a check ran. A failed
/// check keeps the previous answer, and the next one runs again.
async fn refresh_at(
    cache: &Path,
    interval: Duration,
    sources: &[Source],
    now: SystemTime,
) -> Result<bool> {
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_secs();
    if read_checked(cache).is_some_and(|c| now.saturating_sub(c.checked_at) < interval.as_secs()) {
        return Ok(false);
    }
    let mut failure = None;
    for source in sources {
        let latest = match source {
            Source::Site(base) => Site::new(base)?.manifest().await.map(|m| m.version),
            Source::GitHub(repository) => latest_github(repository).await,
        };
        match latest.and_then(|v| stable(&v)) {
            Ok(latest) => {
                let checked = Checked {
                    checked_at: now,
                    latest: latest.to_string(),
                };
                let bytes = serde_json::to_vec(&checked).map_err(|_| invalid())?;
                write_cache(cache, &bytes)?;
                return Ok(true);
            }
            Err(error) => failure = Some(error),
        }
    }
    Err(failure.unwrap_or_else(invalid))
}

/// Atomically replace the check cache, readable by everyone.
fn write_cache(cache: &Path, bytes: &[u8]) -> Result<()> {
    let dir = cache.parent().ok_or_else(invalid)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(dir)
        .map_err(|e| storage(dir, e))?;
    let mut stage = tempfile::NamedTempFile::new_in(dir).map_err(|e| storage(dir, e))?;
    stage
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))
        .and_then(|()| stage.write_all(bytes))
        .map_err(|e| storage(cache, e))?;
    stage.persist(cache).map_err(|e| storage(cache, e.error))?;
    Ok(())
}

async fn latest_github(repository: &str) -> Result<String> {
    let github = GitHub::new(repository).await?;
    let releases = github.releases().await?;
    let release = select(&releases)?;
    Ok(release
        .tag_name
        .strip_prefix('v')
        .ok_or_else(invalid)?
        .to_owned())
}

/// Where natwg is installed, and the lock of `natwg update`.
#[derive(Clone, Debug)]
pub struct Layout {
    /// The binary that the services run, [`service::BINARY`].
    pub service: PathBuf,
    /// The running executable, resolved.
    pub executable: PathBuf,
    pub lock: PathBuf,
}

impl Layout {
    fn system() -> Result<Self> {
        let running = std::env::current_exe().map_err(|e| storage(Path::new("natwg"), e))?;
        let executable = fs::canonicalize(&running).map_err(|e| storage(&running, e))?;
        let service = fs::canonicalize(service::BINARY).unwrap_or_else(|_| service::BINARY.into());
        Ok(Self {
            service,
            executable,
            lock: LOCK.into(),
        })
    }
}

/// An executable that a package manager owns, such as one in a Homebrew
/// Cellar or the Nix store.
fn managed(path: &Path) -> bool {
    let parts: Vec<_> = path.components().map(|c| c.as_os_str()).collect();
    parts.iter().any(|p| *p == "Cellar")
        || parts.windows(2).any(|w| w[0] == "nix" && w[1] == "store")
}

/// The files that the update to `latest` replaces: the service binary when
/// it is older than `latest` or does not say its version, and the running
/// executable when it is another file and older than `latest`. `service` is
/// None without a service binary, else the version that it reports. A file
/// that is as new as `latest` or newer stays.
fn plan(
    layout: &Layout,
    current: &semver::Version,
    service: Option<Option<semver::Version>>,
    latest: &semver::Version,
) -> Result<Vec<PathBuf>> {
    let mut targets = Vec::new();
    if let Some(version) = service
        && version.is_none_or(|version| version < *latest)
    {
        targets.push(layout.service.clone());
    }
    if layout.executable != layout.service && current < latest {
        if managed(&layout.executable) {
            return Err(Error::new(
                "UPDATE_MANAGED",
                format!(
                    "{} belongs to a package manager; upgrade it with that, then run sudo natwg service install to update the service",
                    layout.executable.display()
                ),
            ));
        }
        targets.push(layout.executable.clone());
    }
    Ok(targets)
}

/// The version that the natwg at `path` reports, None when it reports none.
fn version_of(path: &Path) -> Option<semver::Version> {
    let mut command = Command::new(path);
    command.arg("--version").env_clear();
    let output = output_within(&mut command, Duration::from_secs(10))?;
    let text = String::from_utf8(output.stdout).ok()?;
    let version = text.trim().strip_prefix("natwg ")?;
    output
        .status
        .success()
        .then(|| semver::Version::parse(version).ok())?
}

/// What `command` printed, if it exited within `timeout`.
fn output_within(command: &mut Command, timeout: Duration) -> Option<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let deadline = Instant::now() + timeout;
    let mut child = loop {
        match command.spawn() {
            Ok(child) => break child,
            // Linux refuses to run a file that a process holds open for
            // writing, as a child that another thread forked meanwhile
            // does until it execs.
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    };
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Print the versions, and say what the update to `latest` replaces. None
/// means nothing: the check ends here, or every file is up to date.
fn decide(layout: &Layout, latest: &semver::Version, check: bool) -> Result<Option<Vec<PathBuf>>> {
    let current = semver::Version::parse(VERSION).map_err(|_| invalid())?;
    let service = layout
        .service
        .is_file()
        .then(|| version_of(&layout.service));
    say(format!("Latest release : natwg {latest}"));
    say(format!(
        "This natwg     : {current} ({})",
        layout.executable.display()
    ));
    if layout.executable != layout.service {
        match &service {
            Some(Some(version)) => say(format!(
                "Service binary : {version} ({})",
                layout.service.display()
            )),
            Some(None) => say(format!(
                "Service binary : version unknown ({})",
                layout.service.display()
            )),
            None => {}
        }
    }
    let targets = plan(layout, &current, service, latest)?;
    if current > *latest {
        say("This natwg is newer than the latest release; it stays.");
    }
    if targets.is_empty() {
        say("Already up to date.");
        return Ok(None);
    }
    if check {
        say(format!("Run sudo natwg update to install natwg {latest}."));
        return Ok(None);
    }
    Ok(Some(targets))
}

/// What a source offered: nothing to do, or a verified binary for `targets`.
enum Fetched {
    Done,
    Install {
        version: String,
        binary: Vec<u8>,
        targets: Vec<PathBuf>,
    },
}

async fn fetch(source: &Source, layout: &Layout, check: bool) -> Result<Fetched> {
    match source {
        Source::Site(base) => {
            let site = Site::new(base)?;
            let manifest = site.manifest().await?;
            let latest = stable(&manifest.version)?;
            let Some(targets) = decide(layout, &latest, check)? else {
                return Ok(Fetched::Done);
            };
            let version = latest.to_string();
            let artifact = artifact(&manifest, &version)?;
            say(format!("Downloading {}…", artifact.asset));
            let archive = site.archive(&version, &artifact.asset).await?;
            let binary = verified_binary(&archive, artifact, &version)?;
            Ok(Fetched::Install {
                version,
                binary,
                targets,
            })
        }
        Source::GitHub(repository) => {
            let github = GitHub::new(repository).await?;
            let releases = github.releases().await?;
            let release = select(&releases)?;
            let latest = stable(release.tag_name.strip_prefix('v').ok_or_else(invalid)?)?;
            let Some(targets) = decide(layout, &latest, check)? else {
                return Ok(Fetched::Done);
            };
            let version = latest.to_string();
            let asset = |name: &str| {
                release
                    .assets
                    .iter()
                    .find(|a| a.name == name)
                    .ok_or_else(invalid)
            };
            let manifest = github
                .get(&asset(MANIFEST)?.url, true, MANIFEST_LIMIT)
                .await?;
            let manifest: Manifest = serde_json::from_slice(&manifest).map_err(|_| invalid())?;
            let artifact = artifact(&manifest, &version)?;
            say(format!("Downloading {}…", artifact.asset));
            let archive = github
                .get(&asset(&artifact.asset)?.url, true, LIMIT)
                .await?;
            let binary = verified_binary(&archive, artifact, &version)?;
            Ok(Fetched::Install {
                version,
                binary,
                targets,
            })
        }
    }
}

/// What `natwg update` was asked to do.
pub struct Request<'a> {
    /// Only report the versions.
    pub check: bool,
    /// The download site (default [`SITE`]).
    pub site: Option<&'a str>,
    /// The GitHub repository to use alone.
    pub repository: Option<&'a str>,
}

/// `natwg update`: find the newest release, and unless `request.check`,
/// install it over the service binary and the running executable, then
/// restart the natwg services that run.
pub fn run(request: &Request) -> Result<()> {
    if !request.check && unsafe { libc::geteuid() } != 0 {
        return Err(Error::new(
            "NOT_ROOT",
            "natwg update replaces the root-owned service binary and restarts the services; run it as root, or pass --check",
        ));
    }
    let sources = sources(request.site, request.repository)?;
    let layout = Layout::system()?;
    let _lock = match request.check {
        true => None,
        false => Some(lock(&layout.lock)?),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::new("RUNTIME_UNAVAILABLE", e.to_string()))?;
    let mut failure = None;
    for source in &sources {
        match source {
            Source::Site(base) => say(format!("Checking the download site {base}…")),
            Source::GitHub(repository) => say(format!("Checking GitHub Releases of {repository}…")),
        }
        match runtime.block_on(fetch(source, &layout, request.check)) {
            Ok(Fetched::Done) => return Ok(()),
            Ok(Fetched::Install {
                version,
                binary,
                targets,
            }) => {
                if targets.contains(&layout.service)
                    && let Some(dir) = layout.service.parent()
                {
                    service::require_root_only(dir)?;
                }
                return install(&layout, &targets, &version, &binary, &SystemServices);
            }
            // Nothing changed yet, so the next source can be tried.
            Err(error) if matches!(source, Source::Site(_)) => {
                say(format!("The download site failed: {error}"));
                failure = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(failure.unwrap_or_else(invalid))
}

/// Hold the update lock until the file is dropped.
fn lock(path: &Path) -> Result<fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| storage(path, e))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::new(
            "UPDATE_BUSY",
            "another natwg update runs; retry once it ends",
        ));
    }
    Ok(file)
}

/// The services that an update restarts, which tests replace.
pub trait Services {
    type Job: std::fmt::Display;

    /// The services that run a process now.
    fn running(&self) -> Result<Vec<Self::Job>>;

    /// Restart `job` and wait until a new process serves. Returns its pid.
    fn restart(&self, job: &Self::Job) -> Result<u32>;
}

/// The launchd or systemd services of this host.
pub struct SystemServices;

impl Services for SystemServices {
    type Job = service::Job;

    fn running(&self) -> Result<Vec<service::Job>> {
        service::running()
    }

    fn restart(&self, job: &service::Job) -> Result<u32> {
        service::restart_job(job)
    }
}

/// Where an update keeps the file it replaced at `path`: `.natwg.previous`
/// beside `natwg`.
pub fn backup_path(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(".{name}.previous"))
}

/// A file before the update: its bytes, owner and mode.
struct Original {
    path: PathBuf,
    bytes: Vec<u8>,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl Original {
    fn read(path: &Path) -> Result<Self> {
        let meta = fs::symlink_metadata(path).map_err(|e| storage(path, e))?;
        if !meta.is_file() {
            return Err(Error::new(
                "UPDATE_TARGET",
                format!("{} is not a regular file", path.display()),
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            bytes: fs::read(path).map_err(|e| storage(path, e))?,
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode() & 0o777,
        })
    }

    /// A closed temporary file beside the original that holds `bytes` with
    /// its owner and mode.
    fn stage(&self, bytes: &[u8]) -> Result<tempfile::TempPath> {
        let dir = self.path.parent().ok_or_else(invalid)?;
        let fail = |e| storage(dir, e);
        let mut stage = tempfile::Builder::new()
            .prefix(".natwg-new-")
            .tempfile_in(dir)
            .map_err(fail)?;
        let file = stage.as_file();
        let meta = file.metadata().map_err(fail)?;
        // A root update of a user's natwg leaves it the user's.
        if (meta.uid(), meta.gid()) != (self.uid, self.gid) {
            std::os::unix::fs::fchown(file, Some(self.uid), Some(self.gid)).map_err(fail)?;
        }
        file.set_permissions(fs::Permissions::from_mode(self.mode))
            .map_err(fail)?;
        stage.write_all(bytes).map_err(fail)?;
        stage.as_file().sync_all().map_err(fail)?;
        // Closed, because Linux refuses to run a file open for writing.
        Ok(stage.into_temp_path())
    }

    /// Atomically put `staged` at `path`.
    fn commit(&self, staged: tempfile::TempPath, path: &Path) -> Result<()> {
        staged.persist(path).map_err(|e| storage(path, e.error))?;
        let dir = path.parent().ok_or_else(invalid)?;
        fs::File::open(dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| storage(dir, e))
    }

    /// Atomically write `bytes` at `path` with the owner and mode of the original.
    fn write(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        self.commit(self.stage(bytes)?, path)
    }

    fn backup(&self) -> Result<()> {
        self.write(&backup_path(&self.path), &self.bytes)
    }

    fn restore(&self) -> Result<()> {
        self.write(&self.path, &self.bytes)
    }
}

/// Fail unless the natwg at `staged` reports `natwg {version}`.
fn check_version(staged: &Path, version: &str) -> Result<()> {
    match version_of(staged) {
        Some(reported) if reported.to_string() == version => Ok(()),
        _ => Err(Error::new(
            "UPDATE_BINARY",
            format!("the downloaded natwg does not report natwg {version}; nothing was installed"),
        )),
    }
}

/// Put `binary`, a natwg that reports `version`, over each of `targets`
/// with its owner and mode, keeping the file it replaces beside it. When the
/// service binary is one of them, restart the services that run, one at a
/// time, each until it serves again. When one does not come back, put every
/// previous file back, restart the services again and fail.
pub fn install(
    layout: &Layout,
    targets: &[PathBuf],
    version: &str,
    binary: &[u8],
    services: &impl Services,
) -> Result<()> {
    let restarts = targets.contains(&layout.service);
    // A service whose config no longer loads stops the update before
    // anything changes.
    let jobs = if restarts {
        services.running()?
    } else {
        Vec::new()
    };
    let originals = targets
        .iter()
        .map(|path| Original::read(path))
        .collect::<Result<Vec<_>>>()?;
    let Some(first) = originals.first() else {
        return Ok(());
    };
    let staged = first.stage(binary)?;
    check_version(&staged, version)?;
    let mut staged = Some(staged);
    for (done, original) in originals.iter().enumerate() {
        let replaced = original.backup().and_then(|()| match staged.take() {
            Some(staged) => original.commit(staged, &original.path),
            None => original.write(&original.path, binary),
        });
        if let Err(error) = replaced {
            if done == 0 {
                return Err(error);
            }
            let restored = restore(&originals[..done]);
            return Err(Error::new(
                error.code,
                format!("{}; {restored}", error.message),
            ));
        }
    }
    for original in &originals {
        say(format!(
            "Updated {} to natwg {version}; the previous one is {}",
            original.path.display(),
            backup_path(&original.path).display()
        ));
    }
    for (index, job) in jobs.iter().enumerate() {
        let error = match services.restart(job) {
            Ok(pid) => {
                say(format!("Restarted {job}: running, pid {pid}"));
                continue;
            }
            Err(error) => error,
        };
        let mut message = format!(
            "{job} did not come back on natwg {version}, so {}",
            restore(&originals)
        );
        let (mut back, mut failed) = (Vec::new(), String::new());
        for job in &jobs[..=index] {
            match services.restart(job) {
                Ok(pid) => {
                    say(format!(
                        "Restarted {job} on the previous natwg: running, pid {pid}"
                    ));
                    back.push(job.to_string());
                }
                Err(error) => {
                    failed.push_str(&format!("; restarting {job} on them failed: {error}"))
                }
            }
        }
        if !back.is_empty() {
            message.push_str(&format!(" and restarted {} on them", back.join(" and ")));
        }
        // The error goes last, because it can end with lines of the log.
        return Err(Error::new(
            "UPDATE_ROLLED_BACK",
            format!("{message}{failed}.\n{error}"),
        ));
    }
    Ok(())
}

/// Put each original back, and say how that went.
fn restore(originals: &[Original]) -> String {
    let failed: Vec<String> = originals
        .iter()
        .filter_map(|original| original.restore().err().map(|e| e.to_string()))
        .collect();
    match (originals.is_empty(), failed.is_empty()) {
        (true, _) => String::new(),
        (false, true) => "natwg put the previous binaries back".to_owned(),
        (false, false) => format!(
            "natwg could not put every previous binary back ({}), and each is beside it as .natwg.previous",
            failed.join("; ")
        ),
    }
}

fn invalid() -> Error {
    Error::new(
        "UPDATE_INVALID",
        "the release metadata or archive is incomplete or invalid; nothing was installed",
    )
}

fn network(error: reqwest::Error) -> Error {
    let error = error.without_url();
    if error.is_timeout() {
        return Error::new("UPDATE_NETWORK", "the request timed out; retry later");
    }
    let mut text = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    Error::new("UPDATE_NETWORK", format!("the request failed: {text}"))
}

fn storage(path: &Path, error: std::io::Error) -> Error {
    Error::new("UPDATE_IO", format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests;
