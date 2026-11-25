use super::*;
use std::cell::RefCell;

/// Tests that write a script and run it take turns: a child that another
/// test forks meanwhile holds the script open for writing until it execs,
/// and Linux refuses to run a file in that state.
static SCRIPTS: Mutex<()> = Mutex::new(());

fn scripts() -> std::sync::MutexGuard<'static, ()> {
    SCRIPTS.lock().unwrap_or_else(|e| e.into_inner())
}

fn version(text: &str) -> semver::Version {
    semver::Version::parse(text).unwrap()
}

/// A natwg stand-in that reports `natwg {version}`.
fn script(version: &str) -> Vec<u8> {
    format!("#!/bin/sh\necho 'natwg {version}'\n").into_bytes()
}

fn file(path: &Path, bytes: &[u8], mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().mode() & 0o7777
}

#[test]
fn the_check_interval_defaults_to_a_day_and_can_be_turned_off() {
    let hour = Duration::from_secs(3600);
    assert_eq!(check_interval(None).unwrap(), Some(24 * hour));
    assert_eq!(check_interval(Some("off")).unwrap(), None);
    assert_eq!(check_interval(Some("6h")).unwrap(), Some(6 * hour));
    assert_eq!(check_interval(Some("2d")).unwrap(), Some(48 * hour));
    assert_eq!(
        check_interval(Some("90m")).unwrap(),
        Some(Duration::from_secs(5400))
    );
    for bad in [
        "30m",
        "0h",
        "h",
        "1w",
        "-1h",
        "+2h",
        "",
        "24",
        "1.5h",
        "99999999999999999d",
    ] {
        assert_eq!(
            check_interval(Some(bad)).unwrap_err().code,
            "UPDATE_CHECK",
            "{bad:?}"
        );
    }
}

#[test]
fn the_config_sets_the_schedule() {
    let config = UpdateConfig {
        url: Some("https://mirror.example.org".into()),
        repository: Some("me/fork".into()),
        check: Some("6h".into()),
    };
    assert_eq!(
        schedule(Some(&config)).unwrap(),
        Schedule {
            interval: Some(Duration::from_secs(6 * 3600)),
            site: Some("https://mirror.example.org".into()),
            repository: Some("me/fork".into()),
        }
    );
    let off = UpdateConfig {
        check: Some("off".into()),
        ..UpdateConfig::default()
    };
    assert_eq!(schedule(Some(&off)).unwrap().interval, None);
    assert_eq!(
        schedule(None).unwrap().interval,
        Some(Duration::from_secs(86400))
    );
}

#[test]
fn a_config_names_the_update_field_at_fault() {
    assert!(validate(&UpdateConfig::default()).is_ok());
    for (update, field) in [
        (
            UpdateConfig {
                url: Some("http://mirror.example.org".into()),
                ..UpdateConfig::default()
            },
            "update.url",
        ),
        (
            UpdateConfig {
                repository: Some("not a repository".into()),
                ..UpdateConfig::default()
            },
            "update.repository",
        ),
        (
            UpdateConfig {
                check: Some("10m".into()),
                ..UpdateConfig::default()
            },
            "update.check",
        ),
    ] {
        let error = validate(&update).unwrap_err();
        assert!(error.starts_with(field), "{error}");
    }
}

#[test]
fn a_newer_release_produces_a_notice() {
    let text = notice(Some("0.2.0"), "0.3.1").unwrap();
    assert_eq!(
        text,
        "Update available: 0.2.0 → 0.3.1. Run sudo natwg update."
    );
    assert_eq!(notice(Some("0.3.1"), "0.3.1"), None);
    assert_eq!(notice(Some("0.4.0"), "0.3.1"), None);
    assert_eq!(notice(Some("0.2.0"), "0.3.1-rc.1"), None);
    assert_eq!(notice(Some("0.2.0"), "garbage"), None);
    // Without the version of the daemon, this natwg's counts.
    assert!(
        notice(None, "99.0.0")
            .unwrap()
            .contains(&format!("{VERSION} → 99.0.0"))
    );
    assert_eq!(notice(None, VERSION), None);
}

#[test]
fn the_download_site_comes_first_and_github_releases_are_the_fallback() {
    assert_eq!(
        sources(None, None).unwrap(),
        vec![
            Source::Site(SITE.into()),
            Source::GitHub("hackerchai/natwg".into())
        ]
    );
    assert_eq!(
        sources(Some("https://mirror.example.org"), None).unwrap(),
        vec![
            Source::Site("https://mirror.example.org".into()),
            Source::GitHub("hackerchai/natwg".into())
        ]
    );
    // A repository is used alone.
    assert_eq!(
        sources(Some("https://mirror.example.org"), Some("me/fork")).unwrap(),
        vec![Source::GitHub("me/fork".into())]
    );
    for bad in [
        "http://mirror.example.org",
        "https://x.example/path",
        "https://x.example/",
        "https://user:pw@x.example",
        "ftp://x",
        "http://127.0.0.2:9",
        "http://localhost:9",
        "",
    ] {
        assert_eq!(
            sources(Some(bad), None).unwrap_err().code,
            "UPDATE_SOURCE",
            "{bad}"
        );
    }
    assert!(sources(Some("http://127.0.0.1:9"), None).is_ok());
    for bad in [
        "me",
        "me/fork/x",
        "/fork",
        "me/",
        "me/../x",
        "me/f k",
        "../x",
    ] {
        assert_eq!(
            sources(None, Some(bad)).unwrap_err().code,
            "UPDATE_REPOSITORY",
            "{bad}"
        );
    }
}

/// Serve fixed paths over loopback HTTP; anything else is 404.
async fn site(files: Vec<(String, Vec<u8>)>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut head = Vec::new();
            let mut byte = [0];
            while !head.ends_with(b"\r\n\r\n") {
                if socket.read_exact(&mut byte).await.is_err() {
                    break;
                }
                head.push(byte[0]);
            }
            let line = String::from_utf8_lossy(&head).to_string();
            let path = line.split(' ').nth(1).unwrap_or("").to_owned();
            let (status, body) = match files.iter().find(|(p, _)| *p == path) {
                Some((_, body)) => ("200 OK", body.clone()),
                None => ("404 Not Found", Vec::new()),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&body).await;
        }
    });
    base
}

fn manifest_at(path: &str, version: &str) -> (String, Vec<u8>) {
    let manifest = serde_json::json!({"schema": 1, "version": version, "artifacts": []});
    (path.to_owned(), manifest.to_string().into_bytes())
}

#[tokio::test]
async fn the_download_site_serves_the_latest_manifest_and_versioned_archives() {
    let base = site(vec![
        manifest_at("/latest/natwg-update.json", "9.9.9"),
        ("/v9.9.9/natwg-9.9.9-x.tar.gz".into(), b"archive".to_vec()),
    ])
    .await;
    let site = Site::new(&base).unwrap();
    assert_eq!(site.manifest().await.unwrap().version, "9.9.9");
    assert_eq!(
        site.archive("9.9.9", "natwg-9.9.9-x.tar.gz").await.unwrap(),
        b"archive"
    );
    assert_eq!(
        site.archive("9.9.9", "missing.tar.gz")
            .await
            .unwrap_err()
            .code,
        "UPDATE_DOWNLOAD"
    );
    // An unreachable site is a plain network failure, so GitHub comes next.
    let down = Site::new("http://127.0.0.1:9").unwrap();
    assert_eq!(down.manifest().await.unwrap_err().code, "UPDATE_NETWORK");
}

#[tokio::test]
async fn checks_run_only_when_the_interval_has_passed() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("state/update-check.json");
    let base = site(vec![manifest_at("/latest/natwg-update.json", "99.1.0")]).await;
    let day = Duration::from_secs(86400);
    let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    assert!(
        refresh_at(&cache, day, &[Source::Site(base.clone())], start)
            .await
            .unwrap()
    );
    assert_eq!(read_checked(&cache).unwrap().latest, "99.1.0");
    assert_eq!(mode(&cache), 0o644);
    // Within the interval nothing is fetched, even from a site that is down.
    let down = [Source::Site("http://127.0.0.1:9".into())];
    let later = start + day - Duration::from_secs(1);
    assert!(!refresh_at(&cache, day, &down, later).await.unwrap());
    // Once due, a failed check leaves the previous answer in place.
    let due = start + day;
    assert!(refresh_at(&cache, day, &down, due).await.is_err());
    assert_eq!(read_checked(&cache).unwrap().latest, "99.1.0");
    assert!(
        refresh_at(&cache, day, &[Source::Site(base)], due)
            .await
            .unwrap()
    );
    // The process takes the cached answer for its status file.
    remember(&cache);
    assert_eq!(latest().as_deref(), Some("99.1.0"));
}

#[tokio::test]
async fn a_check_refuses_a_version_that_is_not_stable() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("update-check.json");
    let base = site(vec![manifest_at("/latest/natwg-update.json", "9.9.9-rc.1")]).await;
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let error = refresh_at(
        &cache,
        Duration::from_secs(3600),
        &[Source::Site(base)],
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "UPDATE_INVALID");
    assert!(!cache.exists());
}

#[test]
fn the_newest_complete_stable_release_wins_over_drafts_and_partial_uploads() {
    let releases: Vec<Release> = serde_json::from_value(serde_json::json!([
        {"tag_name":"v9.0.0","draft":false,"prerelease":false,"assets":[]},
        {"tag_name":"v1.2.0","draft":false,"prerelease":false,"assets":[{"name":MANIFEST,"url":"https://api.github.com/asset"}]},
        {"tag_name":"v1.10.0","draft":false,"prerelease":false,"assets":[{"name":MANIFEST,"url":"https://api.github.com/asset"}]},
        {"tag_name":"v2.0.0","draft":true,"prerelease":false,"assets":[{"name":MANIFEST,"url":"https://api.github.com/asset"}]},
        {"tag_name":"v3.0.0-rc.1","draft":false,"prerelease":false,"assets":[{"name":MANIFEST,"url":"https://api.github.com/asset"}]},
        {"tag_name":"v4.0.0","draft":false,"prerelease":true,"assets":[{"name":MANIFEST,"url":"https://api.github.com/asset"}]}
    ])).unwrap();
    assert_eq!(select(&releases).unwrap().tag_name, "v1.10.0");
    assert_eq!(
        select(&releases[..1]).unwrap_err().code,
        "UPDATE_UNAVAILABLE"
    );
}

fn artifacts(version: &str, digest: &str) -> Manifest {
    Manifest {
        schema: 1,
        version: version.into(),
        artifacts: TARGETS
            .iter()
            .map(|target| Artifact {
                target: (*target).into(),
                asset: format!("natwg-{version}-{target}.tar.gz"),
                sha256: digest.into(),
            })
            .collect(),
    }
}

#[test]
fn a_later_manifest_with_new_fields_and_targets_still_reads() {
    let platform = target().unwrap();
    let text = serde_json::json!({
        "schema": 1,
        "version": "1.2.3",
        "signature": "a field a later release adds",
        "artifacts": [
            { "target": "riscv64gc-unknown-linux-musl", "asset": "natwg-1.2.3-riscv64gc-unknown-linux-musl.tar.gz", "sha256": "b".repeat(64) },
            { "target": platform, "asset": format!("natwg-1.2.3-{platform}.tar.gz"), "sha256": "a".repeat(64), "size": 1 },
        ],
    });
    let manifest: Manifest = serde_json::from_value(text).unwrap();
    assert_eq!(artifact(&manifest, "1.2.3").unwrap().target, platform);
}

#[test]
fn a_manifest_names_the_archive_of_this_platform_for_its_version() {
    let digest = "a".repeat(64);
    let manifest = artifacts("1.2.3", &digest);
    let found = artifact(&manifest, "1.2.3").unwrap();
    assert_eq!(found.target, target().unwrap());
    // Another version or schema, a missing archive for this platform, a
    // renamed asset or a malformed checksum is refused.
    assert_eq!(
        artifact(&manifest, "1.2.4").unwrap_err().code,
        "UPDATE_INVALID"
    );
    let mut other = artifacts("1.2.3", &digest);
    other.schema = 2;
    assert_eq!(
        artifact(&other, "1.2.3").unwrap_err().code,
        "UPDATE_INVALID"
    );
    let mut missing = artifacts("1.2.3", &digest);
    missing.artifacts.retain(|a| a.target != found.target);
    assert_eq!(
        artifact(&missing, "1.2.3").unwrap_err().code,
        "UPDATE_PLATFORM"
    );
    for (asset, sha256) in [
        ("natwg-1.2.3-other.tar.gz".to_owned(), digest.clone()),
        (found.asset.clone(), "a".repeat(63)),
        (found.asset.clone(), "g".repeat(64)),
    ] {
        let mut bad = artifacts("1.2.3", &digest);
        let mine = bad
            .artifacts
            .iter_mut()
            .find(|a| a.target == found.target)
            .unwrap();
        mine.asset = asset;
        mine.sha256 = sha256;
        assert_eq!(artifact(&bad, "1.2.3").unwrap_err().code, "UPDATE_INVALID");
    }
}

#[test]
fn a_corrupt_download_cannot_be_extracted() {
    let artifact = Artifact {
        target: "aarch64-apple-darwin".into(),
        asset: "archive.tar.gz".into(),
        sha256: "0".repeat(64),
    };
    assert_eq!(
        verified_binary(b"truncated archive", &artifact, "1.0.0")
            .unwrap_err()
            .code,
        "UPDATE_CHECKSUM"
    );
}

/// A release archive of `entries` under `natwg-1.0.0-{target}/`, and its
/// artifact.
fn archive(target: &str, entries: &[(&str, &[u8])]) -> (Vec<u8>, Artifact) {
    let compressor = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut tar = tar::Builder::new(compressor);
    let prefix = format!("natwg-1.0.0-{target}");
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        header.set_size(data.len() as u64);
        header.set_cksum();
        tar.append_data(&mut header, format!("{prefix}/{path}"), *data)
            .unwrap();
    }
    let bytes = tar.into_inner().unwrap().finish().unwrap();
    let artifact = Artifact {
        target: target.into(),
        asset: format!("{prefix}.tar.gz"),
        sha256: hex::encode(Sha256::digest(&bytes)),
    };
    (bytes, artifact)
}

#[test]
fn a_valid_archive_has_one_binary_and_the_platform_of_its_artifact() {
    let mac = "aarch64-apple-darwin";
    let (bytes, artifact) = archive(
        mac,
        &[
            ("TARGET", b"aarch64-apple-darwin\n"),
            ("README.md", b"other files are not read"),
            ("bin/natwg", b"binary"),
        ],
    );
    assert_eq!(
        verified_binary(&bytes, &artifact, "1.0.0").unwrap(),
        b"binary"
    );
    let bad: [&[(&str, &[u8])]; 4] = [
        // Another platform.
        &[("TARGET", b"x86_64-apple-darwin"), ("bin/natwg", b"binary")],
        // Two binaries.
        &[
            ("TARGET", b"aarch64-apple-darwin"),
            ("bin/natwg", b"binary"),
            ("bin/natwg", b"second"),
        ],
        // No binary.
        &[("TARGET", b"aarch64-apple-darwin")],
        // No TARGET.
        &[("bin/natwg", b"binary")],
    ];
    for entries in bad {
        let (bytes, artifact) = archive(mac, entries);
        assert_eq!(
            verified_binary(&bytes, &artifact, "1.0.0")
                .unwrap_err()
                .code,
            "UPDATE_INVALID"
        );
    }
    // The binary of another version's directory is not this release's.
    let (bytes, artifact) = archive(
        mac,
        &[("TARGET", b"aarch64-apple-darwin"), ("bin/natwg", b"x")],
    );
    assert_eq!(
        verified_binary(&bytes, &artifact, "1.0.1")
            .unwrap_err()
            .code,
        "UPDATE_INVALID"
    );
}

#[test]
fn package_managers_keep_their_executables() {
    assert!(managed(Path::new(
        "/opt/homebrew/Cellar/natwg/0.2.0/bin/natwg"
    )));
    assert!(managed(Path::new("/nix/store/abc-natwg-0.2.0/bin/natwg")));
    assert!(!managed(Path::new("/home/me/.cargo/bin/natwg")));
    assert!(!managed(Path::new("/usr/local/bin/natwg")));
    assert!(!managed(Path::new("/home/nix/bin/natwg")));
}

fn layout(dir: &Path) -> Layout {
    Layout {
        service: dir.join("libexec/natwg"),
        executable: dir.join("bin/natwg"),
        lock: dir.join("update.lock"),
    }
}

#[test]
fn an_update_replaces_each_older_natwg_and_nothing_newer() {
    let dir = Path::new("/x");
    let layout = layout(dir);
    let (old, new) = (version("0.2.0"), version("0.3.0"));
    let both = vec![layout.service.clone(), layout.executable.clone()];
    assert_eq!(
        plan(&layout, &old, Some(Some(old.clone())), &new).unwrap(),
        both
    );
    // A service binary that does not report its version is replaced too.
    assert_eq!(plan(&layout, &old, Some(None), &new).unwrap(), both);
    // Without a service binary, only the running natwg.
    assert_eq!(
        plan(&layout, &old, None, &new).unwrap(),
        vec![layout.executable.clone()]
    );
    // A running natwg that is up to date leaves an older service binary
    // to be synced.
    assert_eq!(
        plan(&layout, &new, Some(Some(old.clone())), &new).unwrap(),
        vec![layout.service.clone()]
    );
    assert!(
        plan(&layout, &new, Some(Some(new.clone())), &new)
            .unwrap()
            .is_empty()
    );
    assert!(plan(&layout, &new, None, &new).unwrap().is_empty());
    // No downgrade, of either.
    let newer = version("0.4.0");
    assert!(
        plan(&layout, &newer, Some(Some(newer.clone())), &new)
            .unwrap()
            .is_empty()
    );
    // natwg run from the service binary is one file.
    let same = Layout {
        executable: layout.service.clone(),
        ..layout.clone()
    };
    assert_eq!(
        plan(&same, &old, Some(Some(old.clone())), &new).unwrap(),
        vec![layout.service.clone()]
    );
}

#[test]
fn an_update_refuses_a_natwg_that_a_package_manager_owns() {
    let layout = Layout {
        executable: "/opt/homebrew/Cellar/natwg/0.2.0/bin/natwg".into(),
        ..layout(Path::new("/x"))
    };
    let (old, new) = (version("0.2.0"), version("0.3.0"));
    let error = plan(&layout, &old, Some(Some(old.clone())), &new).unwrap_err();
    assert_eq!(error.code, "UPDATE_MANAGED");
    // Unless it is up to date: then only the service binary is synced.
    assert_eq!(
        plan(&layout, &new, Some(Some(old)), &new).unwrap(),
        vec![layout.service.clone()]
    );
}

#[test]
fn a_backup_sits_hidden_beside_its_file() {
    assert_eq!(
        backup_path(Path::new("/usr/local/libexec/natwg/natwg")),
        Path::new("/usr/local/libexec/natwg/.natwg.previous")
    );
}

#[test]
fn a_second_update_waits_for_the_first() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("update.lock");
    let held = lock(&path).unwrap();
    assert_eq!(lock(&path).unwrap_err().code, "UPDATE_BUSY");
    assert_eq!(mode(&path), 0o600);
    drop(held);
    lock(&path).unwrap();
}

#[test]
fn the_version_of_a_natwg_is_what_it_reports() {
    let _turn = scripts();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("natwg");
    file(&path, &script("1.2.3"), 0o755);
    assert_eq!(version_of(&path), Some(version("1.2.3")));
    check_version(&path, "1.2.3").unwrap();
    assert_eq!(
        check_version(&path, "1.2.4").unwrap_err().code,
        "UPDATE_BINARY"
    );
    file(&path, b"#!/bin/sh\necho 'other 1.2.3'\n", 0o755);
    assert_eq!(version_of(&path), None);
    file(&path, b"#!/bin/sh\necho 'natwg 1.2.3'\nexit 1\n", 0o755);
    assert_eq!(version_of(&path), None);
    assert_eq!(version_of(&dir.path().join("missing")), None);
}

/// Services that record each restart and what the service binary held.
struct Fake {
    jobs: Vec<String>,
    /// The job whose first restart fails.
    fails: Option<String>,
    binary: PathBuf,
    restarts: RefCell<Vec<(String, Vec<u8>)>>,
}

impl Fake {
    fn new(binary: &Path, jobs: &[&str], fails: Option<&str>) -> Self {
        Self {
            jobs: jobs.iter().map(|j| (*j).to_owned()).collect(),
            fails: fails.map(str::to_owned),
            binary: binary.to_owned(),
            restarts: RefCell::new(Vec::new()),
        }
    }
}

impl Services for Fake {
    type Job = String;

    fn running(&self) -> Result<Vec<String>> {
        Ok(self.jobs.clone())
    }

    fn restart(&self, job: &String) -> Result<u32> {
        let mut restarts = self.restarts.borrow_mut();
        let first = !restarts.iter().any(|(j, _)| j == job);
        restarts.push((job.clone(), fs::read(&self.binary).unwrap()));
        if first && self.fails.as_ref() == Some(job) {
            return Err(Error::new("SERVICE_NOT_STABLE", "it crashed"));
        }
        Ok(100 + restarts.len() as u32)
    }
}

#[test]
fn an_update_keeps_owner_and_mode_and_restarts_the_running_services() {
    let _turn = scripts();
    let dir = tempfile::tempdir().unwrap();
    let layout = layout(dir.path());
    file(&layout.service, b"old service", 0o755);
    file(&layout.executable, b"old cli", 0o750);
    // As root, a user's natwg stays the user's.
    let root = unsafe { libc::geteuid() } == 0;
    if root {
        std::os::unix::fs::chown(&layout.executable, Some(1), Some(1)).unwrap();
    }
    let new = script("9.9.9");
    let services = Fake::new(
        &layout.service,
        &["natwg.service", "natwg-client.service"],
        None,
    );
    let targets = [layout.service.clone(), layout.executable.clone()];
    install(&layout, &targets, "9.9.9", &new, &services).unwrap();
    for (path, old, mode_before) in [
        (&layout.service, &b"old service"[..], 0o755),
        (&layout.executable, &b"old cli"[..], 0o750),
    ] {
        assert_eq!(fs::read(path).unwrap(), new);
        assert_eq!(mode(path), mode_before);
        let backup = backup_path(path);
        assert_eq!(fs::read(&backup).unwrap(), old);
        assert_eq!(mode(&backup), mode_before);
    }
    if root {
        for path in [&layout.executable, &backup_path(&layout.executable)] {
            let meta = fs::metadata(path).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (1, 1), "{}", path.display());
        }
    }
    let restarts = services.restarts.into_inner();
    let names: Vec<&str> = restarts.iter().map(|(job, _)| job.as_str()).collect();
    assert_eq!(names, ["natwg.service", "natwg-client.service"]);
    assert!(restarts.iter().all(|(_, binary)| *binary == new));
    // No stage is left behind.
    let left: Vec<_> = fs::read_dir(dir.path().join("bin"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(left.len(), 2, "{left:?}");
}

#[test]
fn an_update_of_the_running_natwg_alone_restarts_nothing() {
    let _turn = scripts();
    let dir = tempfile::tempdir().unwrap();
    let layout = layout(dir.path());
    file(&layout.executable, b"old cli", 0o755);
    let services = Fake::new(&layout.service, &["natwg.service"], None);
    let targets = [layout.executable.clone()];
    install(&layout, &targets, "9.9.9", &script("9.9.9"), &services).unwrap();
    assert_eq!(fs::read(&layout.executable).unwrap(), script("9.9.9"));
    assert!(services.restarts.into_inner().is_empty());
}

#[test]
fn a_service_that_does_not_come_back_rolls_the_update_back() {
    let _turn = scripts();
    let dir = tempfile::tempdir().unwrap();
    let layout = layout(dir.path());
    file(&layout.service, b"old service", 0o755);
    file(&layout.executable, b"old cli", 0o755);
    // An earlier update left the service binary a backup; the CLI has none.
    file(&backup_path(&layout.service), b"older service", 0o755);
    let jobs = [
        "natwg.service",
        "natwg-office.service",
        "natwg-client.service",
    ];
    let services = Fake::new(&layout.service, &jobs, Some("natwg-office.service"));
    let targets = [layout.service.clone(), layout.executable.clone()];
    let error = install(&layout, &targets, "9.9.9", &script("9.9.9"), &services).unwrap_err();
    assert_eq!(error.code, "UPDATE_ROLLED_BACK");
    assert!(
        error
            .message
            .starts_with("natwg-office.service did not come back on natwg 9.9.9"),
        "{}",
        error.message
    );
    assert!(error.message.contains("it crashed"), "{}", error.message);
    assert!(
        error.message.contains(
            "so natwg put the previous binaries back and restarted natwg.service and natwg-office.service on them.\nSERVICE_NOT_STABLE: it crashed"
        ),
        "{}",
        error.message
    );
    assert_eq!(fs::read(&layout.service).unwrap(), b"old service");
    assert_eq!(fs::read(&layout.executable).unwrap(), b"old cli");
    // The backups are as they were before the update.
    assert_eq!(
        fs::read(backup_path(&layout.service)).unwrap(),
        b"older service"
    );
    assert!(!backup_path(&layout.executable).exists());
    // The services restarted so far, and the one that failed, run the
    // previous binary again; the client never stopped.
    let restarts: Vec<(String, Vec<u8>)> = services.restarts.into_inner();
    let expected: Vec<(String, Vec<u8>)> = vec![
        ("natwg.service".into(), script("9.9.9")),
        ("natwg-office.service".into(), script("9.9.9")),
        ("natwg.service".into(), b"old service".to_vec()),
        ("natwg-office.service".into(), b"old service".to_vec()),
    ];
    assert_eq!(restarts, expected);
}

#[test]
fn a_binary_that_fails_its_version_check_changes_nothing() {
    let _turn = scripts();
    let dir = tempfile::tempdir().unwrap();
    let layout = layout(dir.path());
    file(&layout.service, b"old service", 0o755);
    let services = Fake::new(&layout.service, &["natwg.service"], None);
    let targets = [layout.service.clone()];
    let error = install(&layout, &targets, "9.9.9", &script("9.9.8"), &services).unwrap_err();
    assert_eq!(error.code, "UPDATE_BINARY");
    assert_eq!(fs::read(&layout.service).unwrap(), b"old service");
    assert!(!backup_path(&layout.service).exists());
    assert!(services.restarts.into_inner().is_empty());
    let left = fs::read_dir(layout.service.parent().unwrap())
        .unwrap()
        .count();
    assert_eq!(left, 1);
}

/// A manifest and archives for every platform of `version`, each holding
/// `binary`, as the download site serves them.
fn release(version: &str, binary: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut artifacts = Vec::new();
    for target in TARGETS {
        let compressor = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut tar = tar::Builder::new(compressor);
        let prefix = format!("natwg-{version}-{target}");
        for (path, data) in [("TARGET", target.as_bytes()), ("bin/natwg", binary)] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            header.set_size(data.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, format!("{prefix}/{path}"), data)
                .unwrap();
        }
        let bytes = tar.into_inner().unwrap().finish().unwrap();
        let asset = format!("{prefix}.tar.gz");
        artifacts.push(serde_json::json!({
            "target": target, "asset": asset, "sha256": hex::encode(Sha256::digest(&bytes)),
        }));
        files.push((format!("/v{version}/{asset}"), bytes));
    }
    let manifest = serde_json::json!({"schema": 1, "version": version, "artifacts": artifacts});
    files.push((
        "/latest/natwg-update.json".into(),
        manifest.to_string().into_bytes(),
    ));
    files
}

#[tokio::test]
async fn the_download_site_offers_the_verified_binary_of_this_platform() {
    let dir = tempfile::tempdir().unwrap();
    let layout = layout(dir.path());
    let base = site(release("99.0.0", b"the new natwg")).await;
    let Fetched::Install {
        version,
        binary,
        targets,
    } = fetch(&Source::Site(base.clone()), &layout, false)
        .await
        .unwrap()
    else {
        panic!("nothing to install");
    };
    assert_eq!(version, "99.0.0");
    assert_eq!(binary, b"the new natwg");
    // No service binary in this layout: only the running natwg.
    assert_eq!(targets, vec![layout.executable.clone()]);
    // A check stops before the download.
    assert!(matches!(
        fetch(&Source::Site(base), &layout, true).await.unwrap(),
        Fetched::Done
    ));
    // A site whose archive does not match its manifest fails, so the
    // updater moves on to GitHub Releases.
    let mut tampered = release("99.0.0", b"the new natwg");
    let archive = tampered
        .iter_mut()
        .find(|(path, _)| path.contains(target().unwrap()))
        .unwrap();
    archive.1.push(0);
    let base = site(tampered).await;
    let error = fetch(&Source::Site(base), &layout, false)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, "UPDATE_CHECKSUM");
}

#[tokio::test]
async fn the_download_site_offers_nothing_older() {
    let dir = tempfile::tempdir().unwrap();
    let layout = layout(dir.path());
    let base = site(release("0.0.1", b"old")).await;
    assert!(matches!(
        fetch(&Source::Site(base), &layout, false).await.unwrap(),
        Fetched::Done
    ));
}
