//! Check every destination before enrolling. Keep the first peer's JSON
//! recoverable across service startup, DNS propagation and output delivery.
use super::{Enrollment, invalid};
use crate::lock_config_dir;
use natwg::{
    Error, Result,
    config::{self, Config},
    export::{self, Format},
};
use std::{
    fs, io,
    os::unix::{fs::MetadataExt, io::AsFd},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

pub(super) fn wireguard_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // Homebrew's bin/brew is located directly below its prefix. Inspect
        // the path without executing a user-owned brew script as root.
        let prefix = std::env::var_os("PATH")
            .and_then(|path| {
                std::env::split_paths(&path).find(|bin| {
                    bin.is_absolute() && bin.ends_with("bin") && bin.join("brew").is_file()
                })
            })
            .and_then(|bin| bin.parent().map(Path::to_owned))
            .unwrap_or_else(|| {
                PathBuf::from(if cfg!(target_arch = "aarch64") {
                    "/opt/homebrew"
                } else {
                    "/usr/local"
                })
            });
        prefix.join("etc/wireguard")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/etc/wireguard")
    }
}

pub(super) fn check_target(path: &Path, force: bool) -> Result<()> {
    match path.symlink_metadata() {
        Ok(meta) if !meta.is_file() => {
            Err(invalid(format!("{} is not a regular file", path.display())))
        }
        Ok(_) if !force => Err(Error::new(
            "CONFIG_EXISTS",
            format!("{} exists already; --force replaces it", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(invalid(format!("{}: {e}", path.display()))),
    }
}

// Resolve existing directory aliases even when the destination is new.
fn absolute(path: &Path) -> io::Result<PathBuf> {
    match path.canonicalize() {
        Ok(real) => Ok(real),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let full = std::path::absolute(path)?;
            let parent = full.parent().ok_or(e)?;
            Ok(absolute(parent)?.join(full.file_name().ok_or(io::ErrorKind::InvalidInput)?))
        }
        Err(e) => Err(e),
    }
}

fn identity(meta: fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

fn destinations(paths: &[&Path], token: Option<&Path>, stdout: bool, force: bool) -> Result<()> {
    let mut names: Vec<PathBuf> = Vec::new();
    let mut files = std::collections::HashSet::new();
    if stdout {
        let out = fs::File::from(
            io::stdout()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|e| invalid(e.to_string()))?,
        );
        let meta = out.metadata().map_err(|e| invalid(e.to_string()))?;
        if meta.is_file() {
            if meta.mode() & 0o077 != 0
                || config::has_extended_acl(&out).map_err(|e| invalid(e.to_string()))?
            {
                return Err(invalid(
                    "redirected peer output is readable by others; use --out or umask 077",
                ));
            }
            files.insert(identity(meta));
        }
    }
    for &path in paths {
        check_target(path, force)?;
    }
    for path in paths.iter().copied().chain(token) {
        let name = absolute(path).map_err(|e| invalid(format!("{}: {e}", path.display())))?;
        let overlaps = names
            .iter()
            .any(|other| name.starts_with(other) || other.starts_with(&name));
        if overlaps || path.metadata().is_ok_and(|m| !files.insert(identity(m))) {
            return Err(invalid(format!(
                "{} overlaps another input or output; use separate files",
                path.display()
            )));
        }
        names.push(name);
    }
    Ok(())
}

pub(super) struct Saved {
    recovery: Option<(NamedTempFile, Format)>,
    // Other peer/config edits must wait until the peer's profile is delivered.
    _lock: fs::File,
}

impl Saved {
    pub fn finish(self, result: Result<()>) -> Result<()> {
        match (self.recovery, result) {
            (Some((file, _)), Ok(())) => {
                let path = file.path().to_owned();
                file.close().map_err(|e| {
                    Error::new(
                        "INIT_CLEANUP",
                        format!(
                            "Peer delivered; remove its private recovery file {}: {e}",
                            path.display()
                        ),
                    )
                })
            }
            (Some((file, format)), Err(err)) => {
                use clap::ValueEnum;
                let format = format.to_possible_value().unwrap();
                Err(Error::new(
                    "INIT_PEER_RECOVERY",
                    format!(
                        "{err}. The server was saved. The first peer's private JSON is at {} (0600). Once the server is running and DNS is ready, run sudo natwg config export --config {} --format {} --out PATH.",
                        file.path().display(),
                        super::shell_path(file.path()),
                        format.get_name()
                    ),
                ))
            }
            (None, result) => result,
        }
    }
}

pub(super) fn save(
    rt: &Runtime,
    path: &Path,
    config: &Config,
    peer: Option<&Enrollment>,
    native: Option<&Path>,
    token: Option<&Path>,
    force: bool,
) -> Result<Saved> {
    let server_wg = native.map(|dir| dir.join("natwg.conf"));
    let client_wg = native
        .filter(|_| peer.is_some())
        .map(|dir| dir.join("natwg-client.conf"));
    let out = peer.and_then(|p| p.output.out.as_deref());
    let targets: Vec<_> = [Some(path), server_wg.as_deref(), client_wg.as_deref(), out]
        .into_iter()
        .flatten()
        .collect();
    let stdout = peer.is_some() && out.is_none();
    destinations(&targets, token, stdout, force)?;

    let server_stage = config::stage_private(path, &format!("{}\n", config.exposed()))?;
    let lock = lock_config_dir(path)?;
    destinations(&targets, token, stdout, force)?;
    let mut profiles = Vec::new();
    if let Some(wg) = &server_wg {
        let text = rt.block_on(export::render(config, Format::WgQuick, "natwg", None))?;
        profiles.push((wg, config::stage_private(wg, &text)?, force && wg.exists()));
    }
    if let (Some(wg), Some(peer)) = (&client_wg, peer) {
        let text = rt.block_on(export::render(
            &peer.client,
            Format::WgQuick,
            &peer.name,
            Some(config.server()?),
        ))?;
        profiles.push((wg, config::stage_private(wg, &text)?, force && wg.exists()));
    }
    let mut recovery = peer
        .map(|peer| {
            config::stage_private(path, &format!("{}\n", peer.client.exposed()))
                .map(|file| (file, peer.format))
        })
        .transpose()?;
    if let Some((file, _)) = &recovery {
        warn!(
            "First peer recovery file {} (0600) is removed after delivery.",
            file.path().display()
        );
    }
    config::publish_private(server_stage, path, force).map_err(|(e, _)| e)?;
    // From this commit point on, even unwinding must keep the enrolled
    // identity. Only successful delivery removes the recovery file.
    if let Some((file, _)) = &mut recovery {
        file.disable_cleanup(true);
    }
    warn!("Wrote {} (mode 0600).", path.display());
    for (wg, stage, replace) in profiles {
        if let Err((err, _)) = config::publish_private(stage, wg, replace) {
            if let Some((file, _)) = &recovery {
                warn!(
                    "First peer private JSON saved at {} (0600).",
                    file.path().display()
                );
            }
            return Err(Error::new(
                "INIT_NATIVE_OUTPUT",
                format!(
                    "{err}. Server config saved at {}; use config export to retry.",
                    path.display()
                ),
            ));
        }
        warn!("Wrote {} (mode 0600).", wg.display());
    }
    Ok(Saved {
        recovery,
        _lock: lock,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prevent_overlapping_destinations_before_replacing_any_keys() {
        let dir = tempfile::tempdir().unwrap();
        let server = dir.path().join("server.json");
        let nested = server.join("client.json");
        let token = dir.path().join("token");
        config::write_private(&token, "synthetic", false).unwrap();
        let alias = dir.path().join("alias");
        fs::hard_link(&token, &alias).unwrap();
        for (paths, input) in [
            (vec![server.as_path(), nested.as_path()], None),
            (vec![server.as_path(), server.as_path()], None),
            (vec![alias.as_path()], Some(token.as_path())),
        ] {
            assert!(destinations(&paths, input, false, true).is_err());
        }
        assert!(!server.exists());
        assert_eq!(fs::read_to_string(alias).unwrap(), "synthetic");
    }
}
