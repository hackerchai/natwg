//! The commands that give the tunnel interface its address, MTU and routes.
//! A plan is a list of [`Step`]s, and [`apply`] runs it. Applying the same
//! plan again changes nothing. `nat` builds its plans from the same steps,
//! and keeps the steps that undo them in a [`Teardown`].

pub mod linux;
pub mod macos;

#[cfg(not(target_os = "macos"))]
pub use linux::plan;
#[cfg(target_os = "macos")]
pub use macos::plan;

use crate::{Error, Result};
use std::{
    ffi::CStr,
    io::Write,
    net::Ipv4Addr,
    process::{Command, Stdio},
};

// sudo passes the caller's PATH on, and that PATH can hold directories its
// user can write. natwg runs these commands as root.
const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// One command of a plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub argv: Vec<String>,
    /// The text the command reads from standard input.
    pub stdin: Option<String>,
    /// How to tell that the effect of the command is already in place.
    pub done_when: Option<Check>,
}

/// A read-only command that prints `expect` when some state is in place. A
/// check that fails counts as missing state, because many commands fail when
/// the thing they read does not exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub argv: Vec<String>,
    pub expect: String,
}

impl Step {
    pub fn new(argv: &[&str]) -> Self {
        Self {
            argv: owned(argv),
            stdin: None,
            done_when: None,
        }
    }

    pub fn stdin(mut self, text: impl Into<String>) -> Self {
        self.stdin = Some(text.into());
        self
    }

    pub fn done_when(mut self, argv: &[&str], expect: impl Into<String>) -> Self {
        self.done_when = Some(Check {
            argv: owned(argv),
            expect: expect.into(),
        });
        self
    }
}

impl Check {
    fn holds(&self) -> bool {
        run(&self.argv, None).is_ok_and(|output| output.stdout.contains(&self.expect))
    }
}

/// What a command printed before it exited with status 0.
pub struct Output {
    pub stdout: String,
    pub stderr: String,
}

/// Run the steps in order and stop at the first failure. A step whose check
/// already holds does not run.
pub fn apply(steps: &[Step]) -> Result<()> {
    for step in steps {
        let check = step.done_when.as_ref();
        if check.is_some_and(Check::holds) {
            continue;
        }
        let output = run(&step.argv, step.stdin.as_deref())?;
        // macOS `route add` exits 0 when the route exists and when it resolved
        // the interface name as a host, so only the check proves the effect.
        if let Some(check) = check.filter(|check| !check.holds()) {
            return Err(Error::new(
                "COMMAND_NO_EFFECT",
                format!(
                    "`{}` exited 0 and printed {:?}, but `{}` does not print {:?}",
                    step.argv.join(" "),
                    format!("{}{}", output.stdout, output.stderr).trim(),
                    check.argv.join(" "),
                    check.expect
                ),
            ));
        }
    }
    Ok(())
}

/// The steps that undo a plan. They run once: in [`Teardown::run`], or when
/// the value drops. A panic or an early return therefore still undoes the
/// plan.
#[derive(Debug)]
pub struct Teardown(Vec<Step>);

impl Teardown {
    pub fn new(steps: Vec<Step>) -> Self {
        Self(steps)
    }

    /// Add a step that runs after the ones already there.
    pub fn push(&mut self, step: Step) {
        self.0.push(step);
    }

    /// Run every step, also after one fails, and return the first failure.
    pub fn run(mut self) -> Result<()> {
        self.run_once()
    }

    fn run_once(&mut self) -> Result<()> {
        std::mem::take(&mut self.0)
            .iter()
            .map(|step| apply(std::slice::from_ref(step)))
            .fold(Ok(()), Result::and)
    }
}

impl Drop for Teardown {
    fn drop(&mut self) {
        let _ = self.run_once();
    }
}

/// Run one command with a fixed environment and return what it printed. A
/// command that cannot start or exits with another status is an error.
pub fn run(argv: &[String], stdin: Option<&str>) -> Result<Output> {
    let failed =
        |reason: String| Error::new("COMMAND_FAILED", format!("`{}`: {reason}", argv.join(" ")));
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| failed("no program to run".to_owned()))?;
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| failed(e.to_string()))?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // A command that exits early closes the pipe, and its exit status
        // then reports the failure.
        let _ = pipe.write_all(text.as_bytes());
    }
    let output = child
        .wait_with_output()
        .map_err(|e| failed(e.to_string()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(failed(format!("{}: {}", output.status, stderr.trim())));
    }
    Ok(Output { stdout, stderr })
}

/// What a command that only reads state printed on standard output.
pub fn read(argv: &[&str]) -> Result<String> {
    Ok(run(&owned(argv), None)?.stdout)
}

/// Every IPv4 address of every interface, with the name of the interface.
pub fn ipv4_addresses() -> std::io::Result<Vec<(String, Ipv4Addr)>> {
    let mut list = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut found = Vec::new();
    let mut entry = list;
    while let Some(current) = unsafe { entry.as_ref() } {
        entry = current.ifa_next;
        let address = current.ifa_addr;
        if address.is_null() || i32::from(unsafe { (*address).sa_family }) != libc::AF_INET {
            continue;
        }
        let name = unsafe { CStr::from_ptr(current.ifa_name) };
        let address = unsafe { &*address.cast::<libc::sockaddr_in>() };
        found.push((
            name.to_string_lossy().into_owned(),
            Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)),
        ));
    }
    unsafe { libc::freeifaddrs(list) };
    Ok(found)
}

/// Refuse a tunnel address that an interface holds already, such as the
/// utun of a tunnel that `wg-quick down` left behind. That interface would
/// keep the tunnel's traffic.
pub fn require_free_address(address: Ipv4Addr) -> Result<()> {
    let addresses =
        ipv4_addresses().map_err(|e| Error::new("INTERFACES_UNREADABLE", e.to_string()))?;
    let Some((holder, _)) = addresses.iter().find(|(_, held)| *held == address) else {
        return Ok(());
    };
    Err(Error::new(
        "ADDRESS_IN_USE",
        format!(
            "{holder} holds the tunnel address {address} already and would keep the tunnel's traffic; take {holder} down or change interface.address"
        ),
    ))
}

fn owned(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|&arg| arg.to_owned()).collect()
}
