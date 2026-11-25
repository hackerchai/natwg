//! Interactive reads use stdin and stderr. Stdout belongs to the first peer.
use natwg::{Error, Result};
use std::io::{self, IsTerminal, Write};

pub(super) struct Prompt {
    pub interactive: bool,
}

fn input(error: io::Error) -> Error {
    Error::new("INIT_INPUT", error.to_string())
}

impl Prompt {
    pub fn new(yes: bool) -> Self {
        Self {
            interactive: !yes && io::stdin().is_terminal(),
        }
    }

    pub fn ask(&self, label: &str, default: &str) -> Result<String> {
        if !self.interactive {
            return Ok(default.to_owned());
        }
        let mut stderr = io::stderr().lock();
        write!(stderr, "{label} [{default}] ")
            .and_then(|()| stderr.flush())
            .map_err(input)?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line).map_err(input)? == 0 {
            return Err(Error::new("INIT_INPUT", "end of input; setup cancelled"));
        }
        let answer = line.trim();
        Ok(if answer.is_empty() { default } else { answer }.to_owned())
    }

    pub fn required(&self, value: Option<String>, label: &str, flag: &str) -> Result<String> {
        let value = match value {
            Some(value) => value,
            None => self.ask(label, "")?,
        };
        if value.is_empty() {
            return Err(Error::new(
                "INIT_INPUT",
                format!("missing {flag} ({label})"),
            ));
        }
        Ok(value)
    }

    pub fn confirm(&self, label: &str, default: bool) -> Result<bool> {
        loop {
            let answer = self.ask(label, if default { "yes" } else { "no" })?;
            match answer.to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => warn!("Enter yes or no."),
            }
        }
    }

    pub fn token(&self) -> Result<String> {
        if !self.interactive {
            return Err(Error::new(
                "INIT_INPUT",
                "missing --token-file (Cloudflare API token)",
            ));
        }
        // Read the same terminal that supplied the other answers, even when
        // a supervisor gave stdin a PTY without a controlling /dev/tty.
        let options = rpassword::ConfigBuilder::new()
            .input_file_path("/dev/stdin")
            .output_discard()
            .build();
        let mut stderr = io::stderr().lock();
        write!(stderr, "Cloudflare API token (hidden) ")
            .and_then(|()| stderr.flush())
            .map_err(input)?;
        let token = rpassword::read_password_with_config(options);
        writeln!(stderr).map_err(input)?;
        token.map_err(input)
    }
}
