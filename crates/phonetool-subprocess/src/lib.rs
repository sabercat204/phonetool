//! `phonetool-subprocess` — Tier-B subprocess plugin host.
//!
//! Proxies the `Plugin` trait to an out-of-process child over length-prefixed
//! JSON (stdin/stdout). Enables polyglot capabilities (GNU Radio, gnss-sdr,
//! Osmocom, Python scripts) behind the exact same dispatch contract as native
//! Tier-A plugins. The child is untrusted: every frame is bounded, deserialized
//! in a `Result`, and mapped to `PluginError::Backend` on any failure.
//!
//! The gate stays on the Rust side — a subprocess never bypasses authorization.

pub mod frame;

use std::io::{BufReader, BufWriter};
use std::process::{Child, Command as StdCommand, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use phonetool_core::{Command, Event, Manifest, Plugin, PluginError};
use serde::{Deserialize, Serialize};

use crate::frame::{read_frame, write_frame};

/// Configuration for spawning a subprocess plugin.
#[derive(Debug, Clone)]
pub struct SubprocessConfig {
    /// The command to execute (program path).
    pub program: String,
    /// Arguments to pass to the child.
    pub args: Vec<String>,
    /// Response deadline (child must respond within this).
    pub timeout: Duration,
    /// The manifest to serve (cached at registration, not fetched from child
    /// on every call — matches the Tier-A contract where `manifest()` is cheap).
    pub manifest: Manifest,
}

/// A child frame response: either a successful Event or an error.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ChildResponse {
    Ok(Event),
    Err { error: ChildError },
}

#[derive(Debug, Deserialize)]
struct ChildError {
    kind: String,
    message: String,
}

impl ChildError {
    fn into_plugin_error(self) -> PluginError {
        match self.kind.as_str() {
            "invalid_input" => PluginError::InvalidInput(self.message),
            "unsupported" => PluginError::Unsupported(self.message),
            "empty" => PluginError::Empty(self.message),
            _ => PluginError::Backend(self.message),
        }
    }
}

/// The request frame sent to the child.
#[derive(Debug, Serialize)]
struct ChildRequest<'a> {
    verb: &'a str,
    arg: &'a str,
}

/// A Tier-B plugin that proxies dispatch to a child process.
pub struct SubprocessPlugin {
    config: SubprocessConfig,
    child: Mutex<Option<ChildHandle>>,
}

struct ChildHandle {
    process: Child,
    stdin: BufWriter<std::process::ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
}

impl SubprocessPlugin {
    /// Create a new subprocess plugin. The child is spawned lazily on first
    /// dispatch (or eagerly via `spawn()`).
    #[must_use]
    pub fn new(config: SubprocessConfig) -> Self {
        Self {
            config,
            child: Mutex::new(None),
        }
    }

    /// Eagerly spawn the child process.
    ///
    /// # Errors
    /// `PluginError::Backend` if the child cannot be spawned.
    pub fn spawn(&self) -> Result<(), PluginError> {
        let mut guard = self
            .child
            .lock()
            .map_err(|e| PluginError::Backend(format!("lock poisoned: {e}")))?;
        if guard.is_some() {
            return Ok(());
        }
        *guard = Some(self.do_spawn()?);
        Ok(())
    }

    fn do_spawn(&self) -> Result<ChildHandle, PluginError> {
        let mut cmd = StdCommand::new(&self.config.program);
        cmd.args(&self.config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut process = cmd.spawn().map_err(|e| {
            PluginError::Backend(format!("cannot spawn child '{}': {e}", self.config.program))
        })?;

        let stdin = process
            .stdin
            .take()
            .ok_or_else(|| PluginError::Backend("child has no stdin".to_owned()))?;
        let stdout = process
            .stdout
            .take()
            .ok_or_else(|| PluginError::Backend("child has no stdout".to_owned()))?;

        tracing::info!(program = %self.config.program, "Tier-B child spawned");

        Ok(ChildHandle {
            process,
            stdin: BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
        })
    }

    fn ensure_child(&self) -> Result<(), PluginError> {
        let mut guard = self
            .child
            .lock()
            .map_err(|e| PluginError::Backend(format!("lock poisoned: {e}")))?;
        if guard.is_none() {
            *guard = Some(self.do_spawn()?);
        }
        Ok(())
    }

    fn dispatch_to_child(&self, cmd: &Command) -> Result<Event, PluginError> {
        self.ensure_child()?;

        let mut guard = self
            .child
            .lock()
            .map_err(|e| PluginError::Backend(format!("lock poisoned: {e}")))?;
        let handle = guard
            .as_mut()
            .ok_or_else(|| PluginError::Backend("child not running".to_owned()))?;

        let request = ChildRequest {
            verb: &cmd.verb,
            arg: &cmd.arg,
        };
        let request_json = serde_json::to_vec(&request)
            .map_err(|e| PluginError::Backend(format!("serialize request: {e}")))?;

        write_frame(&mut handle.stdin, &request_json)?;

        let response_bytes = read_frame(&mut handle.stdout)?;
        let response_str = String::from_utf8(response_bytes)
            .map_err(|e| PluginError::Backend(format!("child response not UTF-8: {e}")))?;

        let response: ChildResponse = serde_json::from_str(&response_str)
            .map_err(|e| PluginError::Backend(format!("deserialize child response: {e}")))?;

        match response {
            ChildResponse::Ok(event) => Ok(event),
            ChildResponse::Err { error } => Err(error.into_plugin_error()),
        }
    }
}

impl Drop for SubprocessPlugin {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut handle) = guard.take() {
                let _ = handle.process.kill();
                let _ = handle.process.wait();
                tracing::info!(program = %self.config.program, "Tier-B child reaped");
            }
        }
    }
}

impl Plugin for SubprocessPlugin {
    fn manifest(&self) -> Manifest {
        self.config.manifest.clone()
    }

    fn dispatch(&self, cmd: &Command) -> Result<Event, PluginError> {
        self.dispatch_to_child(cmd)
    }
}
