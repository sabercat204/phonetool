//! Integration tests for the Tier-B subprocess plugin host.
//!
//! Spawns the reference `echo_child` binary and drives it through the
//! `SubprocessPlugin` interface to prove the full control-channel round-trip.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::PathBuf;
use std::time::Duration;

use phonetool_core::{CapabilityClass, Command, Manifest, Plugin, PluginError, Transducer};
use phonetool_subprocess::{SubprocessConfig, SubprocessPlugin};

fn echo_child_path() -> PathBuf {
    let mut path = std::env::current_exe().expect("current exe");
    path.pop(); // remove test binary name
    path.pop(); // remove `deps`
    path.push("echo_child");
    path
}

fn echo_config() -> SubprocessConfig {
    SubprocessConfig {
        program: echo_child_path().to_string_lossy().to_string(),
        args: vec![],
        timeout: Duration::from_secs(5),
        manifest: Manifest {
            name: "echo".to_owned(),
            version: "0.1.0".to_owned(),
            transducer: Transducer::Ip,
            capability: CapabilityClass::Passive,
            summary: "echo child for testing".to_owned(),
        },
    }
}

#[test]
fn dispatches_a_command_and_receives_an_event() {
    let plugin = SubprocessPlugin::new(echo_config());
    let cmd = Command {
        verb: "sweep".to_owned(),
        arg: "test-data".to_owned(),
    };
    let event = plugin.dispatch(&cmd).expect("dispatch succeeds");
    assert_eq!(event.source, "echo-child");
    assert_eq!(event.data["verb"], "sweep");
    assert_eq!(event.data["arg"], "test-data");
    assert_eq!(event.data["echo"], true);
}

#[test]
fn multiple_dispatches_on_one_child() {
    let plugin = SubprocessPlugin::new(echo_config());

    for i in 0..5 {
        let cmd = Command {
            verb: "ping".to_owned(),
            arg: format!("iter-{i}"),
        };
        let event = plugin.dispatch(&cmd).expect("dispatch succeeds");
        assert_eq!(event.data["arg"], format!("iter-{i}"));
    }
}

#[test]
fn child_error_maps_to_plugin_error() {
    let plugin = SubprocessPlugin::new(echo_config());
    let cmd = Command {
        verb: "error".to_owned(),
        arg: "something broke".to_owned(),
    };
    let err = plugin.dispatch(&cmd).expect_err("child error");
    assert!(matches!(err, PluginError::Backend(_)));
    let msg = format!("{err}");
    assert!(msg.contains("something broke"));
}

#[test]
fn manifest_is_served_from_config() {
    let plugin = SubprocessPlugin::new(echo_config());
    let m = plugin.manifest();
    assert_eq!(m.name, "echo");
    assert_eq!(m.transducer, Transducer::Ip);
}

#[test]
fn nonexistent_program_is_backend_error() {
    let config = SubprocessConfig {
        program: "/nonexistent/binary".to_owned(),
        args: vec![],
        timeout: Duration::from_secs(1),
        manifest: Manifest {
            name: "bad".to_owned(),
            version: "0.0.0".to_owned(),
            transducer: Transducer::Store,
            capability: CapabilityClass::Passive,
            summary: "should fail".to_owned(),
        },
    };
    let plugin = SubprocessPlugin::new(config);
    let cmd = Command {
        verb: "test".to_owned(),
        arg: String::new(),
    };
    let err = plugin.dispatch(&cmd).expect_err("spawn fails");
    assert!(matches!(err, PluginError::Backend(_)));
}
