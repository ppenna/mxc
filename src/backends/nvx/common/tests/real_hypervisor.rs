// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Drives a real NVX microVM through the MXC state-aware trait, one process per
//! phase, the way `wxc-exec` runs the lifecycle.
//!
//! Requires a hypervisor and NVX artifacts: `NVX_ARTIFACTS_DIR` (or another
//! `Artifacts::discover` source) names an NVX release with the OpenVMM
//! executable, guest kernel, and an Alpine initramfs whose agent supports
//! cancellation.
//!
//! ```text
//! cargo test -p nvx_backend --test real_hypervisor -- --ignored --nocapture
//! ```

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use nvx::openvmm::resolve_guest_path as guest_path;
use nvx_backend::{NvxStateAwareRunner, CANCELLED_EXIT_CODE};
use serde_json::{json, Value};
use wxc_common::config_parser::load_mxc_request_from_json;
use wxc_common::exec_stream::ExecSandboxProcess;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::ExecutionRequest;
use wxc_common::sandbox_process::SandboxProcess;
use wxc_common::state_aware_backend::{ExecStdio, StatefulSandboxBackend};
use wxc_common::state_aware_request::MxcRequest;

fn phase_command(arguments: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nvx-mxc-phase"));
    command.args(arguments);
    command
}

fn phase(arguments: &[&str]) -> Output {
    let output = phase_command(arguments).output().unwrap();
    println!(
        "nvx-mxc-phase {}: {} | {} | {}",
        arguments.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    output
}

fn envelope(arguments: &[&str]) -> Value {
    let output = phase(arguments);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn result(arguments: &[&str]) -> Value {
    let value = envelope(arguments);
    assert!(value.get("error").is_none(), "{value}");
    value["result"].clone()
}

fn error_code(arguments: &[&str]) -> String {
    envelope(arguments)["error"]["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
#[ignore = "requires a hypervisor and NVX artifacts"]
fn lifecycle_runs_one_process_per_phase() {
    let provisioned = result(&["provision", "--memory-mib", "256"]);
    let id = provisioned["sandboxId"].as_str().unwrap().to_owned();
    assert!(id.starts_with("nvx:"), "{id}");
    assert_eq!(error_code(&["exec", &id, "--", "true"]), "not_started");

    let started = result(&["start", &id]);
    assert!(started["metadata"]["bootMilliseconds"].is_number());
    assert_eq!(error_code(&["start", &id]), "already_started");

    let os = phase(&["exec", &id, "--", "grep PRETTY_NAME /etc/os-release; id -u"]);
    assert!(os.status.success());
    let stdout = String::from_utf8_lossy(&os.stdout);
    assert!(stdout.contains("Alpine Linux"), "{stdout}");
    assert!(stdout.contains("65534"), "{stdout}");

    let failing = phase(&["exec", &id, "--", "echo oops >&2; exit 7"]);
    assert_eq!(failing.status.code(), Some(7));
    assert_eq!(String::from_utf8_lossy(&failing.stderr).trim(), "oops");

    assert!(phase(&["exec", &id, "--", "printf kept > /tmp/mxc"])
        .status
        .success());
    let stopped = result(&["stop", &id]);
    assert_eq!(stopped["metadata"]["forced"], false);
    assert_eq!(error_code(&["stop", &id]), "already_stopped");

    // The Alpine root file system lives in guest memory, so a restart starts fresh.
    result(&["start", &id]);
    let fresh = phase(&["exec", &id, "--", "test ! -e /tmp/mxc && echo fresh"]);
    assert_eq!(fresh.stdout, b"fresh\n");

    // An exec whose process dies leaves no workload behind, so the next exec
    // does not wait for it.
    let mut orphaned = phase_command(&["exec", &id, "--", "echo started; sleep 60"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut started = [0u8; 8];
    std::io::Read::read_exact(orphaned.stdout.as_mut().unwrap(), &mut started).unwrap();
    assert_eq!(&started, b"started\n");
    orphaned.kill().unwrap();
    orphaned.wait().unwrap();
    let begin = Instant::now();
    let after = phase(&["exec", &id, "--", "pgrep -x sleep || echo none"]);
    assert_eq!(after.stdout, b"none\n");
    assert!(
        begin.elapsed() < Duration::from_secs(20),
        "{:?}",
        begin.elapsed()
    );
    result(&["stop", &id]);
    result(&["deprovision", &id]);
    assert_eq!(error_code(&["start", &id]), "stale_id");
}

#[test]
#[ignore = "requires a hypervisor and NVX artifacts"]
fn piped_exec_feeds_the_mxc_stream_consumer() {
    let mut backend = NvxStateAwareRunner::new().unwrap();
    let request = ExecutionRequest::default();
    let id = backend.provision(&request, None).unwrap().sandbox_id;
    backend.start(&id, &request, None).unwrap();

    let mut exec = ExecutionRequest {
        script_code: "seq 1 20000".to_owned(),
        ..ExecutionRequest::default()
    };
    let handle = backend.exec(&id, &exec, None, ExecStdio::Piped).unwrap();
    let mut process = ExecSandboxProcess::from_exec_handle(handle).unwrap();
    let mut stdout = String::new();
    std::io::Read::read_to_string(&mut process.take_stdout().unwrap(), &mut stdout).unwrap();
    assert_eq!(process.wait().unwrap(), 0);
    assert_eq!(stdout.lines().count(), 20000);
    assert_eq!(stdout.lines().last(), Some("20000"));

    exec.script_code = "sleep 30".to_owned();
    exec.script_timeout = Duration::from_millis(500).as_millis() as u32;
    let handle = backend.exec(&id, &exec, None, ExecStdio::Piped).unwrap();
    let mut process = ExecSandboxProcess::from_exec_handle(handle).unwrap();
    let error = process.wait().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    drop(process);

    // Killing through MXC's stream consumer cancels the workload in the guest.
    exec.script_code = "echo started; sleep 30".to_owned();
    exec.script_timeout = 0;
    let begin = Instant::now();
    let handle = backend.exec(&id, &exec, None, ExecStdio::Piped).unwrap();
    let mut process = ExecSandboxProcess::from_exec_handle(handle).unwrap();
    let mut stdout = process.take_stdout().unwrap();
    let mut started = [0u8; 8];
    stdout.read_exact(&mut started).unwrap();
    assert_eq!(&started, b"started\n");
    process.kill().unwrap();
    assert_eq!(process.wait().unwrap(), CANCELLED_EXIT_CODE);
    assert!(begin.elapsed() < Duration::from_secs(10));
    drop(process);

    exec.script_code = "pgrep -x sleep || echo none".to_owned();
    let handle = backend.exec(&id, &exec, None, ExecStdio::Piped).unwrap();
    let mut process = ExecSandboxProcess::from_exec_handle(handle).unwrap();
    let mut leftover = String::new();
    std::io::Read::read_to_string(&mut process.take_stdout().unwrap(), &mut leftover).unwrap();
    assert_eq!(process.wait().unwrap(), 0);
    assert_eq!(leftover, "none\n");

    backend.stop(&id, &request, None).unwrap();
    backend.deprovision(&id, &request, None).unwrap();
}

/// Runs `script` and returns its exit code and standard output.
fn exec_output(
    backend: &mut NvxStateAwareRunner,
    id: &str,
    request: &ExecutionRequest,
    script: &str,
) -> (i32, String) {
    // Later phases carry only process settings; the policy was fixed at provision.
    let exec = ExecutionRequest {
        script_code: script.to_owned(),
        working_directory: request.working_directory.clone(),
        ..ExecutionRequest::default()
    };
    backend.validate_exec(id, &exec, None).unwrap();
    let handle = backend.exec(id, &exec, None, ExecStdio::Piped).unwrap();
    let mut process = ExecSandboxProcess::from_exec_handle(handle).unwrap();
    let mut stdout = String::new();
    process
        .take_stdout()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    (process.wait().unwrap(), stdout)
}

#[test]
#[ignore = "requires a hypervisor and NVX artifacts"]
fn mxc_filesystem_and_network_policies_reach_the_guest() {
    let host = tempfile::tempdir().unwrap();
    let work = host.path().join("work");
    for directory in ["src/secret", "out", "other"] {
        std::fs::create_dir_all(work.join(directory)).unwrap();
    }
    std::fs::write(work.join("src").join("a.txt"), "source").unwrap();
    std::fs::write(work.join("src").join("secret").join("key"), "hidden").unwrap();
    let text = |path: std::path::PathBuf| path.to_str().unwrap().to_owned();

    // A complete MXC 1.0.0 document goes through MXC's own parser and policy
    // normalization before it reaches the backend.
    let document = json!({
        "version": "1.0.0",
        "containment": "bubblewrap",
        "process": { "commandLine": "true", "cwd": text(work.join("out")) },
        "filesystem": {
            "readonlyPaths": [text(work.join("src"))],
            "readwritePaths": [text(work.join("out"))],
            "deniedPaths": [text(work.join("src").join("secret"))]
        },
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{
                    "to": [{ "cidr": "10.0.0.0/24", "except": ["10.0.0.128/25"] }],
                    "ports": [{ "protocol": "tcp", "port": 53 }]
                }]
            },
            "ingress": { "default": "deny", "hostLoopback": "deny" }
        }
    });
    let mut logger = Logger::new(Mode::Buffer);
    let request = match load_mxc_request_from_json(&document.to_string(), &mut logger) {
        Ok(MxcRequest::OneShot(request)) => request,
        Ok(_) => panic!("expected a one-shot request"),
        Err(error) => panic!("MXC rejected the document: {error:?}"),
    };

    let mut backend = NvxStateAwareRunner::new().unwrap();
    backend.validate_provision(&request, None).unwrap();
    let id = backend.provision(&request, None).unwrap().sandbox_id;
    let _cleanup = Cleanup(id.clone());
    backend.start(&id, &request, None).unwrap();

    let src = guest_path(&work.join("src")).unwrap();
    let out = guest_path(&work.join("out")).unwrap();
    let script = format!(
        "pwd; cat {src}/a.txt; echo; ls {src}; cat {src}/secret/key 2>/dev/null || echo denied; \
         touch {src}/new 2>/dev/null || echo read-only; echo written > result; \
         ls {} 2>/dev/null || echo unmapped; \
         nc -w 3 10.0.0.1 53 </dev/null && echo gateway || echo blocked; \
         nc -w 3 10.0.0.1 80 </dev/null && echo port-80 || echo port-80-blocked",
        guest_path(&work.join("other")).unwrap()
    );
    let (code, stdout) = exec_output(&mut backend, &id, &request, &script);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(
        stdout,
        format!("{out}\nsource\na.txt\ndenied\nread-only\nunmapped\ngateway\nport-80-blocked\n")
    );
    assert_eq!(
        std::fs::read_to_string(work.join("out").join("result")).unwrap(),
        "written\n"
    );
    assert!(!work.join("src").join("new").exists());
}

/// Stops and deprovisions a sandbox through separate phase processes, even when a test fails.
struct Cleanup(String);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = phase_command(&["stop", &self.0]).output();
        let _ = phase_command(&["deprovision", &self.0]).output();
    }
}

#[test]
#[ignore = "requires a hypervisor and NVX artifacts"]
fn phase_processes_accept_mxc_policy_documents() {
    let host = tempfile::tempdir().unwrap();
    let shared = host.path().join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    let document = json!({
        "version": "1.0.0",
        "containment": "bubblewrap",
        "process": { "commandLine": "true" },
        "filesystem": { "readwritePaths": [shared.to_str().unwrap()] },
        "network": {
            "egress": { "default": "allow" },
            "ingress": { "default": "deny", "hostLoopback": "deny" }
        }
    });
    let config = host.path().join("mxc.json");
    std::fs::write(&config, document.to_string()).unwrap();

    let provisioned = result(&["provision", "--config", config.to_str().unwrap()]);
    let id = provisioned["sandboxId"].as_str().unwrap().to_owned();
    let _cleanup = Cleanup(id.clone());
    result(&["start", &id]);
    let output = phase(&[
        "exec",
        &id,
        "--cwd",
        shared.to_str().unwrap(),
        "--",
        "echo from-guest > note; nc -w 3 10.0.0.1 53 </dev/null && echo online",
    ]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"online\n");
    assert_eq!(
        std::fs::read_to_string(shared.join("note")).unwrap(),
        "from-guest\n"
    );
}
