// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runs one state-aware phase per process, the way `wxc-exec` does, against the
//! NVX backend. Proof-of-concept harness until the backend is wired into the
//! MXC wire contract.
//!
//! ```text
//! nvx-mxc-phase provision [--config MXC.json] [--egress allow|deny] [--memory-mib N]
//! nvx-mxc-phase start|stop|deprovision <sandbox-id>
//! nvx-mxc-phase exec <sandbox-id> [--timeout-ms N] [--cwd DIR] -- <command line>
//! ```
//!
//! `--config` reads an MXC one-shot request document (for example, version
//! `1.0.0`) through MXC's own parser and provisions with its `filesystem` and
//! `network` policy.
//!
//! Non-exec phases print a JSON envelope: `{"result": ...}` or `{"error": ...}`.
//! Exec relays the workload's output and exits with its exit code.

use std::io::{Read, Write};
use std::process::ExitCode;

use nvx_backend::{NvxProvisionConfig, NvxStateAwareRunner};
use serde_json::{json, Value};
use wxc_common::config_parser::load_mxc_request_from_json;
use wxc_common::exec_stream::ExecSandboxProcess;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ExecutionRequest, NetworkPolicy};
use wxc_common::mxc_error::MxcError;
use wxc_common::sandbox_process::SandboxProcess;
use wxc_common::state_aware_backend::{ExecHandle, ExecStdio, StatefulSandboxBackend};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(Outcome::Envelope(result)) => {
            println!("{}", json!({ "result": result }));
            ExitCode::SUCCESS
        }
        Ok(Outcome::Exited(code)) => ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX)),
        Err(error) => {
            println!(
                "{}",
                json!({ "error": { "code": error.code.as_str(), "message": error.message } })
            );
            ExitCode::FAILURE
        }
    }
}

enum Outcome {
    Envelope(Value),
    Exited(i32),
}

fn run(arguments: &[String]) -> Result<Outcome, MxcError> {
    let usage = || MxcError::malformed_request("see the usage in nvx-mxc-phase's documentation");
    let (phase, target, options) = match arguments {
        [phase, rest @ ..] if phase == "provision" => (phase.as_str(), "", rest),
        [phase, target, rest @ ..] => (phase.as_str(), target.as_str(), rest),
        _ => return Err(usage()),
    };
    let mut request = ExecutionRequest::default();
    let mut backend = NvxStateAwareRunner::new()?;
    let metadata = |value: Option<nvx::Metadata>| json!({ "metadata": value });
    match phase {
        "provision" => {
            if let Some(path) = option(options, "--config") {
                request = load_policy(path)?;
            }
            if let Some(egress) = option(options, "--egress") {
                request.policy.default_network_policy = match egress {
                    "allow" => NetworkPolicy::Allow,
                    "deny" => NetworkPolicy::Block,
                    _ => return Err(usage()),
                };
            }
            let mut config = NvxProvisionConfig::default();
            if let Some(memory_mib) = option(options, "--memory-mib") {
                config.memory_mib = Some(memory_mib.parse().map_err(|_| usage())?);
            }
            backend.validate_provision(&request, Some(&config))?;
            let result = backend.provision(&request, Some(config))?;
            Ok(Outcome::Envelope(json!({
                "sandboxId": result.sandbox_id,
                "metadata": result.metadata,
            })))
        }
        "start" => {
            backend.validate_start(target, &request, None)?;
            Ok(Outcome::Envelope(metadata(
                backend.start(target, &request, None)?.metadata,
            )))
        }
        "stop" => {
            backend.validate_stop(target, &request, None)?;
            Ok(Outcome::Envelope(metadata(
                backend.stop(target, &request, None)?.metadata,
            )))
        }
        "deprovision" => {
            backend.validate_deprovision(target, &request, None)?;
            Ok(Outcome::Envelope(metadata(
                backend.deprovision(target, &request, None)?.metadata,
            )))
        }
        "exec" => {
            let separator = options.iter().position(|option| option == "--");
            let command = separator.map(|index| options[index + 1..].join(" "));
            request.script_code = command.ok_or_else(usage)?;
            if let Some(timeout) = option(options, "--timeout-ms") {
                request.script_timeout = timeout.parse().map_err(|_| usage())?;
            }
            if let Some(cwd) = option(options, "--cwd") {
                request.working_directory = cwd.to_owned();
            }
            backend.validate_exec(target, &request, None)?;
            let handle = backend.exec(target, &request, None, ExecStdio::Relayed)?;
            relay(handle).map(Outcome::Exited)
        }
        _ => Err(usage()),
    }
}

/// Parses an MXC one-shot request document and returns its runtime request.
fn load_policy(path: &str) -> Result<ExecutionRequest, MxcError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| MxcError::malformed_request(format!("cannot read {path}: {error}")))?;
    let mut logger = Logger::new(Mode::Buffer);
    match load_mxc_request_from_json(&text, &mut logger) {
        Ok(wxc_common::state_aware_request::MxcRequest::OneShot(request)) => Ok(request),
        Ok(_) => Err(MxcError::malformed_request(
            "--config expects a one-shot MXC request document",
        )),
        Err(error) => Err(MxcError::malformed_request(format!(
            "MXC rejected {path}: {error:?}"
        ))),
    }
}

/// Relays both streams to this process's stdio and returns the exit code.
fn relay(handle: ExecHandle) -> Result<i32, MxcError> {
    let mut process = ExecSandboxProcess::from_exec_handle(handle)?;
    let pumps = [
        process
            .take_stdout()
            .map(|reader| pump(reader, std::io::stdout())),
        process
            .take_stderr()
            .map(|reader| pump(reader, std::io::stderr())),
    ];
    let code = process
        .wait()
        .map_err(|error| MxcError::backend_error(error.to_string()))?;
    for pump in pumps.into_iter().flatten() {
        let _ = pump.join();
    }
    Ok(code)
}

fn pump(
    mut reader: Box<dyn Read + Send>,
    mut writer: impl Write + Send + 'static,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = [0; 8192];
        while let Ok(read) = reader.read(&mut buffer) {
            if read == 0 || writer.write_all(&buffer[..read]).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    })
}

fn option<'a>(options: &'a [String], name: &str) -> Option<&'a str> {
    let end = options
        .iter()
        .position(|option| option == "--")
        .unwrap_or(options.len());
    options[..end]
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}
