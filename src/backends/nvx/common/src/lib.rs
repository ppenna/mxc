// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` for NVX microVM sandboxes.
//!
//! This is a proof of concept that drives the five state-aware phases through the
//! [`nvx`] crate, whose default backend launches OpenVMM directly and keeps sandbox
//! state on disk. Every phase can therefore run in its own short-lived process, which
//! matches MXC's one-process-per-phase model; no daemon is involved.
//!
//! - Each sandbox is a microVM that runs the NVX guest's Alpine Linux userland
//!   directly; there are no image layers or scratch disks. Guest state lives in
//!   memory until the sandbox stops.
//! - The OpenVMM executable, guest kernel, and Alpine initramfs are located with
//!   [`nvx::openvmm::Artifacts::discover`]: `NVX_ARTIFACTS_DIR`, an `nvx/`
//!   directory next to the executable, or the bundle staged by the `bundled`
//!   feature.
//! - Provision configuration is the NVX contract's optional `microvm.provision`
//!   section ([`NvxProvisionConfig`]), which sets the guest memory size.
//! - Exec returns real stdout and stderr pipes for both [`ExecStdio`] topologies;
//!   standard input is not exposed, and the workload reads end-of-file. The
//!   terminator cancels the workload: the guest kills every process in the
//!   workload's cgroup, and the waiter then reports `Exited(137)`.
//!
//! Policy honor follows the nvx crate:
//!
//! - **Network** is fixed at provision. The egress default and directional
//!   egress rules (IPv4 CIDRs with exceptions, TCP/UDP ports and port ranges)
//!   are enforced by OpenVMM; ingress and host loopback are denied. Host-name
//!   lists, proxies, ICMP-only rules, and IPv6 are rejected.
//! - **Filesystem** paths are mapped into the guest the way WSLc maps them:
//!   `C:\work\src` appears at `/mnt/c/work/src`, read-only or read-write;
//!   denied paths inside mapped paths are hidden by OpenVMM. Mapped paths must
//!   exist and share one volume.
//! - **Exec** honors `working_directory` (a host path is translated the same
//!   way) and the timeout; `env` is rejected. The workload runs as a fixed
//!   non-root identity.
//!
//! Rejections surface as `policy_validation` before anything runs.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nvx::openvmm::{resolve_guest_path, Artifacts, Hypervisor, OpenVmmConfig};
use nvx::{
    Access, EgressPolicy, ErrorCode, ExecRequest, FilesystemPolicy, IngressPolicy, Metadata,
    NetworkPeer, NetworkPolicy, NetworkPort, NetworkRule, Nvx, Protocol, ProvisionRequest,
    SandboxId,
};
use wxc_common::models::{
    ExecutionRequest, NetworkAction, NetworkPolicy as MxcNetworkPolicy, NetworkProtocol,
    NetworkRule as MxcNetworkRule,
};
use wxc_common::mxc_error::{MxcError, MxcErrorCode};
use wxc_common::state_aware_backend::{
    null_pipe_handle, DeprovisionResult, ExecHandle, ExecOutcome, ExecStdio, PipeHandle,
    ProvisionResult, StartResult, StatefulSandboxBackend, StopResult,
};

/// Provision configuration: the NVX contract's `microvm.provision` section
/// (the optional `memoryMib`).
pub type NvxProvisionConfig = nvx::MicrovmProvision;

/// Exit code the waiter reports for a cancelled workload, which the guest kills
/// with `SIGKILL`.
pub const CANCELLED_EXIT_CODE: i32 = 128 + 9;

/// State-aware NVX backend.
#[derive(Debug, Clone)]
pub struct NvxStateAwareRunner {
    nvx: Nvx,
}

impl NvxStateAwareRunner {
    /// Creates the backend from discovered artifacts, the host's hypervisor
    /// (`NVX_HYPERVISOR` overrides it), and the per-user state root.
    pub fn new() -> Result<Self, MxcError> {
        let config = OpenVmmConfig::from_artifacts(
            Artifacts::discover().map_err(map_error)?,
            Hypervisor::from_env_or_default().map_err(map_error)?,
            OpenVmmConfig::default_state_root().map_err(map_error)?,
        );
        Ok(Self::with_client(Nvx::openvmm(config).map_err(map_error)?))
    }

    /// Creates the backend over an existing client, for tests and embedders.
    pub fn with_client(nvx: Nvx) -> Self {
        Self { nvx }
    }

    /// The underlying nvx client.
    pub fn client(&self) -> &Nvx {
        &self.nvx
    }

    fn provision_request(
        &self,
        request: &ExecutionRequest,
        config: Option<&NvxProvisionConfig>,
    ) -> Result<ProvisionRequest, MxcError> {
        let mut provision = ProvisionRequest::new();
        if let Some(memory_mib) = config.and_then(|config| config.memory_mib) {
            provision = provision.with_memory_mib(memory_mib);
        }
        let filesystem = filesystem_policy(request);
        if !filesystem.is_empty() {
            provision = provision.with_filesystem(filesystem);
        }
        Ok(provision.with_network(network_policy(request)?))
    }
}

impl StatefulSandboxBackend for NvxStateAwareRunner {
    const ID_PREFIX: &'static str = SandboxId::PREFIX;
    const BACKEND_KEY: &'static str = "nvx";

    type ProvisionConfig = NvxProvisionConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = Metadata;
    type StartMetadata = Metadata;
    type StopMetadata = Metadata;
    type DeprovisionMetadata = Metadata;

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<NvxProvisionConfig>,
    ) -> Result<ProvisionResult<Metadata>, MxcError> {
        let provision = self.provision_request(request, config.as_ref())?;
        let result = self.nvx.provision(&provision).map_err(map_error)?;
        Ok(ProvisionResult {
            sandbox_id: result.sandbox_id.to_string(),
            metadata: result.metadata,
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StartResult<Metadata>, MxcError> {
        let result = self.nvx.start(&parse_id(sandbox_id)?).map_err(map_error)?;
        Ok(StartResult {
            metadata: result.metadata,
        })
    }

    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        let sandbox_id = parse_id(sandbox_id)?;
        let exec = exec_request(request)?;
        let mut execution = self.nvx.exec(&sandbox_id, &exec).map_err(map_error)?;
        let streams = Arc::new(Streams {
            stdout: execution
                .take_stdout()
                .ok_or_else(|| MxcError::backend_error("nvx returned no stdout pipe"))?,
            stderr: execution
                .take_stderr()
                .ok_or_else(|| MxcError::backend_error("nvx returned no stderr pipe"))?,
        });
        let canceller = execution.canceller();
        let (waiter_streams, terminator_streams) = (Arc::clone(&streams), Arc::clone(&streams));
        Ok(ExecHandle {
            stdout: pipe_handle(&streams.stdout),
            stderr: pipe_handle(&streams.stderr),
            stdin: null_pipe_handle(),
            // The closures own the read ends, so the handles stay valid until MXC is done
            // with both; MXC duplicates them and never closes these originals.
            waiter: Box::new(move || {
                let _streams = waiter_streams;
                map_outcome(execution.wait().map_err(map_error)?, stdio)
            }),
            terminator: Box::new(move || {
                let _streams = terminator_streams;
                canceller.cancel().map_err(map_error)
            }),
            stdin_closer: None,
        })
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StopResult<Metadata>, MxcError> {
        let result = self.nvx.stop(&parse_id(sandbox_id)?).map_err(map_error)?;
        Ok(StopResult {
            metadata: result.metadata,
        })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<Metadata>, MxcError> {
        let result = self
            .nvx
            .deprovision(&parse_id(sandbox_id)?)
            .map_err(map_error)?;
        Ok(DeprovisionResult {
            metadata: result.metadata,
        })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&NvxProvisionConfig>,
    ) -> Result<(), MxcError> {
        let provision = self.provision_request(request, config)?;
        self.nvx.validate_provision(&provision).map_err(map_error)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision(sandbox_id, request)
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision(sandbox_id, request)?;
        self.nvx
            .validate_exec(&exec_request(request)?)
            .map_err(map_error)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision(sandbox_id, request)
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision(sandbox_id, request)
    }
}

/// Read ends of an execution's output pipes.
struct Streams {
    stdout: std::io::PipeReader,
    stderr: std::io::PipeReader,
}

#[cfg(windows)]
fn pipe_handle(reader: &std::io::PipeReader) -> PipeHandle {
    use std::os::windows::io::AsRawHandle;
    windows::Win32::Foundation::HANDLE(reader.as_raw_handle())
}

#[cfg(unix)]
fn pipe_handle(reader: &std::io::PipeReader) -> PipeHandle {
    use std::os::fd::AsRawFd;
    reader.as_raw_fd()
}

fn parse_id(sandbox_id: &str) -> Result<SandboxId, MxcError> {
    SandboxId::parse(sandbox_id).map_err(map_error)
}

/// The network posture is fixed at provision; later phases may not restate it.
fn validate_post_provision(sandbox_id: &str, request: &ExecutionRequest) -> Result<(), MxcError> {
    parse_id(sandbox_id)?;
    if request.policy.network_mode_specified {
        return Err(MxcError::policy_validation(
            "the nvx backend fixes the network posture at provision; omit network after it",
        ));
    }
    reject_proxy(request)
}

fn reject_proxy(request: &ExecutionRequest) -> Result<(), MxcError> {
    if request.policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(
            "the nvx backend cannot route workload traffic through a network proxy",
        ));
    }
    Ok(())
}

/// Returns the guest directory of a working directory: a host path is mapped the way the
/// filesystem policy maps it (`C:\work` becomes `/mnt/c/work`), and a guest path is kept.
fn guest_working_directory(directory: &str) -> Result<String, MxcError> {
    if directory.starts_with('/') {
        return Ok(directory.to_owned());
    }
    resolve_guest_path(Path::new(directory)).ok_or_else(|| {
        MxcError::policy_validation(format!(
            "the nvx backend cannot map the working directory {directory:?} into the guest; use \
             an absolute local path"
        ))
    })
}

fn exec_request(request: &ExecutionRequest) -> Result<ExecRequest, MxcError> {
    let mut exec = ExecRequest::command_line(request.script_code.clone());
    if request.script_timeout > 0 {
        exec = exec.with_timeout(Duration::from_millis(request.script_timeout.into()));
    }
    if !request.working_directory.is_empty() {
        exec = exec.with_cwd(guest_working_directory(&request.working_directory)?);
    }
    if let Some(env) = &request.env {
        for entry in env {
            exec = exec.with_env(entry.clone());
        }
        exec = exec.with_inherit_default_env(request.inherit_default_env);
    }
    Ok(exec)
}

fn filesystem_policy(request: &ExecutionRequest) -> FilesystemPolicy {
    let paths = |paths: &[String]| paths.iter().map(PathBuf::from).collect();
    FilesystemPolicy {
        readonly_paths: paths(&request.policy.readonly_paths),
        readwrite_paths: paths(&request.policy.readwrite_paths),
        denied_paths: paths(&request.policy.denied_paths),
    }
}

/// Maps MXC's network policy onto the NVX contract. Directional egress rules map
/// one to one; host-name lists and proxies have no NVX equivalent and are rejected
/// rather than dropped.
fn network_policy(request: &ExecutionRequest) -> Result<NetworkPolicy, MxcError> {
    let policy = &request.policy;
    if !policy.allowed_hosts.is_empty() || !policy.blocked_hosts.is_empty() {
        return Err(MxcError::policy_validation(
            "the nvx backend cannot enforce allowedHosts or blockedHosts; use egress CIDR rules",
        ));
    }
    reject_proxy(request)?;
    let access = |action: NetworkAction| match action {
        NetworkAction::Allow => Access::Allow,
        NetworkAction::Deny => Access::Deny,
    };
    let egress = match &policy.network_egress {
        Some(egress) => EgressPolicy {
            default: access(egress.default),
            allow: egress.allow.iter().map(network_rule).collect(),
            deny: egress.deny.iter().map(network_rule).collect(),
        },
        None if policy.default_network_policy == MxcNetworkPolicy::Allow => {
            EgressPolicy::new(Access::Allow)
        }
        None => EgressPolicy::new(Access::Deny),
    };
    let (ingress, host_loopback) = match &policy.network_ingress {
        Some(ingress) => (access(ingress.default), access(ingress.host_loopback)),
        None if policy.allow_local_network => (Access::Allow, Access::Deny),
        None => (Access::Deny, Access::Deny),
    };
    Ok(NetworkPolicy {
        egress,
        ingress: IngressPolicy {
            default: ingress,
            host_loopback: Some(host_loopback),
        },
    })
}

fn network_rule(rule: &MxcNetworkRule) -> NetworkRule {
    let cidr =
        |cidr: &wxc_common::models::NetworkCidr| format!("{}/{}", cidr.address, cidr.prefix_length);
    NetworkRule {
        to: rule
            .to
            .iter()
            .map(|peer| NetworkPeer {
                cidr: cidr(&peer.cidr),
                except: peer.except.iter().map(cidr).collect(),
            })
            .collect(),
        ports: rule
            .ports
            .iter()
            .map(|port| NetworkPort {
                protocol: match port.protocol {
                    NetworkProtocol::Tcp => Protocol::Tcp,
                    NetworkProtocol::Udp => Protocol::Udp,
                    NetworkProtocol::Icmp => Protocol::Icmp,
                    NetworkProtocol::Any => Protocol::Any,
                },
                port: port.port,
                end_port: port.end_port,
            })
            .collect(),
    }
}

fn map_outcome(outcome: nvx::ExecOutcome, stdio: ExecStdio) -> Result<ExecOutcome, MxcError> {
    match outcome {
        nvx::ExecOutcome::Exited(code) => Ok(ExecOutcome::Exited(code)),
        nvx::ExecOutcome::Signaled(signal) => Ok(ExecOutcome::Exited(128 + signal)),
        // A terminator kill reads like the SIGKILL exit status other backends report.
        nvx::ExecOutcome::Cancelled => Ok(ExecOutcome::Exited(CANCELLED_EXIT_CODE)),
        // The relay has no way to represent a timeout, so it is reported as an error there.
        nvx::ExecOutcome::TimedOut if stdio == ExecStdio::Piped => Ok(ExecOutcome::TimedOut),
        other => Err(MxcError::backend_error(format!("the workload {other}"))),
    }
}

/// Maps an nvx error onto the MXC state-aware error model, keeping its cause chain.
pub fn map_error(error: nvx::Error) -> MxcError {
    let code = match error.code() {
        ErrorCode::MalformedRequest => MxcErrorCode::MalformedRequest,
        ErrorCode::MalformedId => MxcErrorCode::MalformedId,
        ErrorCode::StaleId => MxcErrorCode::StaleId,
        ErrorCode::NotStarted => MxcErrorCode::NotStarted,
        ErrorCode::AlreadyStarted => MxcErrorCode::AlreadyStarted,
        ErrorCode::AlreadyStopped => MxcErrorCode::AlreadyStopped,
        ErrorCode::PolicyValidation => MxcErrorCode::PolicyValidation,
        ErrorCode::BackendUnavailable => MxcErrorCode::BackendUnavailable,
        _ => MxcErrorCode::BackendError,
    };
    let mut message = error.message().to_owned();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        message.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    MxcError::new(code, message)
}

#[cfg(test)]
mod tests;
