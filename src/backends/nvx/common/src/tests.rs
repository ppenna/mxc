// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use nvx::testing::{MockBackend, MockExec};
use nvx::Capabilities;
use wxc_common::exec_stream::ExecSandboxProcess;
use wxc_common::models::{NetworkEgressPolicy, NetworkPeer, NetworkPort as MxcNetworkPort};
use wxc_common::sandbox_process::SandboxProcess;

use super::*;

fn absolute(name: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(format!("C:\\nvx\\{name}"))
    } else {
        PathBuf::from(format!("/nvx/{name}"))
    }
}

fn config(memory_mib: Option<u32>) -> NvxProvisionConfig {
    NvxProvisionConfig { memory_mib }
}

fn runner_with(backend: MockBackend) -> (NvxStateAwareRunner, Arc<MockBackend>) {
    let backend = Arc::new(backend);
    let runner = NvxStateAwareRunner::with_client(Nvx::from_shared(backend.clone()));
    (runner, backend)
}

fn script(code: &str) -> ExecutionRequest {
    ExecutionRequest {
        script_code: code.to_owned(),
        ..ExecutionRequest::default()
    }
}

fn running(runner: &mut NvxStateAwareRunner) -> String {
    let request = ExecutionRequest::default();
    let id = runner.provision(&request, None).unwrap().sandbox_id;
    runner.start(&id, &request, None).unwrap();
    id
}

fn read_all(mut reader: Box<dyn Read + Send>) -> Vec<u8> {
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();
    output
}

#[test]
fn identity_matches_the_nvx_sandbox_id_prefix() {
    assert_eq!(NvxStateAwareRunner::ID_PREFIX, "nvx");
    assert_eq!(NvxStateAwareRunner::BACKEND_KEY, "nvx");
}

#[test]
fn lifecycle_runs_through_the_mxc_trait_and_stream_consumer() {
    let (mut runner, backend) = runner_with(MockBackend::new());
    let request = ExecutionRequest::default();
    let provision = Some(config(None));
    runner
        .validate_provision(&request, provision.as_ref())
        .unwrap();
    let id = runner.provision(&request, provision).unwrap().sandbox_id;
    assert!(id.starts_with("nvx:"), "{id}");
    runner.validate_start(&id, &request, None).unwrap();
    runner.start(&id, &request, None).unwrap();

    let exec = script("echo hello");
    runner.validate_exec(&id, &exec, None).unwrap();
    let handle = runner.exec(&id, &exec, None, ExecStdio::Piped).unwrap();
    let mut process = ExecSandboxProcess::from_exec_handle(handle).unwrap();
    let stdout = read_all(process.take_stdout().unwrap());
    let stderr = read_all(process.take_stderr().unwrap());
    assert_eq!(process.wait().unwrap(), 0);
    assert_eq!(stdout, b"echo hello\n");
    assert!(stderr.is_empty());

    runner.validate_stop(&id, &request, None).unwrap();
    runner.stop(&id, &request, None).unwrap();
    runner.validate_deprovision(&id, &request, None).unwrap();
    runner.deprovision(&id, &request, None).unwrap();
    assert_eq!(backend.sandbox_count(), 0);
    assert_eq!(
        runner.start(&id, &request, None).unwrap_err().code,
        MxcErrorCode::StaleId
    );
}

#[test]
fn provision_configuration_is_optional_and_sets_memory() {
    let (mut runner, backend) = runner_with(MockBackend::new());
    let request = ExecutionRequest::default();
    runner.validate_provision(&request, None).unwrap();
    let id = runner.provision(&request, None).unwrap().sandbox_id;
    let recorded = backend
        .provision_request(&SandboxId::parse(&id).unwrap())
        .unwrap();
    assert_eq!(recorded.microvm.provision.memory_mib, None);

    let id = runner
        .provision(&request, Some(config(Some(512))))
        .unwrap()
        .sandbox_id;
    let recorded = backend
        .provision_request(&SandboxId::parse(&id).unwrap())
        .unwrap();
    assert_eq!(recorded.microvm.provision.memory_mib, Some(512));
    assert_eq!(
        runner
            .validate_provision(&request, Some(&config(Some(0))))
            .unwrap_err()
            .code,
        MxcErrorCode::MalformedRequest
    );
}

#[test]
fn network_policy_maps_or_is_rejected() {
    let mut request = ExecutionRequest::default();
    assert_eq!(network_policy(&request).unwrap(), NetworkPolicy::deny_all());

    request.policy.default_network_policy = MxcNetworkPolicy::Allow;
    assert_eq!(
        network_policy(&request).unwrap(),
        NetworkPolicy::egress(Access::Allow)
    );

    request.policy.network_egress = Some(NetworkEgressPolicy {
        default: NetworkAction::Deny,
        allow: vec![MxcNetworkRule {
            to: vec![NetworkPeer {
                cidr: "10.0.0.0/8".parse().unwrap(),
                except: vec!["10.1.0.0/16".parse().unwrap()],
            }],
            ports: vec![MxcNetworkPort {
                protocol: NetworkProtocol::Tcp,
                port: Some(443),
                end_port: Some(444),
            }],
        }],
        deny: vec![MxcNetworkRule::default()],
    });
    let policy = network_policy(&request).unwrap();
    assert_eq!(policy.egress.default, Access::Deny);
    assert_eq!(
        policy.egress.allow,
        [nvx::NetworkRule {
            to: vec![nvx::NetworkPeer {
                cidr: "10.0.0.0/8".to_owned(),
                except: vec!["10.1.0.0/16".to_owned()],
            }],
            ports: vec![nvx::NetworkPort {
                protocol: nvx::Protocol::Tcp,
                port: Some(443),
                end_port: Some(444),
            }],
        }]
    );
    assert_eq!(policy.egress.deny, [nvx::NetworkRule::default()]);

    let mut request = ExecutionRequest::default();
    request.policy.allowed_hosts = vec!["example.com".to_owned()];
    assert_eq!(
        network_policy(&request).unwrap_err().code,
        MxcErrorCode::PolicyValidation
    );

    let mut request = ExecutionRequest::default();
    request.policy.network_proxy.builtin_test_server = true;
    assert_eq!(
        network_policy(&request).unwrap_err().code,
        MxcErrorCode::PolicyValidation
    );
}

#[test]
fn working_directories_are_mapped_into_the_guest() {
    assert_eq!(guest_working_directory("/tmp").unwrap(), "/tmp");
    if cfg!(windows) {
        assert_eq!(
            guest_working_directory(r"C:\Work\src").unwrap(),
            "/mnt/c/Work/src"
        );
        assert_eq!(
            guest_working_directory(r"\\server\share").unwrap_err().code,
            MxcErrorCode::PolicyValidation
        );
    }
    assert_eq!(
        guest_working_directory("relative").unwrap_err().code,
        MxcErrorCode::PolicyValidation
    );
    let mut request = script("pwd");
    request.working_directory = absolute("work").display().to_string();
    let exec = exec_request(&request).unwrap();
    assert_eq!(
        exec.process.cwd.as_deref(),
        nvx::openvmm::guest_path(&absolute("work")).as_deref()
    );
}

#[test]
fn unsupported_policy_is_rejected_before_anything_runs() {
    let mut capabilities = MockBackend::full_capabilities();
    capabilities.exec.cwd = false;
    capabilities.filesystem = Capabilities::new("restricted").filesystem;
    let (mut runner, backend) = runner_with(MockBackend::new().with_capabilities(capabilities));

    let mut mapped = ExecutionRequest::default();
    mapped.policy.readonly_paths = vec![absolute("data").display().to_string()];
    let error = runner.validate_provision(&mapped, None).unwrap_err();
    assert_eq!(error.code, MxcErrorCode::PolicyValidation);
    assert_eq!(backend.sandbox_count(), 0);

    let id = running(&mut runner);
    let mut exec = script("pwd");
    exec.working_directory = "/tmp".to_owned();
    assert_eq!(
        runner.validate_exec(&id, &exec, None).unwrap_err().code,
        MxcErrorCode::PolicyValidation
    );

    let mut restated = ExecutionRequest::default();
    restated.policy.network_mode_specified = true;
    assert_eq!(
        runner.validate_stop(&id, &restated, None).unwrap_err().code,
        MxcErrorCode::PolicyValidation
    );
    assert_eq!(
        runner
            .validate_start("wsb:0123", &ExecutionRequest::default(), None)
            .unwrap_err()
            .code,
        MxcErrorCode::MalformedId
    );
}

#[test]
fn timeouts_are_outcomes_only_for_piped_callers() {
    let (mut runner, _) = runner_with(MockBackend::new().with_exec_handler(|_| MockExec {
        duration: Duration::from_secs(30),
        ..MockExec::default()
    }));
    let id = running(&mut runner);
    let mut exec = script("sleep 30");
    exec.script_timeout = 50;

    let handle = runner.exec(&id, &exec, None, ExecStdio::Piped).unwrap();
    assert_eq!((handle.waiter)().unwrap(), ExecOutcome::TimedOut);

    let handle = runner.exec(&id, &exec, None, ExecStdio::Relayed).unwrap();
    assert_eq!(
        (handle.waiter)().unwrap_err().code,
        MxcErrorCode::BackendError
    );
}

#[test]
fn signals_become_shell_style_exit_codes() {
    assert_eq!(
        map_outcome(nvx::ExecOutcome::Signaled(9), ExecStdio::Relayed).unwrap(),
        ExecOutcome::Exited(137)
    );
}

#[test]
fn the_terminator_cancels_and_the_waiter_reports_a_kill() {
    let (mut runner, _) = runner_with(MockBackend::new().with_exec_handler(|_| MockExec {
        duration: Duration::from_secs(30),
        ..MockExec::default()
    }));
    let id = running(&mut runner);
    for stdio in [ExecStdio::Piped, ExecStdio::Relayed] {
        let handle = runner.exec(&id, &script("sleep 30"), None, stdio).unwrap();
        (handle.terminator)().unwrap();
        assert_eq!(
            (handle.waiter)().unwrap(),
            ExecOutcome::Exited(CANCELLED_EXIT_CODE)
        );
    }

    // MXC's stream consumer kills through the same terminator.
    let handle = runner
        .exec(&id, &script("sleep 30"), None, ExecStdio::Piped)
        .unwrap();
    let mut process = ExecSandboxProcess::from_exec_handle(handle).unwrap();
    process.kill().unwrap();
    assert_eq!(process.wait().unwrap(), CANCELLED_EXIT_CODE);
}

#[test]
fn errors_keep_their_mxc_codes() {
    let error = map_error(SandboxId::parse("nvx:nope").unwrap_err());
    assert_eq!(error.code, MxcErrorCode::MalformedId);
    for (code, expected) in [
        (ErrorCode::StaleId, MxcErrorCode::StaleId),
        (ErrorCode::NotStarted, MxcErrorCode::NotStarted),
        (
            ErrorCode::BackendUnavailable,
            MxcErrorCode::BackendUnavailable,
        ),
        (ErrorCode::Unsupported, MxcErrorCode::BackendError),
    ] {
        assert_eq!(map_error(nvx::Error::new(code, "x")).code, expected);
    }
}
