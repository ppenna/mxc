# NVX backend (proof of concept)

`nvx_backend` implements `StatefulSandboxBackend` for NVX microVM sandboxes on
top of the [`nvx`](https://github.com/microsoft/nvx/tree/feat-nvx-rs/nvx-rs)
crate. The nvx crate launches OpenVMM directly and keeps sandbox state on disk,
so each phase can run in its own short-lived process, as `wxc-exec` does. No
daemon is involved.

Each sandbox is a microVM that runs the NVX guest's Alpine Linux userland
directly from its initramfs. There are no image layers, scratch disks, or
container namespaces. Workloads run as Alpine's `nobody` (65534) without
capabilities, and guest state lives in memory until the sandbox stops.

| Item | Value |
| --- | --- |
| `ID_PREFIX` / `BACKEND_KEY` | `nvx` / `nvx` |
| Provision configuration | Optional `NvxProvisionConfig`, the NVX contract's `microvm.provision`: `memoryMib` |
| Metadata | `start`: `bootMilliseconds`; `stop`: `forced`, `vmOutcome`, `vmStatusCode`, `teardownComplete` |
| Exec | Real stdout and stderr pipes for both `Relayed` and `Piped`; no stdin |
| Waiter | `Exited(c)`; a signal becomes `Exited(128 + s)`; a cancelled workload `Exited(137)`; `TimedOut` under `Piped` (an error under `Relayed`) |
| Terminator | Cancels the workload: the guest kills every process in the workload's cgroup. `ExecSandboxProcess::kill` therefore stops it. |

No workload process outlives its exec, even one that starts its own session. If
the process that runs an exec dies, the guest kills the workload as soon as
OpenVMM resets the control session, so the next exec does not wait for it.

## Policy

Policy honor follows the nvx crate; anything it cannot enforce is rejected with
`policy_validation` before anything runs.

| MXC policy | NVX behavior |
| --- | --- |
| `filesystem.readonlyPaths`, `readwritePaths` | Mapped into the guest the way WSLc maps them: `C:\work\src` appears at `/mnt/c/work/src`, read-only or read-write. Paths must exist and share a directory below the volume root. |
| `filesystem.deniedPaths` | Hidden by OpenVMM inside mapped paths. A denied path that contains a mapped path, or that does not exist inside one, is rejected. |
| `network.egress` | The default and directional rules are enforced by OpenVMM: IPv4 CIDRs with `except`, TCP/UDP ports and port ranges, and protocol `any`. IPv6, ICMP-only selectors, and TCP/UDP selectors without ports are rejected. |
| `network.ingress`, `hostLoopback` | `deny` only. |
| Legacy `defaultPolicy` | `allow` or `block` maps to the egress default. `allowedHosts`, `blockedHosts`, and proxies are rejected. |
| `process.cwd` | A host path is translated like a mapped path; a guest path is kept. A missing directory ends the workload with exit code 125. |
| `process.env` | Rejected. |

The network posture is fixed at provision; restating network policy in a later
phase is rejected. On Linux hosts, sandboxes that map host paths run their
workloads under the calling user's IDs, so host permissions apply as they do to
that user.

## Artifacts

`NvxStateAwareRunner::new` locates the OpenVMM executable, guest kernel, and
Alpine initramfs with `nvx::openvmm::Artifacts::discover`, in this order:

1. `NVX_OPENVMM`, `NVX_KERNEL`, and `NVX_INITRD`.
2. `NVX_ARTIFACTS_DIR`: an extracted NVX release or an NVX repository checkout.
3. An `nvx/` release directory next to the executable.
4. The build-time bundle, staged by the `bundled` feature.

With the `bundled` feature, the nvx build script stages the release pinned in
its `artifacts.json`, or the directory named by `NVX_BUNDLE_DIR`, and verifies
`SHA256SUMS`. A deployment ships that directory as `nvx/` next to `wxc-exec`.
Its path is exported to dependent build scripts as `DEP_NVX_ARTIFACTS_DIR`.
Cancellation needs an initramfs built from the nvx `feat-nvx-rs` guest sources
or later; the release pinned today predates it.

`NVX_HYPERVISOR` overrides the hypervisor (`whp` on Windows, `kvm` on Linux).
Sandbox state lives under `%LOCALAPPDATA%\nvx\sandboxes` or
`~/.local/state/nvx/sandboxes`.

## Running

```text
cargo test -p nvx_backend                     # mock-backed unit tests; no hypervisor needed
set NVX_ARTIFACTS_DIR=<extracted NVX release>
cargo test -p nvx_backend --test real_hypervisor -- --ignored --nocapture --test-threads=1
```

The `nvx-mxc-phase` binary runs one phase per process and prints a JSON
envelope, which stands in for `wxc-exec` until the backend is routed.
`--config` provisions with the `filesystem` and `network` policy of an MXC
one-shot request document, parsed by MXC's own parser:

```text
nvx-mxc-phase provision [--config MXC.json] [--egress allow|deny] [--memory-mib N]
nvx-mxc-phase start nvx:<token>
nvx-mxc-phase exec nvx:<token> [--cwd DIR] -- cat /etc/os-release
nvx-mxc-phase stop nvx:<token>
nvx-mxc-phase deprovision nvx:<token>
```

## Not done yet

- Wire contract: a `nvx` containment in the schema and `mxc_config_contract`,
  `ContainmentBackend::Nvx`, the `nvx` prefix in `backend_from_prefix`, a
  `bind_nvx` helper, and an engine dispatch arm.
- The `nvx` dependency is a path to a sibling `microsoft/nvx` checkout. A git
  dependency also fetches the private `openvmm` submodule.
