# Current State: Windows WSL2 Backend

*Last updated: February 2026*

## Summary

The Windows backend uses WSL2 (Windows Subsystem for Linux 2) as a **process backend** — it manages a lightweight Alpine Linux distro as a subprocess rather than emulating CPU instructions. The VM lifecycle infrastructure is complete. The remaining work is VPN/SOCKS5 integration for Velocitty.

---

## Why WSL2 Instead of WHP

The original Windows backend used WHP (Windows Hypervisor Platform) for native CPU virtualization. WHP was abandoned due to an **unfixable MSR handling bug**:

- WHP MSR exits don't report which MSR is being accessed (`MsrNumber` field and `ECX` register both read 0)
- WHP corrupts `RAX`/`RDX` values in MSR exit contexts
- WHP reports wrong instruction lengths (e.g., 1 instead of 2 for RDMSR/WRMSR)
- QEMU's WHPX backend has the same issue and just returns 0 for all RDMSR
- Standard Linux kernels cannot boot because they rely on MSRs for timer calibration, APIC config, and paravirt ops

**Result:** Kernel boots to 64-bit long mode but crashes with Divide Error (#DE) during timer calibration. No viable workaround exists without a custom-built kernel.

WSL2 sidesteps all of this by using Microsoft's own Linux kernel and Hyper-V virtualization under the hood.

---

## Architecture

```
Host (Windows)                          WSL2 Distro (microvm-rs)
┌──────────────────────┐                ┌──────────────────────────┐
│  Velocitty / CLI     │                │  Alpine Linux 3.21.3     │
│  ┌────────────────┐  │   TCP 1025     │  ┌────────────────────┐  │
│  │  WslBackend    │──│───────────────→│  │  init-microvm.sh   │  │
│  │                │  │  (commands)    │  │  (control daemon)  │  │
│  └────────────────┘  │                │  └────────────────────┘  │
│  ┌────────────────┐  │                │                          │
│  │ TcpVsockBridge │──│── localhost ──→│  [future: SOCKS5 proxy]  │
│  │                │  │                │  [future: OpenVPN]       │
│  └────────────────┘  │                │                          │
└──────────────────────┘                └──────────────────────────┘
        ↑ shared network namespace (127.0.0.1)
```

**Key insight:** WSL2 shares the host's network namespace. `localhost:1025` inside WSL2 is the same as `localhost:1025` on the host. No port forwarding or vsock emulation needed.

---

## Component Status

### Fully Implemented

| Component | File | What It Does |
|---|---|---|
| **WslBackend** | `src/backend/wsl/mod.rs` | HypervisorBackend impl: start, pause, resume, shutdown, kill |
| **WslDistro** | `src/backend/wsl/distro.rs` | Distro lifecycle: import, exec, exec_with_stdin, terminate, unregister, shell |
| **Process wrapper** | `src/backend/wsl/process.rs` | wsl.exe CLI wrapper, UTF-16LE decoding, availability check |
| **Rootfs manager** | `src/backend/wsl/rootfs.rs` | Embedded Alpine extraction, data directory management |
| **Control daemon** | `guest/wsl-rootfs/init-microvm.sh` | TCP listener on port 1025, socat-based concurrent connections |
| **VsockClient/Handler** | `src/vsock.rs` | Async host-guest communication API |
| **TcpVsockBridge** | `src/vsock.rs` | Maps vsock messages to TCP connections (Windows only) |
| **ProxyConnectionManager** | `src/proxy.rs` | Outbound TCP proxy protocol (binary framing) |
| **Cleanup** | `src/backend/wsl/mod.rs` | `cleanup()` terminates distro, unregisters, removes data |
| **Shell access** | `src/backend/wsl/mod.rs` | `spawn_shell()` (piped) and `run_shell_interactive()` (inherited) |

### Stub / Simplified

| Component | Status | Notes |
|---|---|---|
| **pause/resume** | Stub | Daemon echoes "paused"/"resumed" but doesn't actually pause processes |
| **Windows runtime event loop** | Minimal | Bridges vsock messages via TCP, reads daemon stdout. No proxy manager integration. |
| **CLI Windows path** | Minimal | `src/bin/microvm.rs` just calls start(), waits for Ctrl+C, then shutdown() |
| **Console input** | Not handled | Runtime discards console input on Windows |

### Not Implemented (VPN Integration)

| Component | What's Needed | Priority |
|---|---|---|
| **SOCKS5 proxy** | Deploy microsocks or similar in guest, start on port 1080 | High |
| **OpenVPN client** | Install openvpn in guest, accept config from host | High |
| **VPN lifecycle commands** | Add vpn-start/vpn-stop/vpn-status to daemon protocol | High |
| **VPN config delivery** | Pass .ovpn config from host to guest via control channel | Medium |
| **Connection health monitoring** | Periodic VPN status checks, auto-reconnect | Medium |
| **DNS handling** | Configure guest DNS for VPN tunnel | Medium |

---

## Boot Flow (What Happens Today)

```
1. backend.start()
   ├── ensure_distro()
   │   ├── Check if "microvm-rs" distro already registered
   │   ├── If not: extract embedded Alpine → wsl --import
   │   └── If new: provision_distro()
   │       ├── Write /etc/wsl.conf (disable automount, Windows path interop)
   │       ├── apk update && apk add --no-cache socat
   │       ├── Pipe init-microvm.sh → /etc/microvm/init-microvm.sh
   │       └── chmod +x
   └── Launch daemon: wsl -d microvm-rs -- /bin/sh /etc/microvm/init-microvm.sh
       ├── Daemon starts socat listener on TCP 1025
       └── Host polls 127.0.0.1:1025 every 200ms (timeout: 30s)

2. Host sends commands via TCP:
   send_command("ping")     → "pong"
   send_command("status")   → "running"
   send_command("pause")    → "paused"
   send_command("shutdown")  → terminates

3. backend.shutdown()
   ├── send_command("shutdown") (non-blocking)
   ├── wsl --terminate microvm-rs
   └── Kill daemon process
```

---

## Data Paths

| Path | Location | Purpose |
|---|---|---|
| `%LOCALAPPDATA%\microvm-rs\` | Host | Data directory root |
| `%LOCALAPPDATA%\microvm-rs\wsl\` | Host | WSL2 virtual disk (ext4.vhdx) |
| `%LOCALAPPDATA%\microvm-rs\alpine-rootfs.tar.gz` | Host | Extracted rootfs for import |
| `/etc/microvm/init-microvm.sh` | Guest | Control daemon script |
| `/etc/wsl.conf` | Guest | WSL configuration (isolation settings) |

---

## Gotchas and Lessons Learned

1. **UTF-16LE output**: WSL management commands (`wsl --list`, `--import`, `--unregister`) output UTF-16LE, NOT UTF-8. Use `decode_wsl_output()` in `process.rs`. Commands run INSIDE a distro output normal UTF-8.

2. **Shell escaping**: Writing files into WSL via shell strings is fragile. Always use `exec_with_stdin()` which pipes content via stdin to `tee`.

3. **socat fork recursion**: When socat forks the init script with `--handle`, the script must check for this flag early and jump to the handler function. Otherwise it re-runs the entire init sequence.

4. **Cargo fingerprint issue**: Running `cargo check` then `cargo build` can leave stale fingerprints. Fix by deleting `.fingerprint/` dirs in target/.

5. **Distro reuse**: The distro persists across runs (not reimported every time). Only first boot provisions packages and deploys the init script. This means changes to `init-microvm.sh` require either `cleanup()` or manual update.

---

## What's Needed for Velocitty Integration

### Phase 1: SOCKS5 Proxy (Minimum Viable)
1. Install `microsocks` (or similar lightweight SOCKS5) during provisioning
2. Have `init-microvm.sh` start it on port 1080
3. Velocitty points SSH client at `localhost:1080`
4. Test: SSH through SOCKS5 proxy works end-to-end

### Phase 2: VPN Integration
1. Install `openvpn` during provisioning
2. Add daemon commands: `vpn-start <base64-config>`, `vpn-stop`, `vpn-status`
3. Host sends .ovpn config via control channel
4. Daemon writes config, launches openvpn, monitors connection
5. SOCKS5 proxy routes through VPN tunnel

### Phase 3: Production Hardening
1. Implement real pause/resume (process signals)
2. Add connection health monitoring and auto-reconnect
3. Handle DNS properly for VPN tunnel
4. Add logging/diagnostics accessible from host
5. Test with various VPN providers and configurations

---

## Files Reference

### Host-Side (Rust)
- `src/backend/wsl/mod.rs` — WslBackend struct + HypervisorBackend impl
- `src/backend/wsl/process.rs` — wsl.exe CLI wrapper + UTF-16LE decoding
- `src/backend/wsl/distro.rs` — WSL distro lifecycle (import, exec, terminate)
- `src/backend/wsl/rootfs.rs` — Embedded Alpine rootfs management
- `src/vsock.rs` — VsockClient, VsockHandler, TcpVsockBridge
- `src/proxy.rs` — ProxyConnectionManager, OutboundProxy (Unix only)
- `src/runtime.rs` — VmRuntime with Windows event loop (lines 948-1035)
- `src/bin/microvm.rs` — CLI with Windows path (lines 1484-1520)
- `src/lib.rs` — Public API exports (spawn_vm_shell, cleanup_vm)

### Guest-Side (Shell)
- `guest/wsl-rootfs/alpine-minirootfs.tar.gz` — Alpine 3.21.3 x86_64 rootfs (3.5MB)
- `guest/wsl-rootfs/init-microvm.sh` — Control daemon entrypoint
- `guest/wsl-rootfs/setup.sh` — Legacy provisioning script (not called by backend)

### Tests
- `test_wsl_backend_name()` — Verifies backend name is "wsl2"
- `test_wsl_state_initial()` — Verifies initial state is Created
- `test_check_wsl_available()` — Verifies availability check doesn't panic
- No integration tests yet (require Windows + WSL2 at test time)
