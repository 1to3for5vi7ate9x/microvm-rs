# Velocitty Integration with microvm-rs

How microvm-rs replaces Lima for isolated VPN networking in Velocitty.

---

## Overview

Velocitty currently uses Lima (macOS-only, QEMU-based) to run an Alpine Linux VM
that provides OpenVPN connectivity and a SOCKS5 proxy. microvm-rs replaces this
with a cross-platform embedded solution: native hypervisors on macOS/Linux, and
WSL2 on Windows.

**What Velocitty gets:**
- Zero external dependencies (no `brew install lima`)
- Windows + Linux support (not just macOS)
- Faster boot (~1s vs 10-30s with Lima)
- Simpler communication (vsock / localhost TCP vs Lima port forwarding)

---

## Architecture by Platform

### macOS (HVF) / Linux (KVM) — Native Hypervisor

```
Velocitty (Tauri app)
    │
    ├── MicrovmManager.start_vm()
    │       │
    │       ├── VmRuntime::new(config)  ← creates HVF/KVM backend
    │       │       └── returns (runtime, VsockClient)
    │       │
    │       └── runtime.spawn()  ← boots kernel + initramfs
    │
    ├── VsockClient.request(port=1025, json)  ← virtio-vsock
    │       │
    │       └── Guest VM (kernel + initramfs)
    │               ├── vpn-daemon (vsock port 1025) ← JSON protocol
    │               ├── OpenVPN client (tun0)
    │               └── inbound-proxy (vsock port 7602) ← SOCKS5 relay
    │
    └── Host SOCKS5 listener (localhost:1080)
            └── relays through vsock → inbound-proxy → VPN tunnel
```

**Guest image:** A Linux kernel + initramfs containing the VPN daemon, OpenVPN,
and socat. Bundled as binary assets in the Velocitty app (~10MB total).

### Windows — WSL2 Backend

```
Velocitty (Tauri app)
    │
    ├── MicrovmManager.start_vm()
    │       │
    │       ├── VmRuntime::new(config)  ← creates WSL2 backend
    │       │       └── returns (runtime, VsockClient[TCP-backed])
    │       │
    │       └── runtime.spawn()  ← imports Alpine distro, starts daemon
    │
    ├── VsockClient.request(port=1025, json)  ← TCP on localhost:1025
    │       │
    │       └── WSL2 distro (Alpine Linux)
    │               ├── vpn-daemon (TCP port 1025) ← same JSON protocol
    │               ├── OpenVPN client (tun0)
    │               └── inbound-proxy (TCP port 7602) ← SOCKS5 relay
    │
    └── Host SOCKS5 listener (localhost:1080)
            └── relays through TCP → inbound-proxy → VPN tunnel
```

**Guest image:** A 3.5MB Alpine minirootfs embedded in the binary via
`include_bytes!`. On first run, it's imported as a WSL2 distro named
`microvm-rs`, then provisioned with socat, OpenVPN, and the daemon script.

### Key Difference

| Aspect | macOS/Linux | Windows (WSL2) |
|---|---|---|
| Hypervisor | HVF / KVM | WSL2 (wsl.exe) |
| Guest | Kernel + initramfs | Alpine WSL2 distro |
| Communication | virtio-vsock | TCP on localhost |
| Boot mechanism | vCPU execution | `wsl -d microvm-rs` |
| Rootfs | Embedded initramfs | Embedded Alpine tarball |

The critical design choice: **VsockClient is polymorphic**. On macOS/Linux it
wraps virtio-vsock. On Windows it wraps TCP connections to localhost. Velocitty's
`microvm_network.rs` code doesn't need platform-specific branches — the same
`client.request(port, data)` call works everywhere.

---

## What Velocitty's Code Does Today

### Existing Integration (`microvm_network.rs`, 1231 lines)

Velocitty already has a complete microvm-rs integration. Here's what it does:

**1. VM Lifecycle**
```rust
// Start: creates VmRuntime, spawns background thread, gets VsockClient
pub async fn start_vm(&self) -> Result<String, String>

// Stop: sends Shutdown command, calls handle.shutdown()
pub async fn stop_vm(&self) -> Result<String, String>

// Status: pings daemon, returns MicrovmStatus
pub async fn get_status(&self) -> MicrovmStatus
```

**2. Daemon Communication (JSON-over-vsock, port 1025)**
```rust
// Serializes DaemonCommand to JSON, sends via VsockClient
async fn send_daemon_command(&self, cmd: DaemonCommand) -> Result<DaemonResponse, String>
```

Commands:
| Command | JSON | Purpose |
|---|---|---|
| `Ping` | `{"cmd":"ping"}` | Health check |
| `GetAuthSecret` | `{"cmd":"get_auth_secret"}` | Get auth token |
| `VpnStart` | `{"cmd":"vpn_start","profile":"..."}` | Connect VPN |
| `VpnStop` | `{"cmd":"vpn_stop"}` | Disconnect VPN |
| `VpnStatus` | `{"cmd":"vpn_status"}` | Check VPN state |
| `VpnSetProfile` | `{"cmd":"vpn_set_profile","name":"...","content":"..."}` | Upload .ovpn |
| `ListProfiles` | `{"cmd":"list_profiles"}` | List available profiles |
| `VpnCheckWebauth` | `{"cmd":"vpn_check_webauth"}` | Poll MFA completion |
| `Shutdown` | `{"cmd":"shutdown"}` | Graceful exit |

Response format:
```json
{
    "status": "ok|error|pong|connected|disconnected|webauth_required",
    "tun_ip": "10.x.x.x",
    "error": "optional error message",
    "auth_url": "https://vpn-provider.com/auth",
    "profiles": ["profile1.ovpn", "profile2.ovpn"],
    "auth_secret": "64-hex-chars"
}
```

**3. SOCKS5 Proxy (host-side, localhost:1080)**

Accepts SOCKS5 connections from SSH clients, relays them through the VM's
inbound-proxy (vsock/TCP port 7602) to route traffic through the VPN tunnel.

```
SSH client → localhost:1080 (SOCKS5) → VsockClient → port 7602 → VPN → target
```

Handshake with inbound-proxy:
```
[1 byte: hostname_len] [hostname bytes] [2 bytes: port big-endian]
```

**4. Console Output**

Raw UART output from the VM kernel is broadcast to any subscribed terminal
sessions via `tokio::sync::broadcast`.

### Current Cargo.toml

```toml
# macOS only right now
[target.'cfg(target_os = "macos")'.dependencies]
microvm = { git = "https://github.com/1to3for5vi7ate9x/microvm-rs.git", branch = "main" }
```

---

## What Needs to Change for Windows Support

### 1. Cargo.toml — Add Windows dependency

```toml
# macOS (HVF backend)
[target.'cfg(target_os = "macos")'.dependencies]
microvm = { git = "https://github.com/1to3for5vi7ate9x/microvm-rs.git", branch = "dev" }

# Windows (WSL2 backend)
[target.'cfg(target_os = "windows")'.dependencies]
microvm = { git = "https://github.com/1to3for5vi7ate9x/microvm-rs.git", branch = "dev" }
```

### 2. microvm-rs — VsockClient TCP Adapter (TODO)

The `VsockClient` returned by `VmRuntime::new()` on Windows must wrap TCP
connections instead of virtio-vsock. This is an internal change in microvm-rs,
transparent to Velocitty.

Current state: `VmRuntime` and `VsockClient` are only implemented for macOS.
The Windows `run_event_loop` in `src/runtime.rs` needs to return a TCP-backed
`VsockClient` that maps `client.request(port, data)` to
`TcpStream::connect("127.0.0.1:{port}")`.

### 3. microvm-rs — RuntimeConfig on Windows

On Windows, `RuntimeConfig.kernel_path` is not needed (WSL2 provides its own
kernel). The `start_vm()` code in Velocitty should handle this:

```rust
// In MicrovmManager.start_vm():
#[cfg(target_os = "windows")]
let config = RuntimeConfig {
    memory_mb: 512,
    kernel_path: PathBuf::new(),  // unused on Windows
    initrd_path: None,
    cmdline: String::new(),
    guest_cid: Some(3),
    console_tx: Some(raw_console_tx),
    console_rx: Some(console_input_rx),
};

#[cfg(not(target_os = "windows"))]
let config = RuntimeConfig {
    memory_mb: 512,
    kernel_path: kernel_path.clone(),
    // ... same as current code
};
```

Or better: skip the kernel check on Windows:
```rust
#[cfg(not(target_os = "windows"))]
{
    let kernel_path = self.kernel_path.as_ref()
        .ok_or("Kernel image not found")?;
    if !kernel_path.exists() {
        return Err(format!("Kernel not found at: {:?}", kernel_path));
    }
}
```

### 4. Guest Daemon — Full VPN Protocol

The current `init-microvm.sh` in the WSL2 distro only handles simple commands
(ping, status, pause, resume, shutdown). For Velocitty, the daemon must support
the full JSON protocol from `DaemonCommand`.

**Option A: Port daemon.py into the WSL2 distro**
- Install Python3 during provisioning (`apk add python3`)
- Copy daemon.py into the distro (same `exec_with_stdin` approach)
- Daemon binds to TCP 0.0.0.0:1025 (same port, same protocol)
- Proven code, already handles OpenVPN, SOCKS5, WebAuth

**Option B: Rewrite daemon in shell/Rust (future)**
- Shell: Replace daemon.py with a more capable shell script + socat
- Rust: Compile a static daemon binary, embed it in the rootfs
- Eliminates Python dependency, smaller footprint

Recommended: **Option A first** (works now), then Option B later.

### 5. Velocitty start_vm() — Hypervisor Name

```rust
// Current code says "WHP" for Windows — update to "WSL2"
pub fn hypervisor_name() -> Option<String> {
    #[cfg(target_os = "windows")]
    { Some("WSL2".to_string()) }
    // ...
}
```

---

## End-to-End Flow on Windows

### First Run (provisioning)

```
1. User clicks "Start VM" in Velocitty
2. MicrovmManager.start_vm() is called
3. VmRuntime::new(config) creates WslBackend
4. WslBackend.start():
   a. Extracts embedded Alpine rootfs to %LOCALAPPDATA%\microvm-rs\
   b. wsl --import microvm-rs <path> <rootfs.tar.gz> --version 2
   c. provision_distro():
      - apk update && apk add socat openvpn python3
      - Pipes daemon.py into /etc/microvm/daemon.py via stdin
      - Pipes init-microvm.sh into /etc/microvm/init-microvm.sh via stdin
   d. Starts daemon: wsl -d microvm-rs -- /etc/microvm/init-microvm.sh
   e. Polls localhost:1025 until daemon responds
5. VsockClient(TCP) is ready
6. MicrovmManager sends Ping → daemon responds with {"status":"pong"}
7. VM marked as running, UI updates
```

### Subsequent Runs (distro already exists)

```
1. start_vm() → WslBackend.start()
2. Detects distro already imported (wsl --list --quiet)
3. Skips provisioning
4. Starts daemon directly
5. Ready in ~2-3 seconds
```

### VPN Connect

```
1. User selects VPN profile, clicks Connect
2. MicrovmManager.vpn_connect(profile, username, password)
3. Upload profile: {"cmd":"vpn_set_profile","name":"corp.ovpn","content":"..."}
4. Start VPN: {"cmd":"vpn_start","profile":"corp.ovpn","username":"user","password":"pass"}
5. Daemon starts OpenVPN inside WSL2 distro
6. Daemon monitors tun0 interface
7. Response: {"status":"connected","tun_ip":"10.8.0.6"}
   or: {"status":"webauth_required","auth_url":"https://..."}
8. UI updates to show connected state
```

### SSH Through VPN

```
1. User opens SSH session with "Route through VPN" enabled
2. Velocitty's SSH client connects to localhost:1080 (SOCKS5)
3. Host SOCKS5 proxy accepts connection
4. Proxy connects to VsockClient → TCP localhost:7602 (inbound-proxy)
5. Inbound-proxy in WSL2 distro connects to target through VPN tunnel
6. Bidirectional relay: SSH ↔ SOCKS5 ↔ TCP ↔ WSL2 ↔ VPN ↔ target
```

---

## Port Mapping

| Port | Protocol | macOS/Linux | Windows | Purpose |
|---|---|---|---|---|
| 1025 | JSON | vsock | TCP localhost | Daemon commands |
| 7601 | binary | vsock | TCP localhost | Outbound proxy (reserved) |
| 7602 | binary | vsock | TCP localhost | Inbound proxy (SSH-through-VPN) |
| 1080 | SOCKS5 | TCP localhost | TCP localhost | Host-side SOCKS5 for SSH clients |

On Windows, all "vsock" ports become TCP on localhost because WSL2 shares the
host network namespace. This is handled transparently by `TcpVsockBridge` /
TCP-backed `VsockClient` inside microvm-rs.

---

## What's Done vs What's Left

### Done (in microvm-rs)

- [x] WSL2 backend: distro import, provisioning, lifecycle management
- [x] `init-microvm.sh` with socat-based TCP daemon (basic commands)
- [x] `exec_with_stdin` for safely piping files into the distro
- [x] Embedded Alpine rootfs (3.5MB, include_bytes!)
- [x] `cargo run -- run` works end-to-end on Windows
- [x] Daemon responds to ping/status/shutdown on TCP 1025
- [x] Auto-provisioning on first run (socat install, script copy)

### TODO (in microvm-rs)

- [ ] **TCP-backed VsockClient**: `VmRuntime::new()` on Windows should return a
      `VsockClient` that wraps `TcpStream::connect("127.0.0.1:{port}")` for
      each `client.request(port, data)` call. This is the critical piece that
      makes Velocitty's code work without platform-specific branches.

- [ ] **Full VPN daemon in WSL2 distro**: Replace basic `init-microvm.sh` with
      the full daemon (daemon.py or equivalent) that handles all `DaemonCommand`
      variants: vpn_start, vpn_stop, vpn_status, vpn_set_profile, list_profiles,
      vpn_check_webauth, get_auth_secret.

- [ ] **Inbound proxy in WSL2 distro**: A listener on TCP port 7602 that accepts
      the SOCKS5 relay handshake (`[len][hostname][port]`), connects to the
      target through the VPN tunnel, and relays data bidirectionally.

- [ ] **Console output on Windows**: Currently the WSL2 backend doesn't pipe
      UART/console output back to Velocitty. Either capture WSL process stdout
      or provide a separate console channel.

### TODO (in Velocitty)

- [ ] Add `microvm` dependency for Windows in `Cargo.toml`
- [ ] Conditional kernel path check (skip on Windows)
- [ ] Update hypervisor name display (`"WSL2"` instead of `"WHP"`)
- [ ] Test VPN connect/disconnect through WSL2 backend
- [ ] Bundle daemon.py (or Rust daemon) as an app resource for Windows

---

## Comparison: Lima vs microvm-rs

| | Lima (current) | microvm-rs macOS | microvm-rs Windows |
|---|---|---|---|
| External deps | `brew install lima` | None | None |
| Boot time | 10-30s | <1s | ~2s (first run: ~30s) |
| VM technology | QEMU | HVF (native) | WSL2 |
| Guest OS | Alpine cloud image | Custom initramfs | Alpine minirootfs |
| Communication | TCP via limactl | virtio-vsock | TCP on localhost |
| Guest size | ~50MB disk image | ~10MB kernel+initrd | 3.5MB rootfs |
| Port forwarding | Lima YAML config | vsock (direct) | WSL2 network (direct) |
| Profile access | Host mount (/vpn) | vsock upload | TCP upload |
| Console | `limactl shell` (PTY) | UART serial | WSL process stdout |
| Platforms | macOS only | macOS, Linux | Windows |
